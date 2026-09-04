#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

PATHS = [
    "/",
    "/login",
    "/backup/",
    "/backups/",
    "/old/",
    "/tmp/",
    "/temp/",
    "/test/",
    "/dev/",
    "/staging/",
    "/files/",
    "/file/",
    "/uploads/",
    "/upload/",
    "/data/",
    "/export/",
    "/exports/",
    "/dump/",
    "/dumps/",
    "/db/",
    "/sql/",
    "/logs/",
    "/log/",
    "/private/",
    "/pub/",
    "/public/",
    "/download/",
    "/downloads/",
    "/ftp/",
    "/storage/",
    "/storage/logs/",
    "/admin/",
    "/administrator/",
    "/panel/",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/static/",
    "/assets/",
    "/media/",
    "/images/",
    "/img/",
    "/.well-known/",
    "/icons/",
    "/manual/",
    "/manual/es/",
    "/error/",
    "/cgi-bin/",
    "/server-status",
    "/server-status/",
    "/server-info",
    "/server-info/",
    "/nginx_status",
    "/nginx_status/",
    "/status",
    "/status/",
    "/.git/",
    "/vendor/",
    "/wp-content/uploads/",
    "/wp-content/backup/",
    # IIS / ASP.NET / WebForms / MVC
    "/aspnet_client/",
    "/aspnet_client/system_web/",
    "/scripts/",
    "/Scripts/",
    "/css/",
    "/js/",
    "/content/",
    "/Content/",
    "/fonts/",
    "/App_Data/",
    "/App_Code/",
    "/App_Browsers/",
    "/bin/",
    "/Views/",
    "/Areas/",
    "/wwwroot/",
    "/_vti_bin/",
    "/_vti_pvt/",
    "/reports/",
    "/ReportServer/",
]
_seen: set[str] = set()
PATHS = [p for p in PATHS if not (p in _seen or _seen.add(p))]

LISTING_PATTERNS = [
    re.compile(r"<title>\s*Index of", re.I),
    re.compile(r"<h1>\s*Index of", re.I),
    re.compile(r"Index of /", re.I),
    re.compile(r"<hr>\s*Index of", re.I),
    re.compile(r"Directory listing for", re.I),
    re.compile(r'<a href="\?C=[NMSD];O=[AD]">', re.I),
    re.compile(r"\[DIR\]", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
    re.compile(r"Directory Listing", re.I),
    re.compile(r"IIS Windows(?: Server)?", re.I),
    re.compile(r'<pre>\s*<A HREF="[^"]*">\[To Parent Directory\]', re.I),
]

APACHE_STATUS = re.compile(r"Apache(?:/\d)?(?: Server)? Status", re.I)
NGINX_STATUS = re.compile(
    r"Active connections:\s*\d+|server accepts handled requests", re.I
)
APACHE_INFO = re.compile(r"Apache Server Information", re.I)

INTERESTING = {
    "DIRECTORY_LISTING",
    "APACHE_STATUS",
    "APACHE_INFO",
    "NGINX_STUB_STATUS",
    "AUTH",
    "RATE_LIMIT",
    "HTTP_200_PAGE",
    "REDIRECT",
}


def classify(status: int, content_type: str, body: str) -> str:
    if status == 0:
        return "ERROR"
    if APACHE_STATUS.search(body):
        return "APACHE_STATUS"
    if APACHE_INFO.search(body):
        return "APACHE_INFO"
    if NGINX_STATUS.search(body):
        return "NGINX_STUB_STATUS"
    if status == 200 and any(p.search(body) for p in LISTING_PATTERNS):
        return "DIRECTORY_LISTING"
    if status == 200 and "text/html" in (content_type or "").lower() and len(body) > 200:
        return "HTTP_200_PAGE"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT"
    if status == 403:
        return "FORBIDDEN"
    if status == 401:
        return "AUTH"
    if status == 404:
        return "NOT_FOUND"
    if status == 429:
        return "RATE_LIMIT"
    return f"HTTP_{status}"


def _ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def _is_tls_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    if "certificate" in text or "ssl" in text or "tls" in text:
        return True
    if isinstance(exc, ssl.SSLError):
        return True
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLError)


def _request(url: str, host: str | None, insecure: bool, timeout: float):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; IndexOfCheck/1.0; authorized-recon)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    }
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = _ssl_context(insecure)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(65536)
            body = raw.decode("utf-8", "replace")
            return (
                resp.status,
                resp.headers.get("Content-Type", ""),
                body,
                resp.headers.get("Location", ""),
                resp.headers.get("Server", ""),
                None,
            )
    except urllib.error.HTTPError as e:
        raw = e.read(65536) if e.fp else b""
        body = raw.decode("utf-8", "replace")
        hdrs = e.headers
        return (
            e.code,
            hdrs.get("Content-Type", "") if hdrs else "",
            body,
            hdrs.get("Location", "") if hdrs else "",
            hdrs.get("Server", "") if hdrs else "",
            None,
        )
    except Exception as exc:
        return 0, "", "", "", "", str(exc)


def fetch(url: str, host: str | None, insecure: bool, timeout: float):
    status, ctype, body, location, server, err = _request(url, host, insecure, timeout)
    tls_unverified = bool(insecure)
    if err and not insecure and _is_tls_error(Exception(err)):
        status, ctype, body, location, server, err2 = _request(url, host, True, timeout)
        tls_unverified = True
        if err2:
            err = f"{err} | retry-insecure: {err2}"
        else:
            err = None
    return status, ctype, body, location, server, err, tls_unverified


def normalize_base(base: str, port: int | None = None) -> str:
    base = (base or "").strip()
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL inválida. Usa http(s)://host[:puerto]/")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Host inválido.")
    use_port = port if port else parsed.port
    if use_port is not None:
        use_port = int(use_port)
        if use_port < 1 or use_port > 65535:
            raise ValueError("Puerto inválido (1-65535).")
        if ":" in hostname:
            netloc = f"[{hostname}]:{use_port}"
        else:
            netloc = f"{hostname}:{use_port}"
    else:
        netloc = parsed.netloc
    return parsed.scheme + "://" + netloc


def scan(
    base: str,
    host: str | None = None,
    insecure: bool = False,
    delay: float = 0.4,
    timeout: float = 10.0,
    show_all: bool = False,
    port: int | None = None,
    on_row=None,
) -> dict:
    origin = normalize_base(base, port)
    rows = []
    hits = 0
    for path in PATHS:
        url = origin + path
        status, ctype, body, location, server, err, tls_uv = fetch(url, host, insecure, timeout)
        kind = "ERROR" if err else classify(status, ctype, body)
        show = show_all or kind in INTERESTING or kind == "ERROR" or tls_uv
        hit = kind in {
            "DIRECTORY_LISTING",
            "APACHE_STATUS",
            "APACHE_INFO",
            "NGINX_STUB_STATUS",
        }
        if hit:
            hits += 1
        row = {
            "path": path,
            "url": url,
            "status": status,
            "kind": kind,
            "server": server,
            "location": location,
            "error": err,
            "tls_unverified": tls_uv,
            "hit": hit,
            "show": show,
        }
        if show:
            rows.append(row)
            if on_row:
                on_row(row)
        time.sleep(max(0.15, float(delay)))
    return {
        "base": origin + "/",
        "host": host,
        "port": port,
        "paths": len(PATHS),
        "hits": hits,
        "rows": rows,
    }


def parse_args():
    p = argparse.ArgumentParser(
        description="Comprobar Index of / status pages en un solo target autorizado."
    )
    p.add_argument("base", help="Base URL, ej. https://ejemplo.com o http://1.2.3.4")
    p.add_argument("--host", help="Header Host (vhost). Útil al pegar por IP.")
    p.add_argument("--insecure", action="store_true", help="No verificar TLS.")
    p.add_argument("--delay", type=float, default=0.4, help="Pausa entre requests (s).")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--all", action="store_true", help="Imprimir también 404/403.")
    p.add_argument("--port", type=int, help="Puerto opcional (ej. 8080, 8443). Pisa el de la URL.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    try:
        origin = normalize_base(args.base, args.port)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
    print(f"# target  {origin}/")
    if args.port:
        print(f"# port    {args.port}")
    if args.host:
        print(f"# Host    {args.host}")
    print(f"# paths   {len(PATHS)}  delay={args.delay}s")
    print("-" * 72)

    def emit(row: dict) -> None:
        extra = ""
        if row.get("location"):
            extra = f" -> {row['location']}"
        if row.get("error"):
            extra = f" ({row['error']})"
        if row.get("server"):
            extra += f"  [{row['server']}]"
        flag = ""
        if row["kind"] == "DIRECTORY_LISTING":
            flag = "  *** LISTING"
        elif row["kind"] in ("APACHE_STATUS", "APACHE_INFO", "NGINX_STUB_STATUS"):
            flag = "  *** STATUS/INFO"
        print(f"{row['status'] or '---':>4}  {row['kind']:<22}  {row['path']}{extra}{flag}")

    result = scan(
        origin,
        host=args.host,
        insecure=args.insecure,
        delay=args.delay,
        timeout=args.timeout,
        show_all=args.all,
        port=args.port,
        on_row=emit,
    )
    print("-" * 72)
    print(f"# listings/status expuestos: {result['hits']}")
    print(
        "# DIRECTORY_LISTING = Index of (Apache o Nginx). "
        "STATUS = métricas, no es listado de archivos."
    )


if __name__ == "__main__":
    main()
