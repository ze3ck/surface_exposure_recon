#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
SCRIPT = ROOT / "exposure_recon.py"
TEMPLATE = ROOT / "templates" / "index.html"
META = ROOT / "case_meta.json"
HOST = "127.0.0.1"
PORT = 8765

_lock = threading.Lock()
_job: dict | None = None
_listing: dict | None = None

sys.path.insert(0, str(ROOT))
try:
    from index_of_check import PATHS as LISTING_PATHS
    from index_of_check import scan as listing_scan
except Exception:  
    LISTING_PATHS = []
    listing_scan = None


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = val


def _load_meta() -> dict:
    if not META.is_file():
        return {}
    try:
        data = json.loads(META.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_meta(meta: dict) -> None:
    META.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _safe_case_dir(apex: str) -> Path | None:
    apex = (apex or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", apex):
        return None
    folder = (REPORTS / apex).resolve()
    root = REPORTS.resolve()
    if folder == root or root not in folder.parents:
        return None
    return folder if folder.is_dir() else folder


def shodan_api_key() -> str:
    _load_env_file(ROOT / ".env")
    key = (os.environ.get("SHODAN_API_KEY") or "").strip()
    secrets = ROOT / "secrets.json"
    if not key and secrets.is_file():
        try:
            data = json.loads(secrets.read_text(encoding="utf-8"))
            key = str(data.get("SHODAN_API_KEY") or data.get("shodan_key") or "").strip()
        except Exception:
            key = ""
    return key


def _clean_domains(raw: str) -> list[str]:
    found: list[str] = []
    for line in raw.replace(",", "\n").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^https?://", "", line).split("/")[0].rstrip(".")
        line = line.split(":")[0]
        if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", line) and line not in found:
            found.append(line)
    return found


def _case_signal(data: dict) -> dict:
    stats = data.get("stats") or {}
    hosts = data.get("hosts") or []
    high = int(stats.get("high_risk_findings") or 0)
    cves = int(stats.get("cves") or 0)
    ips = int(stats.get("ips") or 0)
    live = int(stats.get("live_names") or 0)
    cdn_ips = sum(1 for h in hosts if h.get("cdn_or_shared"))
    dedicated = max(0, ips - cdn_ips)
    score = min(100, high * 12 + cves * 15 + dedicated * 4 + (8 if live else 0))
    if cves and dedicated:
        level = "high"
    elif high >= 3 or cves:
        level = "high" if dedicated else "medium"
    elif high or dedicated:
        level = "medium"
    else:
        level = "low"
    if ips and cdn_ips == ips and not dedicated:
        level = "watch" if level == "low" else level
    return {
        "high_risk": high,
        "cves": cves,
        "ips": ips,
        "live": live,
        "cdn_ips": cdn_ips,
        "dedicated_ips": dedicated,
        "score": score,
        "level": level,
    }


def _list_reports() -> list[dict]:
    items = []
    if not REPORTS.exists():
        return items
    meta = _load_meta()
    for d in sorted(REPORTS.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        md = d / "REPORT.md"
        js = d / "report.json"
        if not md.exists() and not js.exists():
            continue
        signal = {
            "high_risk": 0,
            "cves": 0,
            "ips": 0,
            "live": 0,
            "cdn_ips": 0,
            "dedicated_ips": 0,
            "score": 0,
            "level": "low",
        }
        generated = None
        if js.is_file():
            try:
                data = json.loads(js.read_text(encoding="utf-8"))
                signal = _case_signal(data)
                generated = data.get("generated_at")
            except Exception:
                pass
        stamp = js if js.exists() else md
        mark = dict(meta.get(d.name) or {})
        flag = d / "reviewed.json"
        if flag.is_file():
            try:
                mark.update(json.loads(flag.read_text(encoding="utf-8")))
            except Exception:
                mark["reviewed"] = True
        items.append(
            {
                **signal,
                "apex": d.name,
                "mtime": int(stamp.stat().st_mtime),
                "generated_at": generated,
                "reviewed": bool(mark.get("reviewed")),
                "reviewed_at": mark.get("reviewed_at"),
                "files": [
                    name
                    for name in ("REPORT.md", "hosts.csv", "stack.csv", "report.json")
                    if (d / name).exists()
                ],
            }
        )
    return items


def _huntpack_text(data: dict) -> str:
    apex = data.get("apex") or ""
    lines = [
        f"# hunt pack — {apex}",
        f"generated: {data.get('generated_at') or ''}",
        "source: exposure_recon (passive)",
        "",
        "## hostnames",
    ]
    names = [n.get("host") for n in (data.get("names") or []) if n.get("host")]
    if not names:
        names = [x.get("host") for x in (data.get("flow") or []) if x.get("host")]
    lines.extend(names or ["-"])
    lines += ["", "## ipv4"]
    for row in data.get("hosts") or []:
        flag = " CDN" if row.get("cdn_or_shared") else ""
        lines.append(f"{row.get('ip')}{flag}  {row.get('org') or ''}")
    lines += ["", "## cve"]
    cves = sorted({c for row in (data.get("hosts") or []) for c in (row.get("vulns") or [])})
    lines.extend(cves or ["-"])
    lines += ["", "## shodan"]
    lines.extend(data.get("shodan_queries") or data.get("queries") or [f"hostname:{apex}"])
    return "\n".join(lines) + "\n"


def _run_job(job_id: str, domains: list[str], opts: dict) -> None:
    global _job
    cmd = [
        sys.executable,
        "-u",
        str(SCRIPT),
        *domains,
        "-o",
        str(REPORTS),
        "--max-subs",
        str(opts["max_subs"]),
        "--max-http",
        str(opts["max_http"]),
        "--sleep",
        str(opts["sleep"]),
    ]
    if opts["no_crtsh"]:
        cmd.append("--no-crtsh")
    if opts["skip_http"]:
        cmd.append("--skip-http")
    key = shodan_api_key()
    env = os.environ.copy()
    if key:
        env["SHODAN_API_KEY"] = key

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            with _lock:
                if _job and _job["id"] == job_id:
                    _job["log"].append(line.rstrip("\n"))
                    if len(_job["log"]) > 2000:
                        _job["log"] = _job["log"][-1500:]
        code = proc.wait()
        with _lock:
            if _job and _job["id"] == job_id:
                _job["status"] = "ok" if code == 0 else "error"
                _job["returncode"] = code
                _job["finished"] = time.time()
                if code != 0:
                    _job["log"].append(f"[!] proceso terminó con código {code}")
    except Exception as exc:
        with _lock:
            if _job and _job["id"] == job_id:
                _job["status"] = "error"
                _job["finished"] = time.time()
                _job["log"].append(f"[!] {exc}")


def _run_listing(job_id: str, opts: dict) -> None:
    global _listing
    if listing_scan is None:
        with _lock:
            if _listing and _listing["id"] == job_id:
                _listing["status"] = "error"
                _listing["log"].append("[!] falta index_of_check.py")
                _listing["finished"] = time.time()
        return

    def on_row(row: dict) -> None:
        with _lock:
            if not _listing or _listing["id"] != job_id:
                return
            _listing["rows"].append(row)
            if row.get("hit"):
                _listing["hits"] += 1
            flag = ""
            if row["kind"] == "DIRECTORY_LISTING":
                flag = " LISTING"
            elif row.get("hit"):
                flag = " STATUS"
            _listing["log"].append(
                f"{row['status'] or '---':>4}  {row['kind']:<22}  {row['path']}{flag}"
            )
            if len(_listing["log"]) > 2000:
                _listing["log"] = _listing["log"][-1500:]

    try:
        result = listing_scan(
            opts["base"],
            host=opts.get("host") or None,
            insecure=bool(opts.get("insecure")),
            delay=float(opts.get("delay") or 0.4),
            timeout=float(opts.get("timeout") or 10),
            show_all=bool(opts.get("show_all")),
            port=opts.get("port"),
            on_row=on_row,
        )
        folder = REPORTS / "_indexof"
        folder.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9.-]+", "_", urlparse_host(opts["base"]))[:80] or "target"
        out = folder / f"{slug}.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        with _lock:
            if _listing and _listing["id"] == job_id:
                _listing["status"] = "ok"
                _listing["hits"] = result.get("hits") or 0
                _listing["rows"] = result.get("rows") or _listing["rows"]
                _listing["finished"] = time.time()
                _listing["saved"] = str(out.relative_to(ROOT))
                _listing["log"].append(f"# listings/status: {_listing['hits']}")
    except Exception as exc:
        with _lock:
            if _listing and _listing["id"] == job_id:
                _listing["status"] = "error"
                _listing["finished"] = time.time()
                _listing["log"].append(f"[!] {exc}")


def urlparse_host(base: str) -> str:
    from urllib.parse import urlparse as _up

    raw = base if "://" in base else "https://" + base
    return (_up(raw).netloc or "target").lower()


class Handler(BaseHTTPRequestHandler):
    server_version = "exposure-recon-ui/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str, download: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self._send(code, raw, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, _index_bytes(), "text/html; charset=utf-8")
            return
        if path == "/api/state":
            with _lock:
                job = None if _job is None else dict(_job)
                listing = None if _listing is None else dict(_listing)
            self._json(
                200,
                {
                    "job": job,
                    "listing": listing,
                    "reports": _list_reports(),
                    "shodan_configured": bool(shodan_api_key()),
                    "listing_paths": len(LISTING_PATHS),
                },
            )
            return
        if path == "/api/listing/state":
            with _lock:
                listing = None if _listing is None else dict(_listing)
            self._json(200, {"ok": True, "listing": listing, "paths": len(LISTING_PATHS)})
            return
        prev = re.fullmatch(r"/api/preview/([a-z0-9.-]+)", unquote(path))
        if prev:
            payload = _preview_payload(prev.group(1))
            if not payload:
                self._json(404, {"ok": False, "error": "reporte no encontrado"})
                return
            self._json(200, payload)
            return
        pack = re.fullmatch(r"/api/huntpack/([a-z0-9.-]+)", unquote(path))
        if pack:
            payload = _preview_payload(pack.group(1))
            if not payload:
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            self._send(200, payload["huntpack"].encode("utf-8"), "text/plain; charset=utf-8")
            return
        m = re.fullmatch(
            r"/reports/([a-z0-9.-]+)/(REPORT\.md|hosts\.csv|stack\.csv|report\.json)",
            unquote(path),
        )
        if m:
            apex, name = m.group(1), m.group(2)
            file_path = REPORTS / apex / name
            if file_path.is_file():
                ctype = {
                    "REPORT.md": "text/markdown; charset=utf-8",
                    "hosts.csv": "text/csv; charset=utf-8",
                    "stack.csv": "text/csv; charset=utf-8",
                    "report.json": "application/json; charset=utf-8",
                }[name]
                self._send(200, file_path.read_bytes(), ctype, name)
                return
            self._send(404, b"no encontrado", "text/plain; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def _start_run(self) -> None:
        global _job
        if self.path.split("?", 1)[0] != "/api/run":
            self._json(404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            self._json(413, {"ok": False, "error": "payload demasiado grande"})
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "JSON inválido"})
            return

        domains = _clean_domains(str(data.get("domains") or ""))
        if not domains:
            self._json(400, {"ok": False, "error": "Indica al menos un apex válido (ej. midominio.cl)."})
            return
        if len(domains) > 10:
            self._json(400, {"ok": False, "error": "Máximo 10 apex por corrida."})
            return
        try:
            max_subs = max(10, min(int(data.get("max_subs") or 200), 800))
            max_http = max(0, min(int(data.get("max_http") or 15), 50))
            sleep = max(0.05, min(float(data.get("sleep") or 0.12), 2.0))
        except (TypeError, ValueError):
            self._json(400, {"ok": False, "error": "Parámetros numéricos inválidos."})
            return

        with _lock:
            if _job and _job["status"] == "running":
                self._json(409, {"ok": False, "error": "Ya hay un análisis en curso."})
                return
            job_id = uuid.uuid4().hex[:10]
            key_on = bool(shodan_api_key())
            _job = {
                "id": job_id,
                "status": "running",
                "domains": domains,
                "log": [
                    f"Iniciando {', '.join(domains)} …",
                    "Shodan API: " + ("activa (backend)" if key_on else "no configurada → solo InternetDB"),
                ],
                "started": time.time(),
                "finished": None,
                "returncode": None,
                "shodan": key_on,
            }

        opts = {
            "max_subs": max_subs,
            "max_http": max_http,
            "sleep": sleep,
            "no_crtsh": bool(data.get("no_crtsh", True)),
            "skip_http": bool(data.get("skip_http", False)),
        }
        threading.Thread(target=_run_job, args=(job_id, domains, opts), daemon=True).start()
        self._json(200, {"ok": True, "id": job_id})

    def do_DELETE(self) -> None:
        path = self.path.split("?", 1)[0]
        m = re.fullmatch(r"/api/case/([a-z0-9.-]+)", unquote(path))
        if not m:
            self._json(404, {"ok": False, "error": "not found"})
            return
        self._delete_case(m.group(1))

    def do_POST(self) -> None:  # delete via POST for the UI
        path = self.path.split("?", 1)[0]
        if path == "/api/listing/run":
            self._start_listing()
            return
        if path.startswith("/api/delete"):
            length = int(self.headers.get("Content-Length") or 0)
            apex = ""
            if length:
                try:
                    data = json.loads(self.rfile.read(length) or b"{}")
                    apex = str(data.get("apex") or "")
                except json.JSONDecodeError:
                    self._json(400, {"ok": False, "error": "JSON inválido"})
                    return
            if not apex:
                m = re.fullmatch(r"/api/delete/([a-z0-9.-]+)", unquote(path))
                apex = m.group(1) if m else ""
            self._delete_case(apex)
            return
        if path == "/api/reviewed":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except json.JSONDecodeError:
                self._json(400, {"ok": False, "error": "JSON inválido"})
                return
            apex = str(data.get("apex") or "").strip().lower()
            if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", apex):
                self._json(400, {"ok": False, "error": "apex inválido"})
                return
            reviewed = bool(data.get("reviewed"))
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            payload = {"reviewed": True, "reviewed_at": stamp}
            folder = REPORTS / apex
            with _lock:
                meta = _load_meta()
                if reviewed:
                    meta[apex] = payload
                    if folder.is_dir():
                        (folder / "reviewed.json").write_text(
                            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
                        )
                else:
                    meta.pop(apex, None)
                    flag = folder / "reviewed.json"
                    if flag.is_file():
                        flag.unlink()
                _save_meta(meta)
            self._json(200, {"ok": True, "apex": apex, "reviewed": reviewed, "reports": _list_reports()})
            return
        self._start_run()

    def _start_listing(self) -> None:
        global _listing
        length = int(self.headers.get("Content-Length") or 0)
        if length > 16 * 1024:
            self._json(413, {"ok": False, "error": "payload demasiado grande"})
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "JSON inválido"})
            return
        if not data.get("authorized"):
            self._json(400, {"ok": False, "error": "Marca que el target está autorizado."})
            return
        base = str(data.get("base") or "").strip()
        if not base:
            self._json(400, {"ok": False, "error": "Indica la URL base."})
            return
        try:
            delay = max(0.15, min(float(data.get("delay") or 0.4), 5.0))
            timeout = max(2.0, min(float(data.get("timeout") or 10.0), 30.0))
            raw_port = data.get("port")
            port = None
            if raw_port not in (None, "", False):
                port = int(raw_port)
                if port < 1 or port > 65535:
                    raise ValueError("port")
        except (TypeError, ValueError):
            self._json(400, {"ok": False, "error": "Parámetros numéricos inválidos."})
            return
        with _lock:
            if _listing and _listing.get("status") == "running":
                self._json(409, {"ok": False, "error": "Ya hay un Index-of scan en curso."})
                return
            job_id = uuid.uuid4().hex[:10]
            _listing = {
                "id": job_id,
                "status": "running",
                "base": base,
                "host": str(data.get("host") or "").strip(),
                "log": [
                    f"Index-of scan {base}"
                    + (f":{port}" if port else "")
                    + f" · {len(LISTING_PATHS)} paths"
                ],
                "rows": [],
                "hits": 0,
                "started": time.time(),
                "finished": None,
            }
        opts = {
            "base": base,
            "host": str(data.get("host") or "").strip(),
            "insecure": True if data.get("insecure") is None else bool(data.get("insecure")),
            "show_all": bool(data.get("show_all")),
            "delay": delay,
            "timeout": timeout,
            "port": port,
        }
        threading.Thread(target=_run_listing, args=(job_id, opts), daemon=True).start()
        self._json(200, {"ok": True, "id": job_id})

    def _delete_case(self, apex: str) -> None:
        folder = _safe_case_dir(apex)
        if folder is None or not folder.is_dir():
            self._json(404, {"ok": False, "error": "caso no encontrado"})
            return
        with _lock:
            if _job and _job.get("status") == "running" and apex in (_job.get("domains") or []):
                self._json(409, {"ok": False, "error": "No se puede borrar un caso en curso."})
                return
        try:
            shutil.rmtree(folder)
        except OSError as exc:
            self._json(500, {"ok": False, "error": str(exc)})
            return
        with _lock:
            meta = _load_meta()
            if meta.pop(apex, None) is not None:
                _save_meta(meta)
        self._json(200, {"ok": True, "deleted": apex, "reports": _list_reports()})


def _build_flow(data: dict) -> list[dict]:
    """Hostname → IP → puertos/servicios para la preview."""
    ip_map = {row.get("ip"): row for row in (data.get("hosts") or []) if row.get("ip")}
    stack_map = {row.get("host"): row for row in (data.get("stack") or []) if row.get("host")}
    http_map = {}
    for probe in data.get("http") or []:
        chosen = probe.get("https") or probe.get("http") or {}
        http_map[probe.get("host")] = chosen
    flow = []
    for dns in data.get("dns") or []:
        host = dns.get("host")
        if not host:
            continue
        ips = list(dns.get("a") or [])
        ip_nodes = []
        for ip in ips:
            meta = ip_map.get(ip) or {}
            cls = meta.get("classification") or {}
            high = {int(x["port"]): x.get("service") for x in (cls.get("high_risk") or []) if "port" in x}
            web = set(cls.get("web") or [])
            ports = []
            for port in meta.get("ports") or []:
                kind = "high" if port in high else ("web" if port in web else "other")
                ports.append({"port": port, "kind": kind, "service": high.get(port) or ("http(s)" if port in web else "")})
            ip_nodes.append(
                {
                    "ip": ip,
                    "org": meta.get("org"),
                    "asn": meta.get("asn"),
                    "cdn": bool(meta.get("cdn_or_shared")),
                    "confidence": meta.get("confidence"),
                    "ports": ports,
                    "vulns": meta.get("vulns") or [],
                    "cpes": meta.get("cpes") or [],
                }
            )
        stack = stack_map.get(host) or {}
        http = http_map.get(host) or {}
        flow.append(
            {
                "host": host,
                "live": bool(ips),
                "error": dns.get("error"),
                "sources": dns.get("sources") or [],
                "ips": ip_nodes,
                "http": {
                    "status": stack.get("status") or http.get("status"),
                    "server": stack.get("server_raw") or http.get("server"),
                    "product": stack.get("product"),
                    "version": stack.get("version"),
                    "version_source": stack.get("version_source"),
                    "title": stack.get("title") or http.get("title"),
                    "cdn": stack.get("cdn"),
                    "note": stack.get("note"),
                },
            }
        )
    flow.sort(key=lambda x: (0 if x["live"] else 1, x["host"]))
    return flow


def _preview_payload(apex: str) -> dict | None:
    folder = REPORTS / apex
    data_path = folder / "report.json"
    md_path = folder / "REPORT.md"
    if not data_path.is_file():
        return None
    try:
        data = json.loads(data_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    hosts = []
    for row in data.get("hosts") or []:
        hosts.append(
            {
                "ip": row.get("ip"),
                "org": row.get("org"),
                "asn": row.get("asn"),
                "cdn_or_shared": row.get("cdn_or_shared"),
                "confidence": row.get("confidence"),
                "ports": row.get("ports") or [],
                "classification": row.get("classification") or {},
                "vulns": row.get("vulns") or [],
                "cpes": row.get("cpes") or [],
                "hostnames_ours": row.get("hostnames_ours") or [],
                "nginx_cpe": row.get("nginx_cpe"),
                "nginx_cpe_version": row.get("nginx_cpe_version"),
                "shodan_web": row.get("shodan_web") or {},
            }
        )
    names = []
    for row in data.get("names") or []:
        names.append(
            {
                "host": row.get("host"),
                "sources": row.get("sources") or [],
                "first_seen": row.get("first_seen") or "",
            }
        )
    return {
        "apex": data.get("apex") or apex,
        "generated_at": data.get("generated_at"),
        "stats": data.get("stats") or {},
        "stack": data.get("stack") or [],
        "hosts": hosts,
        "names": names,
        "flow": _build_flow(data),
        "queries": data.get("shodan_queries") or [],
        "huntpack": _huntpack_text(data),
        "markdown": md_path.read_text(encoding="utf-8") if md_path.is_file() else "",
    }


def _index_bytes() -> bytes:
    if not TEMPLATE.is_file():
        raise FileNotFoundError(
            f"Falta la plantilla {TEMPLATE}. Debe existir templates/index.html"
        )
    return TEMPLATE.read_bytes()


def main() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    if not TEMPLATE.is_file():
        raise SystemExit(f"Falta {TEMPLATE}")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"UI → http://{HOST}:{PORT}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstop")
        httpd.server_close()


if __name__ == "__main__":
    main()
