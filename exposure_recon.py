#!/usr/bin/env python3
"""
Recon pasivo por fases para apex propios.
CT (crt.name / crt.sh) → DNS → RDAP → InternetDB/Shodan → puertos → CVE → HTTP liviano.
No escanea puertos ni explota servicios.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

CRTNAME = "https://crt.name/v1/search?apex={apex}&dates=1"
CRTSH = "https://crt.sh/?q={q}&output=json"
INTERNETDB = "https://internetdb.shodan.io/{ip}"
RDAP_IP = "https://rdap.org/ip/{ip}"

UA = "exposure-recon/1.0 (passive asset inventory)"
TIMEOUT = 25

# Puertos que en un sitio web público suelen ser hallazgo, no "el front".
HIGH_RISK = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    88: "Kerberos",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    445: "SMB",
    465: "SMTPS",
    587: "Submission",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2222: "SSH-alt",
    2375: "Docker-API",
    2376: "Docker-TLS",
    3000: "DevUI/Grafana?",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5555: "ADB/alt",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
    6000: "X11",
    6080: "noVNC",
    6443: "Kubernetes-API",
    7001: "WebLogic",
    7474: "Neo4j",
    7547: "TR-069",
    8009: "AJP",
    8086: "InfluxDB",
    8089: "Splunk",
    8123: "HomeAssistant?",
    8161: "ActiveMQ",
    8443: "HTTPS-alt/panel",
    8834: "Nessus",
    8883: "MQTT-TLS",
    9000: "Dev/SonaType?",
    9090: "Prometheus",
    9100: "JetDirect",
    9200: "Elasticsearch",
    9300: "ES-transport",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "SAP-mgmt?",
}

WEB_PORTS = {80, 443, 8080, 8443}
NOISE_PORTS = {1337, 12345, 31337, 43}
SERVER_RE = re.compile(
    r"(?i)\b(nginx|openresty|apache|httpd|caddy|litespeed|microsoft-iis|iis|cloudflare|awselb|amazon|gws|google)\b"
    r"(?:[/\s]+([0-9][0-9A-Za-z._-]*))?"
)

CDN_HINTS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "incapsula",
    "sucuri",
    "google llc",
    "amazon.com",
    "amazon technologies",
    "microsoft azure",
    "azure",
    "digitalocean",
    "fastly",
)

INTERESTING_LABELS = (
    "admin",
    "api",
    "app",
    "auth",
    "cpanel",
    "dev",
    "docker",
    "ftp",
    "git",
    "grafana",
    "jenkins",
    "k8s",
    "kibana",
    "kube",
    "mail",
    "ns1",
    "ns2",
    "panel",
    "smtp",
    "ssh",
    "staging",
    "test",
    "vpn",
    "webmail",
    "whm",
    "www",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_server_header(raw: str | None) -> dict[str, str | None]:
    text = (raw or "").strip()
    if not text:
        return {"raw": None, "product": None, "version": None}
    m = SERVER_RE.search(text)
    product = m.group(1).lower() if m else text.split("/")[0].split()[0].lower()
    version = m.group(2) if m else None
    if not version and "/" in text:
        tail = text.split("/", 1)[1].split()[0]
        if re.match(r"^\d", tail):
            version = tail
    aliases = {"httpd": "apache", "microsoft-iis": "iis", "awselb": "aws-elb", "amazon": "aws-elb", "gws": "google"}
    product = aliases.get(product, product)
    return {"raw": text, "product": product, "version": version}


def nginx_from_cpes(cpes: list[str]) -> dict[str, str | None]:
    for cpe in cpes or []:
        low = cpe.lower()
        if "nginx" not in low:
            continue
        version = None
        if low.startswith("cpe:2.3:"):
            bits = low.split(":")
            if len(bits) >= 6 and bits[5] not in {"*", "-", ""}:
                version = bits[5]
        else:
            bits = low.split(":")
            if len(bits) >= 5 and bits[4] not in {"*", "-", ""}:
                version = bits[4]
        return {"cpe": cpe, "version": version}
    return {"cpe": None, "version": None}


def shodan_web_hint(sho: dict[str, Any] | None) -> dict[str, str | None]:
    if not isinstance(sho, dict):
        return {"product": None, "version": None}
    for svc in sho.get("services") or []:
        if svc.get("port") not in WEB_PORTS:
            continue
        prod = (svc.get("product") or "").strip()
        ver = (svc.get("version") or "").strip() or None
        if prod:
            return {"product": prod, "version": ver}
    return {"product": None, "version": None}


def session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def is_hostname(name: str, apex: str) -> bool:
    name = name.strip().lower().rstrip(".")
    apex = apex.strip().lower().rstrip(".")
    if not name or " " in name or "*" in name:
        return False
    return name == apex or name.endswith("." + apex)


def normalize_host(name: str) -> str:
    return name.strip().lower().rstrip(".").lstrip("*.")


class Recon:
    def __init__(self, http: requests.Session, args: argparse.Namespace) -> None:
        self.http = http
        self.args = args
        self.shodan = None
        key = os.environ.get("SHODAN_API_KEY") or args.shodan_key
        if key:
            try:
                import shodan  # type: ignore

                self.shodan = shodan.Shodan(key)
            except Exception as exc:
                print(f"[!] Shodan API no disponible ({exc}); sigo con InternetDB")

    # ----- fase 1 -----
    def crt_name(self, apex: str) -> list[dict[str, str]]:
        url = CRTNAME.format(apex=quote(apex))
        out: list[dict[str, str]] = []
        try:
            r = self.http.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = re.split(r"[\t ]+", line, maxsplit=1)
                host = normalize_host(parts[0])
                first = parts[1].strip() if len(parts) > 1 else ""
                if first.lower() in {"unknown", "none", "-"}:
                    first = ""
                if is_hostname(host, apex):
                    out.append({"host": host, "first_seen": first, "source": "crt.name"})
        except Exception as exc:
            print(f"    [crt.name] error: {exc}")
        return out

    def crt_sh(self, apex: str) -> list[dict[str, str]]:
        url = CRTSH.format(q=quote(f"%.{apex}"))
        out: list[dict[str, str]] = []
        try:
            r = self.http.get(url, timeout=40)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                return out
            for row in data:
                raw = str(row.get("name_value") or "")
                for part in raw.split("\n"):
                    host = normalize_host(part)
                    if is_hostname(host, apex):
                        out.append(
                            {
                                "host": host,
                                "first_seen": str(row.get("not_before") or ""),
                                "source": "crt.sh",
                            }
                        )
        except Exception as exc:
            print(f"    [crt.sh] error: {exc}")
        return out

    def phase1_names(self, apex: str) -> list[dict[str, Any]]:
        print(f"  [1] Nombres CT para {apex}")
        rows = self.crt_name(apex)
        if not self.args.no_crtsh:
            rows.extend(self.crt_sh(apex))
        merged: dict[str, dict[str, Any]] = {}
        for row in rows:
            host = row["host"]
            cur = merged.setdefault(
                host, {"host": host, "sources": [], "first_seen": row.get("first_seen", "")}
            )
            if row["source"] not in cur["sources"]:
                cur["sources"].append(row["source"])
            if row.get("first_seen") and not cur["first_seen"]:
                cur["first_seen"] = row["first_seen"]
        # siempre incluir apex y www
        for extra in (apex, f"www.{apex}"):
            merged.setdefault(extra, {"host": extra, "sources": ["seed"], "first_seen": ""})
        names = sorted(merged.values(), key=lambda x: x["host"])
        if self.args.max_subs and len(names) > self.args.max_subs:
            # Siempre conservar apex y www; el resto por etiqueta útil y poca profundidad.
            forced = {apex, f"www.{apex}"}

            def score(item: dict[str, Any]) -> tuple[int, int, str]:
                h = item["host"]
                if h in forced:
                    return (0, 0, h)
                label = h[: -len(apex)].strip(".")
                labels = [x for x in label.split(".") if x]
                depth = len(labels)
                interesting = bool(labels) and labels[0] in INTERESTING_LABELS
                return (1 if interesting else 2, depth, h)

            ranked = sorted(names, key=score)
            keep = []
            seen: set[str] = set()
            for item in ranked:
                if item["host"] in seen:
                    continue
                keep.append(item)
                seen.add(item["host"])
                if len(keep) >= self.args.max_subs:
                    break
            for must in forced:
                if must not in seen and must in merged:
                    keep.append(merged[must])
            names = keep
            print(f"    recortado a --max-subs {self.args.max_subs} (apex/www siempre incluidos)")
        print(f"    {len(names)} hostnames")
        return names

    # ----- fase 2 -----
    def resolve_host(self, host: str) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "host": host,
            "a": [],
            "aaaa": [],
            "cname": None,
            "error": None,
        }
        try:
            try:
                cname, aliases, _ = socket.gethostbyname_ex(host)
                if aliases:
                    rec["cname"] = aliases[0] if aliases[0] != host else None
            except Exception:
                pass
            infos = socket.getaddrinfo(host, None)
            seen: set[str] = set()
            for fam, *_rest, addr in infos:
                ip = addr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                if fam == socket.AF_INET:
                    rec["a"].append(ip)
                elif fam == socket.AF_INET6:
                    rec["aaaa"].append(ip)
        except socket.gaierror as exc:
            rec["error"] = str(exc)
        return rec

    def phase2_dns(self, names: list[dict[str, Any]]) -> list[dict[str, Any]]:
        print("  [2] DNS")
        resolved = []
        for i, item in enumerate(names, 1):
            rec = self.resolve_host(item["host"])
            rec["sources"] = item.get("sources", [])
            rec["first_seen"] = item.get("first_seen", "")
            resolved.append(rec)
            if i % 25 == 0:
                print(f"    {i}/{len(names)}")
            time.sleep(self.args.sleep)
        live = sum(1 for r in resolved if r["a"] or r["aaaa"])
        print(f"    vivos (A/AAAA): {live}/{len(resolved)}")
        return resolved

    # ----- fase 3 -----
    def rdap_ip(self, ip: str) -> dict[str, Any]:
        info = {"ip": ip, "org": None, "asn": None, "name": None, "country": None, "error": None}
        try:
            r = self.http.get(RDAP_IP.format(ip=ip), timeout=TIMEOUT)
            if r.status_code == 404:
                info["error"] = "rdap-404"
                return info
            r.raise_for_status()
            data = r.json()
            info["name"] = data.get("name")
            info["country"] = data.get("country")
            for cid in data.get("cidr0_cidrs") or []:  # some rdap
                pass
            entities = data.get("entities") or []

            def walk(ents: list) -> None:
                for ent in ents:
                    vcard = (ent.get("vcardArray") or [None, []])[1]
                    for item in vcard:
                        if item and item[0] == "fn" and not info["org"]:
                            info["org"] = item[3]
                    walk(ent.get("entities") or [])

            walk(entities)
            for notice in data.get("notices") or []:
                pass
            # ARIN / RIPE variants
            for net in data.get("arin_originas0_originautnums") or []:
                info["asn"] = f"AS{net}"
            if not info["asn"]:
                remarks = json.dumps(data).lower()
                m = re.search(r"as(\d{1,10})", remarks)
                if m:
                    info["asn"] = f"AS{m.group(1)}"
        except Exception as exc:
            info["error"] = str(exc)
        return info

    def phase3_owners(self, dns_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        print("  [3] RDAP / dueño de IP")
        ips: set[str] = set()
        for row in dns_rows:
            ips.update(row.get("a") or [])
        owners: dict[str, dict[str, Any]] = {}
        for i, ip in enumerate(sorted(ips), 1):
            owners[ip] = self.rdap_ip(ip)
            org = (owners[ip].get("org") or "").lower()
            owners[ip]["cdn_or_shared"] = any(h in org for h in CDN_HINTS)
            time.sleep(max(self.args.sleep, 0.15))
            if i % 10 == 0:
                print(f"    {i}/{len(ips)}")
        print(f"    IPs únicas IPv4: {len(owners)}")
        return owners

    # ----- fase 4 -----
    def internetdb(self, ip: str) -> dict[str, Any]:
        empty = {
            "ip": ip,
            "ports": [],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "source": "internetdb",
            "error": None,
        }
        try:
            r = self.http.get(INTERNETDB.format(ip=ip), timeout=TIMEOUT)
            if r.status_code == 404:
                return empty
            r.raise_for_status()
            data = r.json()
            empty.update(
                {
                    "ports": sorted(data.get("ports") or []),
                    "vulns": data.get("vulns") or [],
                    "cpes": data.get("cpes") or [],
                    "hostnames": data.get("hostnames") or [],
                    "tags": data.get("tags") or [],
                }
            )
            return empty
        except Exception as exc:
            empty["error"] = str(exc)
            return empty

    def shodan_host(self, ip: str) -> dict[str, Any] | None:
        if not self.shodan:
            return None
        try:
            host = self.shodan.host(ip)
            services = []
            for banner in host.get("data") or []:
                services.append(
                    {
                        "port": banner.get("port"),
                        "transport": banner.get("transport"),
                        "product": banner.get("product"),
                        "version": banner.get("version"),
                        "cpe": banner.get("cpe") or banner.get("cpe23") or [],
                        "timestamp": banner.get("timestamp"),
                        "module": (banner.get("_shodan") or {}).get("module"),
                    }
                )
            return {
                "org": host.get("org"),
                "isp": host.get("isp"),
                "asn": host.get("asn"),
                "os": host.get("os"),
                "last_update": host.get("last_update"),
                "vulns": list((host.get("vulns") or {}).keys())
                if isinstance(host.get("vulns"), dict)
                else (host.get("vulns") or []),
                "ports": host.get("ports") or [],
                "hostnames": host.get("hostnames") or [],
                "services": services,
            }
        except Exception as exc:
            return {"error": str(exc)}

    def phase4_index(self, owners: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        print("  [4] InternetDB / Shodan")
        indexed: dict[str, dict[str, Any]] = {}
        for i, ip in enumerate(sorted(owners), 1):
            db = self.internetdb(ip)
            extra = self.shodan_host(ip)
            indexed[ip] = {"internetdb": db, "shodan": extra}
            time.sleep(max(self.args.sleep, 0.2))
            if i % 10 == 0:
                print(f"    {i}/{len(owners)}")
        print(f"    IPs consultadas: {len(indexed)}")
        return indexed

    # ----- fase 5 + 6 -----
    def classify_ports(self, ports: list[int]) -> dict[str, Any]:
        high = [{"port": p, "service": HIGH_RISK[p]} for p in ports if p in HIGH_RISK]
        web = [p for p in ports if p in WEB_PORTS]
        noise = [p for p in ports if p in NOISE_PORTS]
        other = [p for p in ports if p not in HIGH_RISK and p not in WEB_PORTS and p not in NOISE_PORTS]
        return {"web": web, "high_risk": high, "noise": noise, "other": other}

    # ----- fase 7 -----
    def http_probe(self, host: str) -> dict[str, Any]:
        result: dict[str, Any] = {"host": host, "https": None, "http": None}
        ctx = ssl.create_default_context()
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                r = self.http.get(url, timeout=12, allow_redirects=True)
                entry: dict[str, Any] = {
                    "url": url,
                    "final_url": str(r.url),
                    "status": r.status_code,
                    "server": r.headers.get("Server"),
                    "hsts": r.headers.get("Strict-Transport-Security"),
                    "csp": bool(r.headers.get("Content-Security-Policy")),
                    "xfo": r.headers.get("X-Frame-Options"),
                    "title": None,
                }
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:8000], re.I | re.S)
                if m:
                    entry["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
                result[scheme] = entry
                if scheme == "https":
                    break
            except Exception as exc:
                result[scheme] = {"url": url, "error": str(exc)[:200]}
        return result

    def phase7_http(self, apex: str, dns_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.args.skip_http:
            print("  [7] HTTP omitido")
            return []
        print("  [7] HTTP liviano (hostnames vivos del apex)")
        probes = []
        candidates = [
            r["host"]
            for r in dns_rows
            if (r.get("a") or r.get("aaaa")) and is_hostname(r["host"], apex)
        ]
        # limita a apex, www y etiquetas interesantes para no martillar 400 vhosts
        picked = []
        for h in candidates:
            label = h[: -len(apex)].strip(".")
            if h == apex or h == f"www.{apex}" or any(
                tok == label or tok in label.split(".") for tok in INTERESTING_LABELS
            ):
                picked.append(h)
        if len(picked) > self.args.max_http:
            picked = picked[: self.args.max_http]
        print(f"    sondas HTTP: {len(picked)}")
        for h in picked:
            probes.append(self.http_probe(h))
            time.sleep(max(self.args.sleep, 0.2))
        return probes


def build_host_rows(
    apex: str,
    dns_rows: list[dict[str, Any]],
    owners: dict[str, dict[str, Any]],
    indexed: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    ip_to_hosts: dict[str, list[str]] = defaultdict(list)
    for row in dns_rows:
        for ip in row.get("a") or []:
            ip_to_hosts[ip].append(row["host"])

    rows = []
    for ip, hosts in sorted(ip_to_hosts.items()):
        owner = owners.get(ip) or {}
        idx = indexed.get(ip) or {}
        db = idx.get("internetdb") or {}
        sho = idx.get("shodan") or {}
        ports = db.get("ports") or sho.get("ports") or []
        ports = sorted(set(int(p) for p in ports))
        vulns = list(dict.fromkeys((db.get("vulns") or []) + (sho.get("vulns") or [])))
        cpes = db.get("cpes") or []
        recon = Recon.__new__(Recon)  # only for classify
        classification = Recon.classify_ports(recon, ports)
        ngx = nginx_from_cpes(cpes)
        sh_web = shodan_web_hint(sho if isinstance(sho, dict) else None)
        rows.append(
            {
                "apex": apex,
                "ip": ip,
                "hostnames_ours": sorted(set(hosts)),
                "hostnames_index": db.get("hostnames") or sho.get("hostnames") or [],
                "org": owner.get("org") or (sho.get("org") if isinstance(sho, dict) else None),
                "asn": owner.get("asn") or (sho.get("asn") if isinstance(sho, dict) else None),
                "cdn_or_shared": owner.get("cdn_or_shared", False),
                "ports": ports,
                "classification": classification,
                "cpes": cpes,
                "nginx_cpe": ngx["cpe"],
                "nginx_cpe_version": ngx["version"],
                "shodan_web": sh_web,
                "vulns": vulns,
                "tags": db.get("tags") or [],
                "shodan_last_update": sho.get("last_update") if isinstance(sho, dict) else None,
                "confidence": (
                    "baja"
                    if owner.get("cdn_or_shared")
                    else ("alta" if len(set(hosts)) <= 15 else "media")
                ),
            }
        )
    return rows


def build_web_stack(
    dns_rows: list[dict[str, Any]],
    host_rows: list[dict[str, Any]],
    http_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ip_info = {r["ip"]: r for r in host_rows}
    host_ips = {r["host"]: list(r.get("a") or []) for r in dns_rows}
    stack: list[dict[str, Any]] = []
    for probe in http_rows:
        host = probe["host"]
        https = probe.get("https") or {}
        http = probe.get("http") or {}
        chosen = https if https.get("status") or https.get("server") else http
        parsed = parse_server_header(chosen.get("server") if isinstance(chosen, dict) else None)
        ips = host_ips.get(host) or []
        cdn = False
        orgs: list[str] = []
        ngx_cpe = None
        ngx_ver = None
        sh_prod = None
        sh_ver = None
        for ip in ips:
            meta = ip_info.get(ip) or {}
            cdn = cdn or bool(meta.get("cdn_or_shared"))
            if meta.get("org"):
                orgs.append(str(meta["org"]))
            ngx_cpe = ngx_cpe or meta.get("nginx_cpe")
            ngx_ver = ngx_ver or meta.get("nginx_cpe_version")
            sh = meta.get("shodan_web") or {}
            sh_prod = sh_prod or sh.get("product")
            sh_ver = sh_ver or sh.get("version")
        product = parsed["product"]
        version = parsed["version"]
        source = "header" if version else None
        if not version and ngx_ver and (product in {None, "nginx", "openresty"} or "nginx" in (ngx_cpe or "")):
            product = product or "nginx"
            version = ngx_ver
            source = "cpe"
        if not version and sh_ver and (product or sh_prod):
            product = product or (sh_prod or "").lower()
            version = sh_ver
            source = "shodan"
        note = ""
        if product in {"cloudflare", "aws-elb", "akamai", "fastly"} or cdn:
            note = "Header/IP de edge (CDN). La versión de nginx de origen suele no ser visible."
        elif product == "nginx" and not version:
            note = "Nginx visible, versión oculta (server_tokens off o header recortado)."
        elif not product:
            note = "Sin header Server."
        stack.append(
            {
                "host": host,
                "ips": ips,
                "org": orgs[0] if orgs else None,
                "cdn": cdn,
                "status": chosen.get("status") if isinstance(chosen, dict) else None,
                "title": chosen.get("title") if isinstance(chosen, dict) else None,
                "server_raw": parsed["raw"],
                "product": product,
                "version": version,
                "version_source": source,
                "nginx_cpe": ngx_cpe,
                "note": note,
            }
        )
    return stack


def markdown_report(apex: str, payload: dict[str, Any]) -> str:
    lines = [
        f"# Exposición pasiva — `{apex}`",
        "",
        f"Generado: {payload['generated_at']}",
        "",
        "## Resumen",
        "",
        f"- Hostnames CT: **{payload['stats']['names']}**",
        f"- DNS vivos: **{payload['stats']['live_names']}**",
        f"- IPs IPv4: **{payload['stats']['ips']}**",
        f"- IPs con puertos indexados: **{payload['stats']['ips_with_ports']}**",
        f"- Hallazgos high-risk (puertos): **{payload['stats']['high_risk_findings']}**",
        f"- CVE indexados (inferidos): **{payload['stats']['cves']}**",
        "",
        "Los CVE de InternetDB/Shodan suelen ser *unverified* (inferidos por versión). "
        "Un puerto en el índice no implica que esté abierto ahora ni que sea explotable.",
        "",
    ]
    if payload.get("stack"):
        lines += [
            "## Stack web (nginx / servidor / versión)",
            "",
            "| Hostname | IP | CDN | Server | Producto | Versión | Fuente | Título | Nota |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for s in payload["stack"]:
            ips = ", ".join(s.get("ips") or []) or "—"
            lines.append(
                "| `{host}` | `{ips}` | {cdn} | {server} | {product} | {version} | {src} | {title} | {note} |".format(
                    host=s.get("host") or "",
                    ips=ips,
                    cdn="sí" if s.get("cdn") else "no",
                    server=(s.get("server_raw") or "—").replace("|", "/"),
                    product=s.get("product") or "—",
                    version=s.get("version") or "—",
                    src=s.get("version_source") or "—",
                    title=(s.get("title") or "—").replace("|", "/"),
                    note=(s.get("note") or "—").replace("|", "/"),
                )
            )
        lines += [
            "",
            "Sin número de versión no se deben asociar CVE de nginx. "
            "Si el Server es `cloudflare`/`awselb`, esa no es la versión del origen.",
            "",
        ]
    lines += [
        "## IPs",
        "",
    ]
    for row in payload["hosts"]:
        hr = ", ".join(f"{x['port']}/{x['service']}" for x in row["classification"]["high_risk"]) or "—"
        ports = ", ".join(str(p) for p in row["ports"][:40]) or "—"
        if len(row["ports"]) > 40:
            ports += f" … (+{len(row['ports']) - 40})"
        names = ", ".join(f"`{h}`" for h in row["hostnames_ours"][:12])
        extra = f" (+{len(row['hostnames_ours']) - 12})" if len(row["hostnames_ours"]) > 12 else ""
        flag = " **[CDN/compartido — no atribuir todos los puertos]**" if row["cdn_or_shared"] else ""
        lines += [
            f"### `{row['ip']}` — confianza {row['confidence']}{flag}",
            "",
            f"- Org / ASN: {row.get('org') or '—'} / {row.get('asn') or '—'}",
            f"- Nuestros hostnames: {names}{extra}",
            f"- Puertos indexados: {ports}",
            f"- High-risk: {hr}",
            f"- CPE: {', '.join(row['cpes'][:12]) or '—'}",
            f"- CVE: {', '.join(row['vulns'][:20]) or '—'}",
            "",
        ]
        if row["vulns"]:
            lines.append("  Validar en NVD solo si el CPE/versión del banner coincide:")
            for cve in row["vulns"][:20]:
                lines.append(f"  - [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
            lines.append("")
    if payload.get("http"):
        lines += ["## HTTP (sonda liviana)", ""]
        for probe in payload["http"]:
            https = probe.get("https") or {}
            if https.get("status"):
                lines.append(
                    f"- `{probe['host']}` → {https.get('status')} `{https.get('final_url')}` "
                    f"Server={https.get('server') or '—'} HSTS={'sí' if https.get('hsts') else 'no'} "
                    f"title={https.get('title') or '—'}"
                )
            elif https.get("error"):
                lines.append(f"- `{probe['host']}` HTTPS error: {https['error']}")
        lines.append("")
    lines += [
        "## Queries Shodan sugeridas",
        "",
        "```",
        f"hostname:{apex}",
        f"ssl.cert.subject.cn:{apex}",
        f'ssl:"{apex}"',
        f"ssl.cert.subject.cn:{apex} -port:80 -port:443",
        f"ssl.cert.subject.cn:{apex} port:22,2222,2375,2376,3389,5900,5985,6443,1433,3306,5432,6379,27017,9200,5601,8009,2087,10000",
        "```",
        "",
        "## Próximos pasos",
        "",
        "1. IPs marcadas CDN/compartido: no reportar la grilla completa como tuya.",
        "2. High-risk en IP dedicada: confirmar en firewall/`ss` que el puerto escucha.",
        "3. CVE: abrir NVD y comprobar versión + precondiciones (auth, local vs red).",
        "4. 2375/2376 con banner Docker = misconfiguración de API, no 'CVE del puerto'.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(out_dir: Path, apex: str, payload: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    with (out_dir / "hosts.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "apex",
                "ip",
                "org",
                "asn",
                "cdn_or_shared",
                "confidence",
                "hostnames",
                "ports",
                "high_risk",
                "vulns",
                "cpes",
            ]
        )
        for row in payload["hosts"]:
            w.writerow(
                [
                    apex,
                    row["ip"],
                    row.get("org") or "",
                    row.get("asn") or "",
                    row["cdn_or_shared"],
                    row["confidence"],
                    ";".join(row["hostnames_ours"]),
                    ",".join(map(str, row["ports"])),
                    ",".join(str(x["port"]) for x in row["classification"]["high_risk"]),
                    ",".join(row["vulns"]),
                    ";".join(row["cpes"]),
                ]
            )
    with (out_dir / "stack.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "host",
                "ips",
                "org",
                "cdn",
                "status",
                "server",
                "product",
                "version",
                "version_source",
                "nginx_cpe",
                "title",
                "note",
            ]
        )
        for s in payload.get("stack") or []:
            w.writerow(
                [
                    s.get("host"),
                    ",".join(s.get("ips") or []),
                    s.get("org") or "",
                    s.get("cdn"),
                    s.get("status") or "",
                    s.get("server_raw") or "",
                    s.get("product") or "",
                    s.get("version") or "",
                    s.get("version_source") or "",
                    s.get("nginx_cpe") or "",
                    s.get("title") or "",
                    s.get("note") or "",
                ]
            )
    (out_dir / "REPORT.md").write_text(markdown_report(apex, payload), encoding="utf-8")


def analyze_apex(recon: Recon, apex: str, out_root: Path) -> Path:
    apex = normalize_host(apex)
    print(f"\n=== {apex} ===", flush=True)
    names = recon.phase1_names(apex)
    dns_rows = recon.phase2_dns(names)
    owners = recon.phase3_owners(dns_rows)
    indexed = recon.phase4_index(owners)
    host_rows = build_host_rows(apex, dns_rows, owners, indexed)
    http_rows = recon.phase7_http(apex, dns_rows)
    stack = build_web_stack(dns_rows, host_rows, http_rows)

    live = sum(1 for r in dns_rows if r.get("a") or r.get("aaaa"))
    ips_with_ports = sum(1 for r in host_rows if r["ports"])
    high = sum(len(r["classification"]["high_risk"]) for r in host_rows)
    cves = len({c for r in host_rows for c in r["vulns"]})

    payload = {
        "apex": apex,
        "generated_at": utc_now(),
        "stats": {
            "names": len(names),
            "live_names": live,
            "ips": len(owners),
            "ips_with_ports": ips_with_ports,
            "high_risk_findings": high,
            "cves": cves,
        },
        "names": names,
        "dns": dns_rows,
        "owners": owners,
        "indexed": indexed,
        "hosts": host_rows,
        "http": http_rows,
        "stack": stack,
        "shodan_queries": [
            f"hostname:{apex}",
            f"ssl.cert.subject.cn:{apex}",
            f'ssl:"{apex}"',
        ],
    }
    dest = out_root / apex
    write_outputs(dest, apex, payload)
    print(f"  → {dest}/REPORT.md")
    return dest


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recon pasivo de exposición para apex propios")
    p.add_argument("domains", nargs="*", help="Apex (ej. midominio.cl)")
    p.add_argument("-f", "--file", help="Archivo con un apex por línea")
    p.add_argument("-o", "--out", default="reports", help="Directorio de salida")
    p.add_argument("--max-subs", type=int, default=400, help="Tope de hostnames CT a resolver")
    p.add_argument("--max-http", type=int, default=25, help="Tope de sondas HTTP")
    p.add_argument("--sleep", type=float, default=0.12, help="Pausa entre requests")
    p.add_argument("--no-crtsh", action="store_true", help="No consultar crt.sh")
    p.add_argument("--skip-http", action="store_true", help="Saltar fase 7")
    p.add_argument("--shodan-key", default="", help="API key Shodan (o env SHODAN_API_KEY)")
    return p.parse_args()


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    targets.extend(args.domains)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    cleaned = []
    for t in targets:
        t = normalize_host(t)
        t = re.sub(r"^https?://", "", t).split("/")[0]
        if t and t not in cleaned:
            cleaned.append(t)
    return cleaned


def main() -> int:
    args = parse_args()
    targets = load_targets(args)
    if not targets:
        print("Uso: python3 exposure_recon.py tudominio.com")
        return 2
    recon = Recon(session(), args)
    out_root = Path(args.out)
    for apex in targets:
        try:
            analyze_apex(recon, apex, out_root)
        except KeyboardInterrupt:
            print("\nInterrumpido")
            return 130
        except Exception as exc:
            print(f"[!] fallo en {apex}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())