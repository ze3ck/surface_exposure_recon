# exposure_recon

Passive internet-exposure inventory for **your own** apex domains, plus an optional authorized **Index of** check for Apache / Nginx / IIS.

It does **not** run nmap, does **not** exploit anything, and does **not** brute-force paths. Port data comes from Shodan InternetDB (no API key) and, if configured, `shodan.host`. Directory checks use a **closed path list** only.

Use it only against assets you own or have written authorization to assess.

## Layout

```
exposure_recon/
  app.py                 # web UI (stdlib http.server)
  exposure_recon.py      # passive recon CLI (7 phases)
  index_of_check.py      # Index of / status-page checker
  templates/index.html   # UI
  requirements.txt
  targets.txt
  .env.example
  secrets.example.json
  reports/<apex>/        # case output
  case_meta.json         # reviewed flags (created at runtime)
```

## Requirements

- Python 3.10+
- Network access to Certificate Transparency, DNS, RDAP, and InternetDB
- Optional: a Shodan API key and `pip install shodan`

```bash
cd exposure_recon
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Shodan API key (backend only)

The key is **never** collected in the browser. The backend reads it in this order:

1. Environment variable `SHODAN_API_KEY`
2. `.env` next to `app.py`
3. `secrets.json` → `{"SHODAN_API_KEY":"..."}`

```bash
cp .env.example .env
# edit .env
pip install shodan
```

Without a key, recon uses InternetDB only.

Do not commit `.env` or `secrets.json`.

## Web UI

```bash
python3 app.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765)

Navbar modules:

| Module | What it does |
|---|---|
| **Passive recon** | CT → DNS → RDAP → InternetDB/Shodan → port class → inferred CVE → light HTTP |
| **Index of** | Closed-list GET of common Apache/Nginx/IIS paths; flags directory listings and status pages |

### Passive recon UI

- Intake: one apex per line, max CT names, max HTTP probes
- Live collector log
- Case table with search, pagination, risk score, filters (High / CVE / Dedicated IP / CDN / Open / Reviewed)
- Sort by recent, risk, or name
- Per case: Open dossier, Hunt pack, Re-run, Delete, Index-of
- Reviewed checkbox persisted in `case_meta.json` and `reports/<apex>/reviewed.json` (plus browser localStorage)
- Dossier modal: Graph (hostname → IP → ports), Stack (Server / nginx version / CDN), Assets / CT, CVE, parsed Markdown report

Outputs under `reports/<apex>/`:

| File | Contents |
|---|---|
| `REPORT.md` | Human-readable report |
| `hosts.csv` | One row per IP |
| `stack.csv` | Web stack (Server, product, version, CDN) |
| `report.json` | Full structured payload |

### Index of UI

- Base URL (`https://domain` or `http://IP`)
- Optional **port** (overrides URL port; e.g. `8080`, `8443`)
- Optional `Host` header (vhost when hitting an IP)
- Delay between requests, TLS insecure (default on; auto-retries if certificate verify fails)
- Show 404/403 (off by default)
- **Authorized target** must be checked before a run
- Live hit table + KPIs (listings, status/info, auth)
- Results saved under `reports/_indexof/`

From a Passive recon case, **Index-of** opens this module with `https://<apex>`.

## CLI — passive recon

```bash
python3 exposure_recon.py example.com
python3 exposure_recon.py example.com other.com -o ./salida
python3 exposure_recon.py -f targets.txt --max-subs 300
python3 exposure_recon.py example.com --skip-http --no-crtsh
```

Phases:

0. Scope (apex you pass in)
1. Certificate Transparency (`crt.name`, optional `crt.sh`)
2. DNS A / AAAA / CNAME
3. RDAP / ASN per IPv4
4. InternetDB (+ Shodan host API if a key is set)
5. Port classification (web / high-risk / noise)
6. CVE strings from InternetDB / Shodan (inferred, often unverified)
7. Light GET HTTPS/HTTP only to live hostnames of that apex

## CLI — Index of

```bash
python3 index_of_check.py https://yourdomain.com
python3 index_of_check.py http://1.2.3.4 --host yourdomain.com --insecure
python3 index_of_check.py https://yourdomain.com --port 8080
python3 index_of_check.py https://yourdomain.com --all --delay 0.3
```

Path list includes common Apache, Nginx, and IIS/ASP.NET locations (`/aspnet_client/`, `/bin/`, `/App_Data/`, `/ReportServer/`, etc.). Listing signatures cover Apache autoindex, Nginx listings, and IIS `[To Parent Directory]`.

## How to read findings

- An indexed port is **not** proof it is open right now.
- Many hostnames on one IP + Cloudflare/Akamai/Fastly/etc. → **do not attribute the full port grid** to your site.
- `Server: nginx` with no version → do not assign nginx CVEs.
- `Server: cloudflare` / AWS ELB → you are seeing the edge, not origin nginx.
- InternetDB/Shodan CVEs are usually inferred from CPE/version. Confirm on [NVD](https://nvd.nist.gov/) and check preconditions (auth, local vs network, module enabled).
- Docker `2375` without TLS is a **misconfiguration** (unauthenticated API), not “the CVE of the port”.
- Directory listing = files may be enumerable. Apache/Nginx/IIS **status** pages leak metrics, not a file index.

## Suggested Shodan queries (after an apex run)

```
hostname:yourdomain.com
ssl.cert.subject.cn:yourdomain.com
ssl:"yourdomain.com"
ssl.cert.subject.cn:yourdomain.com -port:80 -port:443
```

Prefer certificate / hostname queries over raw IP when the address is shared or on a CDN.

## Safety

- Authorized targets only.
- Index of is a fixed path list, not a fuzzer.
- HTTP probes are limited (`--max-http` / UI field).
- One passive job and one Index-of job at a time in the UI.

## License / use

Internal defensive inventory. You are responsible for staying inside your authorization and applicable law.
