# OSINT_Hub

Live OSINT collection, deterministic cross-source correlation, and optional LLM attack-surface analysis.

Authorized targets only. Respect each API’s terms of service and rate limits. Do not use this against systems you do not have permission to assess. There is no LinkedIn scraper.

## What it does

1. **Collect** — domain infrastructure (DNS, crt.sh, GitHub, Shodan, …) and/or people OSINT via optional [User Scanner](https://github.com/kaifcodec/user-scanner) (email/username account leads).
2. **Correlate** — rule-based joins written to `correlations.json` **before** any LLM runs.
3. **Report** — one markdown document plus a unified `bundle.json`.
4. **Analyze (optional)** — send the report plus precomputed edges to a local Ollama model or Claude for domain/both runs; emit lab-shaped JSON and a Rich target list.

Missing API keys skip that collector with a warning. DNS and crt.sh need none. People mode needs the optional `people` extra.

## Setup

```bash
git clone https://github.com/gabrielslabdotcom/OSINT_Hub.git
cd OSINT_Hub
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web,people]"
cp .env.example .env
```

Fill `.env` with keys you have. The web extra includes the Anthropic SDK; Claude analysis also needs `ANTHROPIC_API_KEY`. The people extra installs MIT-licensed User Scanner for account-existence checks.

On a lab Linux box with Ollama, point `OLLAMA_BASE_URL` at that host. On a real engagement, sanitize client identifiers before sending anything to a cloud model.

## Configuration

Copy `.env.example` to `.env`. Empty keys skip that collector.

### Collectors

| Variable | Used by |
|----------|---------|
| `SHODAN_API_KEY` | Shodan collector |
| `GITHUB_TOKEN` | GitHub code search (recommended; unauthenticated search is not used) |
| `CENSYS_API_TOKEN` | Censys Platform Search (preferred) |
| `CENSYS_ORGANIZATION_ID` | Censys organization id (optional with the platform token) |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys Legacy Search if no platform token |
| `HUNTER_API_KEY` | Hunter domain-search for mailboxes |
| `TOMBA_API_KEY` / `TOMBA_SECRET` | Tomba domain-search for mailboxes (both required) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails subdomain enumeration |
| `GREYNOISE_API_KEY` | GreyNoise community context for resolved IPs |
| `URLSCAN_API_KEY` | URLScan domain search |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain report |
| `PDCP_API_KEY` | ProjectDiscovery Chaos / associated domains |
| `LEAKIX_API_KEY` | LeakIX domain metadata (no leak payloads stored) |
| `HIBP_API_KEY` | Have I Been Pwned breach check for collected mailboxes |
| `ABUSEIPDB_API_KEY` | AbuseIPDB check for resolved IPs |
| `IPINFO_TOKEN` | IPinfo org/ASN for resolved IPs |

### LLM

| Variable | Used by |
|----------|---------|
| `OLLAMA_BASE_URL` | Ollama host (`https://ollama.com` or `http://127.0.0.1:11434`) |
| `OLLAMA_API_KEY` | Ollama Cloud (required for `https://ollama.com`; unused locally) |
| `OLLAMA_MODEL` | Model name (`gemma4:31b` on cloud; `llama3.2` locally) |
| `ANTHROPIC_API_KEY` | Cloud LLM |
| `ANTHROPIC_MODEL` | Claude model id |
| `ANTHROPIC_MAX_TOKENS` | Claude output cap (default 16384) |

### Limits

| Variable | Default | Used by |
|----------|---------|---------|
| `DNS_MAX_HOSTS` | 80 | DNS follow-up names from CT |
| `SHODAN_MAX_HOSTS` | 15 | Shodan host lookups |
| `GITHUB_MAX_RESULTS` | 30 | GitHub code search hits |
| `HUNTER_MAX_EMAILS` | 25 | Hunter mailbox rows |
| `PEOPLE_PHONE_ENRICH_MAX` | 5 | Extra phone lookups for top mailboxes still missing a number (0 disables) |
| `PEOPLE_SCAN_MAX_EMAILS` | 10 | Cap email seeds sent to User Scanner |
| `PEOPLE_SCAN_MAX_USERNAMES` | 10 | Cap username seeds sent to User Scanner |
| `PEOPLE_SCAN_TIMEOUT` | 120 | Overall people-scan timeout (seconds) |
| `PEOPLE_SCAN_MAX_CONCURRENCY` | 8 | Concurrent User Scanner module checks |
| `PEOPLE_SCAN_ALLOW_LOUD` | false | Must be true **and** `--allow-loud` / API flag to enable modules that may notify a target |
| `PEOPLE_SCAN_INCLUDE_NSFW` | false | Include NSFW platform modules |
| `HTTP_TIMEOUT` | 30 | Collector HTTP timeout (seconds) |
| `OLLAMA_TIMEOUT` | 180 | Ollama request timeout (seconds) |

## Investigation modes

| Mode | Input | What runs |
|------|-------|-----------|
| `domain` | organization domain | Existing infrastructure collectors only |
| `people` | emails and/or usernames (optional domain for Hunter/Tomba) | User Scanner + HIBP/phone enrich; no DNS/CVE claims |
| `both` | domain (+ optional seeds) | Domain collectors, then User Scanner on seeds derived from mailboxes |

Scan depth for people/both: `quick` (high-signal subset), `standard` (default), `full` (broader, slower, more noise). Account-existence hits are leads — they can be wrong and are subject to each site’s terms.

## CLI

```bash
# Collection + correlation only
osint-hub all corp.example

# Full pipeline with a local model
osint-hub all corp.example --analyze local

# People OSINT
osint-hub collect --mode people --email alice@corp.example --username alice --scan-depth standard

# Domain + people
osint-hub all corp.example --mode both --username alice --scan-depth quick

# Staged
osint-hub collect corp.example
osint-hub report --run runs/corp.example_20261023T120000
osint-hub analyze --run runs/corp.example_20261023T120000 --provider claude
osint-hub targets --run runs/corp.example_20261023T120000
osint-hub compare --run runs/corp.example_20261023T120000
```

`python -m osint_hub` is equivalent to `osint-hub`.

## Web GUI

Local investigation console. API keys still live in `.env`; the UI shows collector readiness including User Scanner.

```bash
pip install -e ".[web,people]"
osint-hub web --open
```

Binds `127.0.0.1:8741` by default and rejects non-loopback `Host` headers. A LAN `--host` requires `--allow-remote` (the console has no login).

| Command | What it does |
|---------|----------------|
| `osint-hub web` | Serve the console + JSON API on loopback |
| `osint-hub web --open` | Also open a browser tab |
| `osint-hub web --host 0.0.0.0 --allow-remote` | Bind on all interfaces (unauthenticated — trusted network only) |
| `cd web && npm install && npm run dev` | Vite dev server (proxies `/api` to port 8741) |
| `cd web && npm run build` | Rebuild static files into `osint_hub/webapp/static/` |

The launch pad lets you pick Domain, People, or Both, streams collector progress, then shows evidence including people OSINT leads when present. LLM analysis stays domain/both-only for now. ⌘K jumps to a recent run.

## Run artifacts

Each run writes `runs/<slug>_<timestamp>/` (gitignored). Domain runs use the domain slug; people-only runs use `people_<timestamp>` (no email/username in the path).

| File | Contents |
|------|----------|
| `sources/*.json` | Per-collector raw output and skip/error status |
| `bundle.json` | Normalized DNS, certs, GitHub findings, Shodan hosts, profile findings |
| `manifest.json` | Mode, target label, collector status, timings, errors |
| `correlations.json` | Rule-based `{data_points, relationship, offensive_relevance}` |
| `report.md` | Human-readable consolidation |
| `analysis_<provider>.json` | LLM JSON (after `analyze`) |
| `target_list.json` | Ranked vectors (after `targets`) |
| `raw_response.txt` | Saved if LLM JSON parsing fails |

## Collectors

| Collector | Key | Notes |
|-----------|-----|--------|
| dns | none | A/AAAA/MX/TXT/NS/CNAME on the apex, then discovered names from CT (capped) |
| crtsh | none | Public crt.sh JSON; deduped CNs/SANs in scope |
| kev | none | CISA Known Exploited Vulnerabilities catalog |
| github | `GITHUB_TOKEN` | Code search for the domain string |
| shodan | `SHODAN_API_KEY` | `hostname:` search plus host lookups for DNS A/AAAA (capped) |
| censys | `CENSYS_API_TOKEN` (or ID/secret) | Platform Search; legacy ID/secret still accepted |
| hunter | `HUNTER_API_KEY` | Domain-search for mailboxes (no person-name search) |
| tomba | `TOMBA_API_KEY` + `TOMBA_SECRET` | Domain-search for mailboxes |
| securitytrails | `SECURITYTRAILS_API_KEY` | Subdomain enumeration |
| greynoise | `GREYNOISE_API_KEY` | Community context for resolved IPs |
| urlscan | `URLSCAN_API_KEY` | Domain search |
| virustotal | `VIRUSTOTAL_API_KEY` | Domain report and in-scope subdomains |
| pdcp | `PDCP_API_KEY` | Chaos DNS, then Cloud associated-domains fallback |
| leakix | `LEAKIX_API_KEY` | Domain metadata only; leak payloads are not stored |
| hibp | `HIBP_API_KEY` | Breach check for collected mailboxes |
| abuseipdb | `ABUSEIPDB_API_KEY` | Reputation check for resolved IPs |
| ipinfo | `IPINFO_TOKEN` | Org/ASN for resolved IPs |
| phone_enrich | Tomba, else Hunter | Extra phones for top-ranked mailboxes still missing a number when `PEOPLE_PHONE_ENRICH_MAX` > 0 |
| user_scanner | optional `people` extra | Email/username account-existence leads via User Scanner (MIT). Loud modules off by default |

Metered collectors skip until their key is set. Caps and timeouts are under Configuration. There is no LinkedIn scraper.

## Correlation rules (v1)

- GitHub match text ↔ in-scope hostnames / CT common names
- DNS A/AAAA IP ↔ Shodan host
- Shodan title/product matches for Jenkins, Grafana, OWA, VPN, and similar admin surfaces
- CT `not_after` in the past
- SPF/DMARC TXT posture (intelligence only — no spoofing or exploitation)
- Exact email/username seed ↔ User Scanner found profile (leads only — no cross-platform identity claim)

## Troubleshooting

- **GitHub/Shodan skipped** — expected until the matching `.env` key is set.
- **crt.sh non-JSON** — the public API is often rate-limited; wait and retry.
- **Ollama connection error** — for local, confirm `ollama serve` and `OLLAMA_BASE_URL`. For cloud, use `https://ollama.com` and `OLLAMA_API_KEY`.
- **Ollama HTTP 404** — cloud uses `/api/chat` and a catalog model from `GET https://ollama.com/api/tags` (not local names like `llama3.2`).
- **LLM JSON parse failed** — inspect `raw_response.txt` in the run directory; try Claude or a larger local model.
- **Shodan 401** — invalid or exhausted API key.

## Secrets and run data

Do not commit `.env` or `runs/` (API keys and target identifiers). Copy `.env.example` into the repo root (parent-directory `.env` files such as `~/.env` are not loaded). Keep investigation artifacts off GitHub.

Collection rejects IP literals and public suffixes (`co.uk`, `github.io`, …) so a target must be an organization domain.
