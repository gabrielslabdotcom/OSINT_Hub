# OSINT_Hub

Live OSINT collection, deterministic cross-source correlation, and optional LLM attack-surface analysis.

Authorized targets only. Respect each API’s terms of service and rate limits. Do not use this against systems you do not have permission to assess. There is no LinkedIn scraper.

## What it does

1. **Collect** — DNS, [crt.sh](https://crt.sh) certificate transparency, GitHub code search, and Shodan host lookups in parallel where keys exist.
2. **Correlate** — rule-based joins (hostname alignment, IP convergence, admin-UI exposure tags, expired certs, SPF/DMARC) written to `correlations.json` **before** any LLM runs.
3. **Report** — one markdown document plus a unified `bundle.json`.
4. **Analyze (optional)** — send the report plus precomputed edges to a local Ollama model or Claude; emit lab-shaped JSON and a Rich target list.

Missing API keys skip that collector with a warning. DNS and crt.sh need none.

## Setup

```bash
git clone https://github.com/gabrielslabdotcom/OSINT_Hub.git
cd OSINT_Hub
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web]"
cp .env.example .env
```

Fill `.env` with keys you have. The web extra includes the Anthropic SDK; Claude analysis also needs `ANTHROPIC_API_KEY`.

On a lab Linux box with Ollama, point `OLLAMA_BASE_URL` at that host. On a real engagement, sanitize client identifiers before sending anything to a cloud model.

## Configuration

| Variable | Used by |
|----------|---------|
| `SHODAN_API_KEY` | Shodan collector |
| `GITHUB_TOKEN` | GitHub code search (recommended; unauthenticated search is not used) |
| `OLLAMA_BASE_URL` | Ollama host (`https://ollama.com` or `http://127.0.0.1:11434`) |
| `OLLAMA_API_KEY` | Ollama Cloud (required for `https://ollama.com`; unused locally) |
| `OLLAMA_MODEL` | Model name (`gemma4:31b` on cloud; `llama3.2` locally) |
| `ANTHROPIC_API_KEY` | Cloud LLM |
| `ANTHROPIC_MODEL` | Claude model id |

## CLI

```bash
# Collection + correlation only
osint-hub all corp.example

# Full pipeline with a local model
osint-hub all corp.example --analyze local

# Staged
osint-hub collect corp.example
osint-hub report --run runs/corp.example_20261023T120000
osint-hub analyze --run runs/corp.example_20261023T120000 --provider claude
osint-hub targets --run runs/corp.example_20261023T120000
osint-hub compare --run runs/corp.example_20261023T120000
```

`python -m osint_hub` is equivalent to `osint-hub`.

## Web GUI

Local investigation console. API keys still live in `.env`; the UI only shows whether GitHub, Shodan, Ollama, and Claude are configured.

```bash
pip install -e ".[web]"
osint-hub web --open
```

Binds `127.0.0.1:8741` by default. Do not pass a LAN `--host` unless you intend to expose recon artifacts on the network.

| Command | What it does |
|---------|----------------|
| `osint-hub web` | Serve the console + JSON API |
| `osint-hub web --open` | Also open a browser tab |
| `cd web && npm install && npm run dev` | Vite dev server (proxies `/api` to port 8741) |
| `cd web && npm run build` | Rebuild static files into `osint_hub/webapp/static/` |

The launch pad opens a dossier, streams collector progress, then shows DNS, certificates, GitHub, Shodan, correlation threads, the markdown report, optional LLM analysis, and ranked targets. ⌘K jumps to a recent run.

## Run artifacts

Each run writes `runs/<domain>_<timestamp>/` (gitignored):

| File | Contents |
|------|----------|
| `sources/*.json` | Per-collector raw output and skip/error status |
| `bundle.json` | Normalized DNS, certs, GitHub findings, Shodan hosts |
| `manifest.json` | Collector status, timings, errors |
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
| github | `GITHUB_TOKEN` | Code search for the domain string |
| shodan | `SHODAN_API_KEY` | `hostname:` search plus host lookups for DNS A/AAAA (capped) |

GitHub code search and Shodan lookups are metered. Caps: `DNS_MAX_HOSTS` (default 80), `SHODAN_MAX_HOSTS` (default 15), `GITHUB_MAX_RESULTS` (default 30).

People/LinkedIn is not in v1 (no legitimate bulk API). Optional later: Hunter.io or a CSV import collector.

## Correlation rules (v1)

- GitHub match text ↔ in-scope hostnames / CT common names
- DNS A/AAAA IP ↔ Shodan host
- Shodan title/product matches for Jenkins, Grafana, OWA, VPN, and similar admin surfaces
- CT `not_after` in the past
- SPF/DMARC TXT posture (intelligence only — no spoofing or exploitation)

## Troubleshooting

- **GitHub/Shodan skipped** — expected until the matching `.env` key is set.
- **crt.sh non-JSON** — the public API is often rate-limited; wait and retry.
- **Ollama connection error** — for local, confirm `ollama serve` and `OLLAMA_BASE_URL`. For cloud, use `https://ollama.com` and `OLLAMA_API_KEY`.
- **Ollama HTTP 404** — cloud uses `/api/chat` and a catalog model from `GET https://ollama.com/api/tags` (not local names like `llama3.2`).
- **LLM JSON parse failed** — inspect `raw_response.txt` in the run directory; try Claude or a larger local model.
- **Shodan 401** — invalid or exhausted API key.

## Secrets and run data

Do not commit `.env` or `runs/` (API keys and target identifiers). Copy `.env.example` locally and keep investigation artifacts off GitHub.
