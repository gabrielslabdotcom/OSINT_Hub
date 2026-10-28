"""Shared helpers for domains, run directories, and JSON I/O."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

# Multi-label public suffixes only. Single-label TLDs already fail DOMAIN_RE.
PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "me.uk",
        "ac.uk",
        "gov.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "govt.nz",
        "ac.nz",
        "co.za",
        "org.za",
        "web.za",
        "gov.za",
        "ac.za",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "com.br",
        "org.br",
        "net.br",
        "gov.br",
        "co.in",
        "org.in",
        "net.in",
        "firm.in",
        "gen.in",
        "ind.in",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.mx",
        "org.mx",
        "gob.mx",
        "co.kr",
        "or.kr",
        "ne.kr",
        "go.kr",
        "ac.kr",
        "co.il",
        "org.il",
        "ac.il",
        "gov.il",
        "com.tw",
        "org.tw",
        "gov.tw",
        "edu.tw",
        "com.hk",
        "org.hk",
        "gov.hk",
        "edu.hk",
        "com.sg",
        "org.sg",
        "gov.sg",
        "edu.sg",
        "com.ar",
        "org.ar",
        "gob.ar",
        "com.tr",
        "org.tr",
        "gov.tr",
        "com.pl",
        "org.pl",
        "net.pl",
        "co.th",
        "or.th",
        "ac.th",
        "go.th",
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "azurewebsites.net",
        "cloudapp.net",
        "cloudfront.net",
        "s3.amazonaws.com",
        "appspot.com",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "workers.dev",
        "fly.dev",
        "onrender.com",
        "web.app",
        "firebaseapp.com",
        "blob.core.windows.net",
        "amazonaws.com",
    }
)


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    value = value.split("/")[0].split(":")[0].strip(".")
    if ".." in value or not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"Invalid domain: {raw!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(f"Invalid domain (IP literals are not allowed): {raw!r}")
    if value in PUBLIC_SUFFIXES:
        raise ValueError(f"Invalid domain (public suffix is not a target): {raw!r}")
    return value


def is_in_scope(hostname: str, domain: str) -> bool:
    host = hostname.strip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    return host == domain or host.endswith("." + domain)


def contains_hostname_token(text: str, hostname: str) -> bool:
    """True when hostname appears as a name token, not a substring of a longer domain."""
    blob = (text or "").lower()
    needle = (hostname or "").strip(".").lower()
    if not blob or not needle:
        return False
    pattern = rf"(?<![a-z0-9-]){re.escape(needle)}(?![a-z0-9.-])"
    return re.search(pattern, blob) is not None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_stamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%S")


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat()


def new_run_dir(runs_root: Path, domain: str) -> Path:
    stamp = utc_stamp()
    last_error: OSError | None = None
    for suffix in ("", *(f"_{index}" for index in range(1, 20))):
        path = runs_root / f"{domain}_{stamp}{suffix}"
        try:
            path.mkdir(parents=True, exist_ok=False)
            (path / "sources").mkdir()
            return path
        except FileExistsError as exc:
            last_error = exc
            continue
    raise RuntimeError(f"Could not allocate a unique run directory under {runs_root}") from last_error


def resolve_run_dir(path: str | Path) -> Path:
    run_dir = Path(path).expanduser().resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError("Run directory not found")
    if not (run_dir / "bundle.json").is_file() and not (run_dir / "sources").is_dir():
        raise FileNotFoundError("Not an OSINT_Hub run directory")
    return run_dir


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def find_env_file() -> Path | None:
    """Load only the package repo `.env` — never parent directories such as `$HOME/.env`."""
    pkg_root = Path(__file__).resolve().parent.parent
    candidate = pkg_root / ".env"
    if candidate.is_file():
        return candidate
    return None


def dump_model(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model
