"""Shared helpers for domains, run directories, and JSON I/O."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    value = value.split("/")[0].split(":")[0].strip(".")
    if ".." in value or not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"Invalid domain: {raw!r}")
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
    path = runs_root / f"{domain}_{utc_stamp()}"
    path.mkdir(parents=True, exist_ok=False)
    (path / "sources").mkdir()
    return path


def resolve_run_dir(path: str | Path) -> Path:
    run_dir = Path(path).expanduser().resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")
    if not (run_dir / "bundle.json").is_file() and not (run_dir / "sources").is_dir():
        raise FileNotFoundError(f"Not an OSINT_Hub run directory: {run_dir}")
    return run_dir


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def find_env_file() -> Path | None:
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate
    pkg_root = Path(__file__).resolve().parent.parent
    candidate = pkg_root / ".env"
    if candidate.is_file():
        return candidate
    return None


def dump_model(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model
