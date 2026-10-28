"""LeakIX domain metadata. Requires LEAKIX_API_KEY. Never stores leak payloads."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, LeakRecord
from osint_hub.util import is_in_scope

URL = "https://leakix.net/domain/{domain}"
CAP = 20


def _plugin(item: dict) -> str:
    leak = item.get("leak") if isinstance(item.get("leak"), dict) else {}
    return str(
        item.get("event_source")
        or item.get("plugin")
        or (leak or {}).get("type")
        or item.get("type")
        or ""
    )[:80]


def _event_label(item: dict, kind: str) -> str:
    leak = item.get("leak") if isinstance(item.get("leak"), dict) else {}
    bits = [
        str(item.get("event_type") or kind),
        str((leak or {}).get("severity") or ""),
    ]
    return " ".join(part for part in bits if part).strip()[:120]


def _event_row(item: object, kind: str, domain: str) -> LeakRecord | None:
    if not isinstance(item, dict):
        return None
    host = str(item.get("host") or item.get("hostname") or "").strip(".").lower()
    if not host or not is_in_scope(host, domain):
        return None
    port_raw = item.get("port") or 0
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 0
    return LeakRecord(
        ip=str(item.get("ip") or ""),
        hostname=host,
        port=port,
        protocol=str(item.get("protocol") or ""),
        plugin=_plugin(item),
        event=_event_label(item, kind),
        kind=kind,
    )


def _rows(payload: object, domain: str) -> list[LeakRecord]:
    found: list[LeakRecord] = []
    seen: set[str] = set()
    buckets: list[tuple[str, object]] = []
    if isinstance(payload, dict):
        for kind, key in (("service", "Services"), ("leak", "Leaks"), ("service", "services"), ("leak", "leaks")):
            buckets.append((kind, payload.get(key)))
    elif isinstance(payload, list):
        buckets.append(("event", payload))
    for kind, group in buckets:
        for item in group or []:
            row = _event_row(item, kind, domain)
            if row is None or row.entity_id in seen:
                continue
            seen.add(row.entity_id)
            found.append(row)
            if len(found) >= CAP:
                return found
    return found


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_leakix:
        return skipped("leakix", "LEAKIX_API_KEY not set", started)
    try:
        response = await get_with_retry(
            client,
            URL.format(domain=domain),
            headers=client_headers(settings, {"api-key": settings.leakix_api_key or ""}),
        )
        if response.status_code >= 400:
            body = response.text[:200]
            key = settings.leakix_api_key or ""
            if key and key in body:
                body = body.replace(key, "<redacted>")
            raise RuntimeError(f"LeakIX HTTP {response.status_code}: {body}")
        rows = _rows(response.json(), domain)
    except Exception as exc:  # noqa: BLE001
        return failed("leakix", str(exc), started)
    return CollectorResult(
        name="leakix",
        status="ok",
        records=len(rows),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
