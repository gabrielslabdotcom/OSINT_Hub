"""Certificate Transparency collector via the public crt.sh JSON API (no API key)."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, get_with_retry
from osint_hub.config import Settings
from osint_hub.models import Certificate, CollectorResult
from osint_hub.util import is_in_scope

CRTSH_URL = "https://crt.sh/"
MAX_CERTS = 200


def _split_names(blob: str | None) -> list[str]:
    if not blob:
        return []
    names: list[str] = []
    for line in blob.replace(",", "\n").splitlines():
        name = line.strip().lower().rstrip(".")
        if name:
            names.append(name)
    return names


def _parse_certs(payload: object, domain: str) -> list[Certificate]:
    if not isinstance(payload, list):
        return []
    seen: set[tuple[str, str, str]] = set()
    certs: list[Certificate] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        common_name = str(row.get("common_name") or "").strip().lower().rstrip(".")
        issuer = str(row.get("issuer_name") or row.get("issuer") or "unknown")
        not_after = str(row.get("not_after") or "")
        names = _split_names(row.get("name_value"))
        if common_name:
            names.insert(0, common_name)
        scoped = []
        for name in names:
            if is_in_scope(name, domain) and name not in scoped:
                scoped.append(name)
        if not scoped:
            continue
        cn = common_name or scoped[0]
        key = (cn, issuer, not_after)
        if key in seen:
            continue
        seen.add(key)
        certs.append(Certificate(common_name=cn, issuer=issuer, not_after=not_after, names=scoped))
        if len(certs) >= MAX_CERTS:
            break
    return certs


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    headers = client_headers(settings)
    retry_statuses = {429, 404, 502, 503}
    last_status = 0
    certs: list[Certificate] = []
    try:
        for query in (f"%.{domain}", domain):
            response = await get_with_retry(
                client,
                CRTSH_URL,
                params={"q": query, "output": "json"},
                headers=headers,
                retry_statuses=retry_statuses,
            )
            last_status = response.status_code
            if response.status_code >= 400:
                continue
            try:
                payload = response.json()
            except ValueError:
                continue
            certs = _parse_certs(payload, domain)
            break
        else:
            if last_status >= 400:
                raise RuntimeError(f"crt.sh HTTP {last_status}")
            raise RuntimeError("crt.sh returned non-JSON (rate limited or HTML error page)")
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.perf_counter() - started) * 1000)
        return CollectorResult(
            name="crtsh",
            status="error",
            error=str(exc),
            duration_ms=elapsed,
            data=[],
        )
    elapsed = int((time.perf_counter() - started) * 1000)
    return CollectorResult(
        name="crtsh",
        status="ok",
        records=len(certs),
        duration_ms=elapsed,
        data=certs,
    )
