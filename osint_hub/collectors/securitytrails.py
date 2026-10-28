"""SecurityTrails subdomain enumeration. Requires SECURITYTRAILS_API_KEY."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult
from osint_hub.util import is_in_scope

URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
CAP = 100


def _names(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for label in payload.get("subdomains") or []:
        host = str(label).strip(".").lower()
        if not host or "*" in host:
            continue
        fqdn = host if host.endswith("." + domain) or host == domain else f"{host}.{domain}"
        if is_in_scope(fqdn, domain) and fqdn not in found:
            found.append(fqdn)
        if len(found) >= CAP:
            break
    return found


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_securitytrails:
        return skipped("securitytrails", "SECURITYTRAILS_API_KEY not set", started)
    try:
        response = await get_with_retry(
            client,
            URL.format(domain=domain),
            headers=client_headers(settings, {"APIKEY": settings.securitytrails_api_key or ""}),
        )
        if response.status_code >= 400:
            raise RuntimeError(f"SecurityTrails HTTP {response.status_code}: {response.text[:200]}")
        names = _names(response.json(), domain)
    except Exception as exc:  # noqa: BLE001
        return failed("securitytrails", str(exc), started)
    return CollectorResult(
        name="securitytrails",
        status="ok",
        records=len(names),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=names,
    )
