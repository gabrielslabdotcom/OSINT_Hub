"""ProjectDiscovery Cloud / Chaos names. Requires PDCP_API_KEY.

Tries Chaos DNS first. Free Cloud keys often get 401 there; in that case we
fall back to Cloud associated-domains and any existing PDCP asset rows.
Does not start a PDCP enumeration scan.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult
from osint_hub.util import is_in_scope

CHAOS_URL = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
ASSOCIATED_URL = "https://api.projectdiscovery.io/v1/domain/associated"
CONTENTS_URL = "https://api.projectdiscovery.io/v1/asset/enumerate/contents"
CAP = 100


def _host(value: object) -> str:
    text = str(value or "").strip().strip(".").lower()
    if "://" in text:
        text = (urlparse(text).hostname or "").strip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    return text


def _add(found: list[str], value: object, domain: str) -> None:
    host = _host(value)
    if not host or "*" in host:
        return
    fqdn = host if host.endswith("." + domain) or host == domain else host
    if is_in_scope(fqdn, domain) and fqdn not in found:
        found.append(fqdn)


def _from_chaos(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for label in payload.get("subdomains") or []:
        host = _host(label)
        if not host or "*" in host:
            continue
        fqdn = host if host.endswith("." + domain) or host == domain else f"{host}.{domain}"
        _add(found, fqdn, domain)
        if len(found) >= CAP:
            break
    return found


def _from_associated(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        _add(found, item.get("domain"), domain)
        _add(found, (evidence or {}).get("cert_common_name"), domain)
        if len(found) >= CAP:
            break
    return found


def _from_contents(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        _add(found, item.get("name"), domain)
        _add(found, item.get("host"), domain)
        _add(found, item.get("domain_name"), domain)
        if len(found) >= CAP:
            break
    return found


async def _chaos(client: httpx.AsyncClient, domain: str, settings: Settings, key: str) -> httpx.Response:
    headers = client_headers(settings, {"Authorization": key, "X-Api-Key": key})
    last: httpx.Response | None = None
    for attempt in range(3):
        response = await get_with_retry(client, CHAOS_URL.format(domain=domain), headers=headers)
        last = response
        if response.status_code not in {500, 502, 503}:
            return response
        await asyncio.sleep(1 + attempt)
    assert last is not None
    return last


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_pdcp:
        return skipped("pdcp", "PDCP_API_KEY not set", started)
    key = settings.pdcp_api_key or ""
    names: list[str] = []
    notes: list[str] = []
    try:
        chaos = await _chaos(client, domain, settings, key)
        if chaos.status_code == 200:
            names = _from_chaos(chaos.json(), domain)
        elif chaos.status_code in {401, 403}:
            notes.append("Chaos DNS rejected this key; using Cloud associated domains / existing assets")
        elif chaos.status_code >= 400:
            notes.append(f"Chaos DNS HTTP {chaos.status_code}")
        if len(names) < CAP:
            cloud_headers = client_headers(settings, {"X-Api-Key": key})
            associated = await get_with_retry(
                client,
                ASSOCIATED_URL,
                params={"domain": domain, "limit": 50},
                headers=cloud_headers,
            )
            if associated.status_code == 200:
                for name in _from_associated(associated.json(), domain):
                    if name not in names:
                        names.append(name)
                    if len(names) >= CAP:
                        break
            elif associated.status_code >= 400:
                notes.append(f"Cloud associated HTTP {associated.status_code}")
            if len(names) < CAP:
                contents = await get_with_retry(
                    client,
                    CONTENTS_URL,
                    params={"domain": domain, "only_dns": "true", "limit": CAP},
                    headers=cloud_headers,
                )
                if contents.status_code == 200:
                    for name in _from_contents(contents.json(), domain):
                        if name not in names:
                            names.append(name)
                        if len(names) >= CAP:
                            break
                elif contents.status_code >= 400:
                    notes.append(f"Cloud assets HTTP {contents.status_code}")
        if not names and notes and all("rejected this key" not in note and "HTTP 401" not in note and "HTTP 403" not in note for note in notes if "associated" in note or "assets" in note):
            cloud_failed = [note for note in notes if note.startswith("Cloud")]
            if cloud_failed and "Chaos DNS rejected" in " ".join(notes):
                raise RuntimeError("; ".join(notes)[:300])
    except Exception as exc:  # noqa: BLE001
        return failed("pdcp", str(exc), started)
    return CollectorResult(
        name="pdcp",
        status="ok",
        records=len(names),
        error="; ".join(notes) or None,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=names,
    )
