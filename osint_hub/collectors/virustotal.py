"""VirusTotal domain report. Requires VIRUSTOTAL_API_KEY."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, VtDomain
from osint_hub.util import is_in_scope

DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
SUBS_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
CAP = 40


def _parse_domain(payload: object, domain: str) -> VtDomain:
    attrs = {}
    if isinstance(payload, dict):
        data = payload.get("data") or {}
        if isinstance(data, dict):
            attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    categories = attrs.get("categories") or {}
    cat_list = sorted({str(v) for v in (categories.values() if isinstance(categories, dict) else [])})
    resolutions: list[str] = []
    for record in attrs.get("last_dns_records") or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("type") or "").upper() in {"A", "AAAA"} and record.get("value"):
            ip = str(record["value"])
            if ip not in resolutions:
                resolutions.append(ip)
    return VtDomain(
        domain=domain,
        malicious=int(stats.get("malicious") or 0),
        suspicious=int(stats.get("suspicious") or 0),
        harmless=int(stats.get("harmless") or 0),
        undetected=int(stats.get("undetected") or 0),
        categories=cat_list[:12],
        resolutions=resolutions[:CAP],
    )


def _subdomains(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    found: list[str] = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("id") or "").strip(".").lower()
        if host and is_in_scope(host, domain) and "*" not in host and host not in found:
            found.append(host)
        if len(found) >= CAP:
            break
    return found


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_virustotal:
        return skipped("virustotal", "VIRUSTOTAL_API_KEY not set", started)
    headers = client_headers(settings, {"x-apikey": settings.virustotal_api_key or ""})
    try:
        response = await get_with_retry(client, DOMAIN_URL.format(domain=domain), headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(f"VirusTotal HTTP {response.status_code}: {response.text[:200]}")
        report = _parse_domain(response.json(), domain)
        subs = await get_with_retry(client, SUBS_URL.format(domain=domain), params={"limit": CAP}, headers=headers)
        if subs.status_code < 400:
            report.subdomains = _subdomains(subs.json(), domain)
    except Exception as exc:  # noqa: BLE001
        return failed("virustotal", str(exc), started)
    return CollectorResult(
        name="virustotal",
        status="ok",
        records=1 + len(report.subdomains) + len(report.resolutions),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=[report],
    )
