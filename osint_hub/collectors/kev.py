"""Fetch the CISA Known Exploited Vulnerabilities catalog. No API key."""

from __future__ import annotations

import time
from typing import Any

import httpx

from osint_hub.collectors.base import client_headers, get_with_retry
from osint_hub.config import Settings
from osint_hub.models import CollectorResult

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def compact_entries(payload: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        rows.append(
            {
                "cve_id": cve,
                "vendor": str(item.get("vendorProject") or "").strip(),
                "product": str(item.get("product") or "").strip(),
                "name": str(item.get("vulnerabilityName") or "").strip(),
                "date_added": str(item.get("dateAdded") or "").strip(),
                "short_description": str(item.get("shortDescription") or "").strip(),
                "required_action": str(item.get("requiredAction") or "").strip(),
                "known_ransomware": str(item.get("knownRansomwareCampaignUse") or "").strip(),
            }
        )
    return rows


async def collect(settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    headers = client_headers(settings)
    try:
        response = await get_with_retry(client, KEV_URL, headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(f"CISA KEV HTTP {response.status_code}: {response.text[:200]}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("CISA KEV returned a non-object payload")
        entries = compact_entries(payload)
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.perf_counter() - started) * 1000)
        return CollectorResult(
            name="kev",
            status="error",
            error=str(exc),
            duration_ms=elapsed,
            data=[],
        )
    elapsed = int((time.perf_counter() - started) * 1000)
    return CollectorResult(
        name="kev",
        status="ok",
        records=len(entries),
        duration_ms=elapsed,
        data=entries,
    )
