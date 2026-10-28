"""URLScan domain search. Requires URLSCAN_API_KEY."""

from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, UrlScanRecord
from osint_hub.util import is_in_scope

URL = "https://urlscan.io/api/v1/search/"
CAP = 15


def _host_from_url(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").strip(".").lower()
    except Exception:  # noqa: BLE001
        return ""


def _rows(payload: object, domain: str) -> list[UrlScanRecord]:
    if not isinstance(payload, dict):
        return []
    found: list[UrlScanRecord] = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        page = item.get("page") or {}
        url = str(page.get("url") or item.get("task", {}).get("url") or "")
        host = _host_from_url(url)
        if not url or not host or not is_in_scope(host, domain):
            continue
        scan_id = str(item.get("_id") or "")
        scan_url = str(item.get("result") or "")
        if not scan_url and scan_id:
            scan_url = f"https://urlscan.io/result/{scan_id}/"
        found.append(
            UrlScanRecord(
                url=url,
                title=str(page.get("title") or ""),
                ip=str(page.get("ip") or ""),
                scan_url=scan_url,
            )
        )
        if len(found) >= CAP:
            break
    return found


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_urlscan:
        return skipped("urlscan", "URLSCAN_API_KEY not set", started)
    try:
        response = await get_with_retry(
            client,
            URL,
            params={"q": f"domain:{domain}", "size": CAP},
            headers=client_headers(settings, {"API-Key": settings.urlscan_api_key or ""}),
        )
        if response.status_code >= 400:
            raise RuntimeError(f"URLScan HTTP {response.status_code}: {response.text[:200]}")
        rows = _rows(response.json(), domain)
    except Exception as exc:  # noqa: BLE001
        return failed("urlscan", str(exc), started)
    return CollectorResult(
        name="urlscan",
        status="ok",
        records=len(rows),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
