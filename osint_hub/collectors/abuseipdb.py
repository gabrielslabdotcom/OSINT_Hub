"""AbuseIPDB check for resolved IPs. Requires ABUSEIPDB_API_KEY."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, IpIntel

URL = "https://api.abuseipdb.com/api/v2/check"


def _row(payload: object, ip: str) -> IpIntel:
    data = (payload.get("data") if isinstance(payload, dict) else None) or {}
    score = data.get("abuseConfidenceScore")
    return IpIntel(
        ip=ip,
        abuse_score=int(score) if score is not None else None,
        abuse_usage_type=str(data.get("usageType") or ""),
        abuse_isp=str(data.get("isp") or ""),
        org=str(data.get("isp") or ""),
    )


async def collect(settings: Settings, client: httpx.AsyncClient, ips: list[str]) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_abuseipdb:
        return skipped("abuseipdb", "ABUSEIPDB_API_KEY not set", started)
    headers = client_headers(settings, {"Key": settings.abuseipdb_api_key or ""})
    rows: list[IpIntel] = []
    errors: list[str] = []
    try:
        for ip in ips:
            response = await get_with_retry(
                client,
                URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers,
            )
            if response.status_code >= 400:
                errors.append(f"{ip}: HTTP {response.status_code}")
                continue
            rows.append(_row(response.json(), ip))
    except Exception as exc:  # noqa: BLE001
        return failed("abuseipdb", str(exc), started)
    error = "; ".join(errors) if errors else None
    return CollectorResult(
        name="abuseipdb",
        status="ok" if not (error and not rows) else "error",
        records=len(rows),
        error=error,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
