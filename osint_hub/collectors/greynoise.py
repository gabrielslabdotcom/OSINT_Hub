"""GreyNoise community context for resolved IPs. Requires GREYNOISE_API_KEY."""

from __future__ import annotations

import ipaddress
import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, IpIntel

URL = "https://api.greynoise.io/v3/community/{ip}"


def _row(payload: object, ip: str) -> IpIntel:
    data = payload if isinstance(payload, dict) else {}
    return IpIntel(
        ip=ip,
        greynoise_classification=str(data.get("classification") or ""),
        greynoise_noise=bool(data["noise"]) if "noise" in data else None,
        greynoise_riot=bool(data["riot"]) if "riot" in data else None,
        greynoise_name=str(data.get("name") or ""),
        greynoise_last_seen=str(data.get("last_seen") or ""),
    )


async def collect(settings: Settings, client: httpx.AsyncClient, ips: list[str]) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_greynoise:
        return skipped("greynoise", "GREYNOISE_API_KEY not set", started)
    headers = client_headers(settings, {"key": settings.greynoise_api_key or ""})
    rows: list[IpIntel] = []
    errors: list[str] = []
    try:
        for ip in ips:
            try:
                if ipaddress.ip_address(ip).version == 6:
                    continue
            except ValueError:
                continue
            response = await get_with_retry(client, URL.format(ip=ip), headers=headers)
            if response.status_code == 404:
                rows.append(IpIntel(ip=ip, greynoise_classification="unknown"))
                continue
            if response.status_code >= 400:
                errors.append(f"{ip}: HTTP {response.status_code}")
                continue
            rows.append(_row(response.json(), ip))
    except Exception as exc:  # noqa: BLE001
        return failed("greynoise", str(exc), started)
    error = "; ".join(errors) if errors else None
    return CollectorResult(
        name="greynoise",
        status="ok" if not (error and not rows) else "error",
        records=len(rows),
        error=error,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
