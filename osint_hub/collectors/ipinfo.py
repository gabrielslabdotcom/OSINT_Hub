"""IPinfo org/ASN for resolved IPs. Requires IPINFO_TOKEN."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, IpIntel

URL = "https://ipinfo.io/{ip}"


def _row(payload: object, ip: str) -> IpIntel:
    data = payload if isinstance(payload, dict) else {}
    org = str(data.get("org") or "")
    asn = ""
    if org.startswith("AS"):
        asn = org.split(" ", 1)[0]
    return IpIntel(ip=ip, org=org, asn=asn, hostname=str(data.get("hostname") or ""))


async def collect(settings: Settings, client: httpx.AsyncClient, ips: list[str]) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_ipinfo:
        return skipped("ipinfo", "IPINFO_TOKEN not set", started)
    headers = client_headers(settings)
    rows: list[IpIntel] = []
    errors: list[str] = []
    try:
        for ip in ips:
            response = await get_with_retry(
                client,
                URL.format(ip=ip),
                params={"token": settings.ipinfo_token},
                headers=headers,
            )
            if response.status_code >= 400:
                errors.append(f"{ip}: HTTP {response.status_code}")
                continue
            rows.append(_row(response.json(), ip))
    except Exception as exc:  # noqa: BLE001
        return failed("ipinfo", str(exc), started)
    error = "; ".join(errors) if errors else None
    return CollectorResult(
        name="ipinfo",
        status="ok" if not (error and not rows) else "error",
        records=len(rows),
        error=error,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
