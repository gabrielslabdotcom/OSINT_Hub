"""Have I Been Pwned breach check for collected mailboxes. Requires HIBP_API_KEY."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import quote

import httpx

from osint_hub.collectors.base import client_headers, failed, skipped
from osint_hub.config import Settings
from osint_hub.models import BreachRecord, CollectorResult, EmailRecord

URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
CAP = 25
PAUSE = 1.6


def _breaches(payload: object, email: str) -> list[BreachRecord]:
    if not isinstance(payload, list):
        return []
    rows: list[BreachRecord] = []
    for item in payload:
        name = ""
        date = ""
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = str(item.get("Name") or item.get("Title") or "")
            date = str(item.get("BreachDate") or "")
        if name:
            rows.append(BreachRecord(email=email, name=name, breach_date=date))
    return rows


async def collect(
    settings: Settings,
    client: httpx.AsyncClient,
    emails: list[EmailRecord],
) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_hibp:
        return skipped("hibp", "HIBP_API_KEY not set", started)
    if not emails:
        return skipped("hibp", "no mailboxes to check", started)
    headers = client_headers(
        settings,
        {"hibp-api-key": settings.hibp_api_key or "", "user-agent": settings.user_agent},
    )
    rows: list[BreachRecord] = []
    errors: list[str] = []
    try:
        for index, record in enumerate(emails[:CAP]):
            if index:
                await asyncio.sleep(PAUSE)
            response = await client.get(
                URL.format(email=quote(record.email, safe="@")),
                params={"truncateResponse": "true"},
                headers=headers,
            )
            if response.status_code == 404:
                continue
            if response.status_code == 429:
                wait = response.headers.get("Retry-After") or "2"
                await asyncio.sleep(min(int(wait) if wait.isdigit() else 2, 30))
                response = await client.get(
                    URL.format(email=quote(record.email, safe="@")),
                    params={"truncateResponse": "true"},
                    headers=headers,
                )
            if response.status_code >= 400:
                errors.append(f"{record.email}: HTTP {response.status_code}")
                continue
            rows.extend(_breaches(response.json(), record.email))
    except Exception as exc:  # noqa: BLE001
        return failed("hibp", str(exc), started)
    error = "; ".join(errors) if errors else None
    return CollectorResult(
        name="hibp",
        status="ok" if not (error and not rows and emails[:CAP]) else "error",
        records=len(rows),
        error=error,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=rows,
    )
