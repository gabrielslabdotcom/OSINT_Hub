"""HTTP helpers shared by API-backed collectors."""

from __future__ import annotations

import asyncio
import time

import httpx

from osint_hub.config import Settings
from osint_hub.models import CollectorResult


def client_headers(settings: Settings, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"User-Agent": settings.user_agent, "Accept": "application/json"}
    if extra:
        headers.update(extra)
    return headers


def skipped(name: str, error: str, started: float) -> CollectorResult:
    return CollectorResult(
        name=name,
        status="skipped",
        error=error,
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=[],
    )


def failed(name: str, error: str, started: float) -> CollectorResult:
    return CollectorResult(
        name=name,
        status="error",
        error=str(error),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=[],
    )


def _retry_wait(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return min(int(retry_after), 30)
    return min(2 ** attempt, 30)


async def get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict[str, str] | None = None,
    attempts: int = 4,
    retry_statuses: set[int] | None = None,
) -> httpx.Response:
    retry_on = retry_statuses if retry_statuses is not None else {429}
    last: httpx.Response | None = None
    for attempt in range(attempts):
        response = await client.get(url, params=params, headers=headers)
        last = response
        if response.status_code not in retry_on:
            return response
        await asyncio.sleep(_retry_wait(response, attempt))
    assert last is not None
    return last


async def post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: dict | None = None,
    params: dict | None = None,
    headers: dict[str, str] | None = None,
    attempts: int = 4,
    retry_statuses: set[int] | None = None,
) -> httpx.Response:
    retry_on = retry_statuses if retry_statuses is not None else {429}
    last: httpx.Response | None = None
    for attempt in range(attempts):
        response = await client.post(url, json=json, params=params, headers=headers)
        last = response
        if response.status_code not in retry_on:
            return response
        await asyncio.sleep(_retry_wait(response, attempt))
    assert last is not None
    return last
