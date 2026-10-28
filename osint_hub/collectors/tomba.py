"""Tomba domain-search for mailboxes. Requires TOMBA_API_KEY and TOMBA_SECRET."""

from __future__ import annotations

import time
from typing import Any

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, EmailRecord
from osint_hub.people import merge_email_records

URL = "https://api.tomba.io/v1/domain-search"
FREE_LIMIT = 10
PAID_LIMIT = 20
PREFERRED: tuple[str, ...] = ("executive", "it", "finance", "")


def _phone(item: dict[str, Any]) -> str:
    value = item.get("phone_number") or item.get("phone") or ""
    if isinstance(value, dict):
        value = value.get("number") or value.get("value") or ""
    phone_data = item.get("phone_data")
    if not value and isinstance(phone_data, list) and phone_data:
        first = phone_data[0]
        if isinstance(first, dict):
            value = first.get("phone_number") or first.get("number") or ""
        else:
            value = first
    return str(value or "").strip()


def _linkedin(item: dict[str, Any]) -> str:
    return str(item.get("linkedin") or item.get("linkedin_url") or "").strip()


def _email_value(item: dict[str, Any]) -> str:
    return str(item.get("email") or item.get("value") or "").strip().lower()


def _emails(payload: object, domain: str, *, cap: int) -> list[EmailRecord]:
    data = payload.get("data") if isinstance(payload, dict) else None
    rows = (data or {}).get("emails") if isinstance(data, dict) else []
    found: list[EmailRecord] = []
    suffix = "@" + domain
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        email = _email_value(item)
        if not email.endswith(suffix):
            continue
        score = item.get("score") or item.get("confidence")
        confidence = int(score) if str(score or "").replace(".", "", 1).isdigit() else None
        found.append(
            EmailRecord(
                email=email,
                first_name=str(item.get("first_name") or ""),
                last_name=str(item.get("last_name") or ""),
                position=str(item.get("position") or item.get("job_title") or ""),
                department=str(item.get("department") or ""),
                type=str(item.get("type") or ""),
                confidence=confidence,
                phone=_phone(item),
                linkedin=_linkedin(item),
                seniority=str(item.get("seniority") or ""),
                source="tomba",
            )
        )
        if len(found) >= cap:
            break
    return found


async def _search(
    client: httpx.AsyncClient,
    settings: Settings,
    domain: str,
    *,
    limit: int,
    department: str,
) -> tuple[httpx.Response, bool]:
    headers = client_headers(
        settings,
        {
            "X-Tomba-Key": settings.tomba_api_key or "",
            "X-Tomba-Secret": settings.tomba_secret or "",
        },
    )
    params: dict[str, str | int] = {"domain": domain, "limit": limit}
    if department:
        params["department"] = department
    response = await get_with_retry(client, URL, params=params, headers=headers)
    free_capped = False
    if response.status_code == 400 and limit > FREE_LIMIT:
        free_capped = True
        params["limit"] = FREE_LIMIT
        response = await get_with_retry(client, URL, params=params, headers=headers)
    return response, free_capped


def _redact(body: str, settings: Settings) -> str:
    text = body
    for key in (settings.tomba_api_key, settings.tomba_secret):
        if key and key in text:
            text = text.replace(key, "<redacted>")
    return text


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_tomba:
        return skipped("tomba", "TOMBA_API_KEY or TOMBA_SECRET not set", started)
    cap = min(settings.hunter_max_emails, PAID_LIMIT)
    collected: list[EmailRecord] = []
    free_capped = False
    try:
        for department in PREFERRED:
            if len(collected) >= cap or free_capped:
                break
            response, hit_free = await _search(
                client,
                settings,
                domain,
                limit=PAID_LIMIT,
                department=department,
            )
            if hit_free:
                free_capped = True
            if response.status_code >= 400:
                body = _redact(response.text[:200], settings)
                raise RuntimeError(f"Tomba HTTP {response.status_code}: {body}")
            collected.extend(_emails(response.json(), domain, cap=cap))
            collected = merge_email_records(collected, cap=cap)
    except Exception as exc:  # noqa: BLE001
        return failed("tomba", str(exc), started)
    return CollectorResult(
        name="tomba",
        status="ok",
        records=len(collected),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=collected,
    )
