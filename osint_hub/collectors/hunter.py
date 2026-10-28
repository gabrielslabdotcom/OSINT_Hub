"""Hunter domain-search for mailboxes. Requires HUNTER_API_KEY. No person-name search."""

from __future__ import annotations

import time
from typing import Any

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, EmailRecord
from osint_hub.people import merge_email_records

URL = "https://api.hunter.io/v2/domain-search"
FREE_LIMIT = 10
PREFERRED: tuple[dict[str, str], ...] = (
    {"department": "executive"},
    {"department": "it"},
    {"department": "finance"},
    {},
)
PHONE_PREFERRED: tuple[dict[str, str], ...] = (
    {"department": "executive", "required_field": "phone_number"},
    {"department": "it", "required_field": "phone_number"},
    {"department": "finance", "required_field": "phone_number"},
    {"required_field": "phone_number"},
)


def _phone(item: dict[str, Any]) -> str:
    value = item.get("phone_number") or item.get("phone") or ""
    if isinstance(value, dict):
        value = value.get("number") or value.get("value") or ""
    return str(value or "").strip()


def _linkedin(item: dict[str, Any]) -> str:
    value = item.get("linkedin") or item.get("linkedin_url") or ""
    return str(value or "").strip()


def _emails(payload: object, domain: str, *, cap: int) -> list[EmailRecord]:
    data = payload.get("data") if isinstance(payload, dict) else None
    rows = (data or {}).get("emails") if isinstance(data, dict) else []
    found: list[EmailRecord] = []
    suffix = "@" + domain
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        email = str(item.get("value") or "").strip().lower()
        if not email.endswith(suffix):
            continue
        found.append(
            EmailRecord(
                email=email,
                first_name=str(item.get("first_name") or ""),
                last_name=str(item.get("last_name") or ""),
                position=str(item.get("position") or ""),
                department=str(item.get("department") or ""),
                type=str(item.get("type") or ""),
                confidence=int(item["confidence"]) if str(item.get("confidence") or "").isdigit() else None,
                phone=_phone(item),
                linkedin=_linkedin(item),
                seniority=str(item.get("seniority") or ""),
                source="hunter",
            )
        )
        if len(found) >= cap:
            break
    return found


def _redact(body: str, key: str) -> str:
    if key and key in body:
        return body.replace(key, "<redacted>")
    return body


async def _search(
    client: httpx.AsyncClient,
    settings: Settings,
    domain: str,
    *,
    limit: int,
    extra: dict[str, str],
) -> tuple[httpx.Response, bool]:
    headers = client_headers(settings)
    params: dict[str, str | int] = {
        "domain": domain,
        "limit": limit,
        "api_key": settings.hunter_api_key or "",
        **extra,
    }
    response = await get_with_retry(client, URL, params=params, headers=headers)
    free_capped = False
    if response.status_code == 400 and "pagination_error" in response.text and limit > FREE_LIMIT:
        free_capped = True
        params["limit"] = FREE_LIMIT
        response = await get_with_retry(client, URL, params=params, headers=headers)
    return response, free_capped


async def _passes(
    client: httpx.AsyncClient,
    settings: Settings,
    domain: str,
    extras: tuple[dict[str, str], ...],
    collected: list[EmailRecord],
    *,
    cap: int,
    free_capped: bool,
    stop_when_full: bool,
    abort_on_http_error: bool,
) -> tuple[list[EmailRecord], bool]:
    for extra in extras:
        if stop_when_full and (len(collected) >= cap or free_capped):
            break
        remaining = cap - len(collected)
        if stop_when_full:
            limit = min(cap, max(remaining, 1))
        else:
            limit = cap
        if free_capped:
            limit = min(limit, FREE_LIMIT)
        response, hit_free = await _search(
            client,
            settings,
            domain,
            limit=limit,
            extra=extra,
        )
        if hit_free:
            free_capped = True
        if response.status_code >= 400:
            if abort_on_http_error:
                body = _redact(response.text[:200], settings.hunter_api_key or "")
                raise RuntimeError(f"Hunter HTTP {response.status_code}: {body}")
            break
        collected.extend(_emails(response.json(), domain, cap=cap))
        collected = merge_email_records(collected, cap=cap)
    return collected, free_capped


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_hunter:
        return skipped("hunter", "HUNTER_API_KEY not set", started)
    cap = settings.hunter_max_emails
    collected: list[EmailRecord] = []
    free_capped = False
    try:
        collected, free_capped = await _passes(
            client,
            settings,
            domain,
            PREFERRED,
            collected,
            cap=cap,
            free_capped=free_capped,
            stop_when_full=True,
            abort_on_http_error=True,
        )
        collected, _ = await _passes(
            client,
            settings,
            domain,
            PHONE_PREFERRED,
            collected,
            cap=cap,
            free_capped=free_capped,
            stop_when_full=False,
            abort_on_http_error=False,
        )
    except Exception as exc:  # noqa: BLE001
        return failed("hunter", str(exc), started)
    return CollectorResult(
        name="hunter",
        status="ok",
        records=len(collected),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=collected,
    )
