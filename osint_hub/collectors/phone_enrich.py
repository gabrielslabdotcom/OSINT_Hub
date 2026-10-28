"""Fill missing mailbox phones via Tomba phone-finder, else Hunter people/find."""

from __future__ import annotations

import time
from typing import Any

import httpx

from osint_hub.collectors.base import client_headers, failed, get_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, EmailRecord
from osint_hub.people import candidates_missing_phone

TOMBA_URL = "https://api.tomba.io/v1/phone-finder"
HUNTER_URL = "https://api.hunter.io/v2/people/find"


def _as_phone(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("number") or value.get("value") or value.get("intl_format") or ""
    text = str(value or "").strip()
    if text.lower() in {"", "true", "false", "none", "null"}:
        return ""
    return text


def _phone_from_mapping(item: dict[str, Any]) -> str:
    for key in ("intl_format", "e164_format", "phone_number", "phone", "local_format", "number"):
        phone = _as_phone(item.get(key))
        if phone:
            return phone
    phone_data = item.get("phone_data")
    if isinstance(phone_data, list):
        for entry in phone_data:
            if isinstance(entry, dict):
                phone = _phone_from_mapping(entry)
            else:
                phone = _as_phone(entry)
            if phone:
                return phone
    return ""


def _tomba_phone(payload: object) -> str:
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                phone = _phone_from_mapping(item)
                if phone:
                    return phone
        return ""
    if isinstance(data, dict):
        return _phone_from_mapping(data)
    return ""


def _hunter_phone(payload: object) -> str:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return ""
    return _phone_from_mapping(data)


def _redact(body: str, settings: Settings) -> str:
    text = body
    for key in (settings.tomba_api_key, settings.tomba_secret, settings.hunter_api_key):
        if key and key in text:
            text = text.replace(key, "<redacted>")
    return text


def _apply_phone(row: EmailRecord, phone: str, provider: str) -> None:
    row.phone = phone
    if row.source and row.source not in {provider, "merged"}:
        row.source = "merged"


async def _tomba_lookup(
    client: httpx.AsyncClient,
    settings: Settings,
    email: str,
) -> str:
    headers = client_headers(
        settings,
        {
            "X-Tomba-Key": settings.tomba_api_key or "",
            "X-Tomba-Secret": settings.tomba_secret or "",
        },
    )
    response = await get_with_retry(client, TOMBA_URL, params={"email": email}, headers=headers)
    if response.status_code in {400, 404, 422, 451}:
        return ""
    if response.status_code >= 400:
        body = _redact(response.text[:200], settings)
        raise RuntimeError(f"Tomba phone-finder HTTP {response.status_code}: {body}")
    return _tomba_phone(response.json())


async def _hunter_lookup(
    client: httpx.AsyncClient,
    settings: Settings,
    email: str,
) -> str:
    headers = client_headers(settings)
    params = {"email": email, "api_key": settings.hunter_api_key or ""}
    response = await get_with_retry(client, HUNTER_URL, params=params, headers=headers)
    if response.status_code in {400, 404, 422, 451}:
        return ""
    if response.status_code >= 400:
        body = _redact(response.text[:200], settings)
        raise RuntimeError(f"Hunter people/find HTTP {response.status_code}: {body}")
    return _hunter_phone(response.json())


async def collect(
    emails: list[EmailRecord],
    settings: Settings,
    client: httpx.AsyncClient,
) -> CollectorResult:
    started = time.perf_counter()
    if settings.people_phone_enrich_max <= 0:
        return skipped("phone_enrich", "PEOPLE_PHONE_ENRICH_MAX=0", started)
    if not settings.has_tomba and not settings.has_hunter:
        return skipped("phone_enrich", "TOMBA or HUNTER keys not set", started)
    if not emails:
        return skipped("phone_enrich", "no mailboxes to enrich", started)
    candidates = candidates_missing_phone(emails, limit=settings.people_phone_enrich_max)
    if not candidates:
        return CollectorResult(
            name="phone_enrich",
            status="ok",
            records=0,
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=[],
        )
    use_tomba = settings.has_tomba
    filled: list[dict[str, str]] = []
    try:
        for row in candidates:
            provider = "tomba" if use_tomba else "hunter"
            if use_tomba:
                phone = await _tomba_lookup(client, settings, row.email)
            else:
                phone = await _hunter_lookup(client, settings, row.email)
            if not phone:
                continue
            _apply_phone(row, phone, provider)
            filled.append({"email": row.email, "phone": phone, "source": provider})
    except Exception as exc:  # noqa: BLE001
        if filled:
            return CollectorResult(
                name="phone_enrich",
                status="ok",
                records=len(filled),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
                data=filled,
            )
        return failed("phone_enrich", str(exc), started)
    return CollectorResult(
        name="phone_enrich",
        status="ok",
        records=len(filled),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=filled,
    )
