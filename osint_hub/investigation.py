"""Validate investigation requests and derive people seeds."""

from __future__ import annotations

import re
from typing import Any

from osint_hub.models import EmailRecord, InvestigationRequest, ScanDepth
from osint_hub.util import normalize_domain

EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", re.IGNORECASE)
USERNAME_RE = re.compile(r"^[a-z0-9._\-]{2,64}$", re.IGNORECASE)
LOCAL_PART_RE = re.compile(r"^[a-z0-9._\-]{2,64}$", re.IGNORECASE)


def normalize_email(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value or not EMAIL_RE.fullmatch(value):
        raise ValueError(f"Invalid email: {raw!r}")
    return value


def normalize_username(raw: str) -> str:
    value = (raw or "").strip().lstrip("@").lower()
    if not value or not USERNAME_RE.fullmatch(value):
        raise ValueError(f"Invalid username: {raw!r}")
    return value


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def validate_investigation_request(
    *,
    mode: str = "domain",
    domain: str | None = None,
    emails: list[str] | None = None,
    usernames: list[str] | None = None,
    scan_depth: ScanDepth = "standard",
    allow_loud: bool = False,
    max_emails: int = 10,
    max_usernames: int = 10,
) -> InvestigationRequest:
    if mode not in {"domain", "people", "both"}:
        raise ValueError("mode must be domain, people, or both")
    if scan_depth not in {"quick", "standard", "full"}:
        raise ValueError("scan_depth must be quick, standard, or full")

    normalized_domain: str | None = None
    if domain and str(domain).strip():
        normalized_domain = normalize_domain(domain)

    email_list = _unique([normalize_email(item) for item in (emails or []) if str(item).strip()])
    username_list = _unique(
        [normalize_username(item) for item in (usernames or []) if str(item).strip()]
    )

    if mode in {"domain", "both"} and not normalized_domain:
        raise ValueError("domain is required for domain and both modes")
    if mode == "domain":
        email_list = []
        username_list = []
    if mode == "people" and not email_list and not username_list:
        raise ValueError("people mode requires at least one email or username")
    if mode == "both" and not normalized_domain:
        raise ValueError("both mode requires a domain")

    if len(email_list) > max_emails:
        email_list = email_list[:max_emails]
    if len(username_list) > max_usernames:
        username_list = username_list[:max_usernames]

    return InvestigationRequest(
        mode=mode,  # type: ignore[arg-type]
        domain=normalized_domain,
        emails=email_list,
        usernames=username_list,
        scan_depth=scan_depth,
        allow_loud=bool(allow_loud),
    )


def target_label_for(request: InvestigationRequest) -> str:
    if request.mode == "people":
        if request.domain:
            return f"people@{request.domain}"
        return "people"
    return request.domain or "unknown"


def run_slug_for(request: InvestigationRequest) -> str:
    if request.mode == "people":
        return "people"
    return request.domain or "unknown"


def usernames_from_emails(emails: list[EmailRecord] | list[str], *, limit: int) -> list[str]:
    derived: list[str] = []
    for item in emails:
        raw = item.email if isinstance(item, EmailRecord) else str(item)
        local = raw.split("@", 1)[0].strip().lower()
        if not LOCAL_PART_RE.fullmatch(local):
            continue
        if local not in derived:
            derived.append(local)
        if len(derived) >= max(limit, 0):
            break
    return derived


def merge_people_seeds(
    request: InvestigationRequest,
    *,
    mailbox_emails: list[EmailRecord] | None = None,
    max_emails: int = 10,
    max_usernames: int = 10,
) -> dict[str, list[str]]:
    emails = list(request.emails)
    usernames = list(request.usernames)
    if mailbox_emails:
        for row in mailbox_emails:
            value = row.email.strip().lower()
            if value and value not in emails:
                try:
                    emails.append(normalize_email(value))
                except ValueError:
                    continue
        derived = usernames_from_emails(mailbox_emails, limit=max_usernames)
        for name in derived:
            if name not in usernames:
                usernames.append(name)
    return {
        "emails": emails[:max_emails],
        "usernames": usernames[:max_usernames],
    }


def request_summary(request: InvestigationRequest) -> dict[str, Any]:
    return {
        "mode": request.mode,
        "domain": request.domain,
        "target_label": target_label_for(request),
        "scan_depth": request.scan_depth,
        "email_seed_count": len(request.emails),
        "username_seed_count": len(request.usernames),
        "allow_loud": request.allow_loud,
    }
