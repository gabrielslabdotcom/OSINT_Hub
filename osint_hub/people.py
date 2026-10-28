"""Merge mailbox records from Hunter / Tomba into a single EmailRecord list."""

from __future__ import annotations

from osint_hub.models import EmailRecord

COMBINED_CAP = 25
ROLE_EXEC = (
    "ceo",
    "cfo",
    "cto",
    "ciso",
    "coo",
    "president",
    "founder",
    "owner",
    "director",
    "vp",
    "vice president",
    "executive",
    "chief",
)
ROLE_IT = (
    "it",
    "information technology",
    "sysadmin",
    "administrator",
    "security",
    "engineer",
    "devops",
    "sre",
    "infrastructure",
    "network",
)
ROLE_FINANCE = ("finance", "accounting", "payroll", "treasurer", "controller", "accounts")


def _fill(current: EmailRecord, incoming: EmailRecord) -> None:
    if incoming.first_name and not current.first_name:
        current.first_name = incoming.first_name
    if incoming.last_name and not current.last_name:
        current.last_name = incoming.last_name
    if incoming.position and not current.position:
        current.position = incoming.position
    if incoming.department and not current.department:
        current.department = incoming.department
    if incoming.type and not current.type:
        current.type = incoming.type
    if incoming.phone and not current.phone:
        current.phone = incoming.phone
    if incoming.linkedin and not current.linkedin:
        current.linkedin = incoming.linkedin
    if incoming.seniority and not current.seniority:
        current.seniority = incoming.seniority
    if incoming.confidence is not None and current.confidence is None:
        current.confidence = incoming.confidence
    sources = {part for part in (current.source, incoming.source) if part}
    if len(sources) > 1:
        current.source = "merged"
    elif sources and not current.source:
        current.source = next(iter(sources))


def merge_email_records(*groups: list[EmailRecord], cap: int = COMBINED_CAP) -> list[EmailRecord]:
    by_email: dict[str, EmailRecord] = {}
    for group in groups:
        for row in group:
            key = row.email.strip().lower()
            if not key:
                continue
            existing = by_email.get(key)
            if existing is None:
                by_email[key] = row
            else:
                _fill(existing, row)
    return list(by_email.values())[:cap]


def email_priority(row: EmailRecord) -> tuple[int, str]:
    blob = " ".join(
        part.lower()
        for part in (row.position, row.department, row.seniority, row.type)
        if part
    )
    if row.seniority.lower() in {"executive", "director"} or any(token in blob for token in ROLE_EXEC):
        return 5, "executive / leadership title"
    if any(token in blob for token in ROLE_IT) or row.department.lower() in {"it", "engineering"}:
        return 4, "IT / security / engineering role"
    if any(token in blob for token in ROLE_FINANCE) or row.department.lower() in {"finance", "accounting"}:
        return 3, "finance / payroll role"
    if row.type.lower() == "personal":
        return 1, "named mailbox"
    return 0, "published mailbox"


def candidates_missing_phone(emails: list[EmailRecord], *, limit: int) -> list[EmailRecord]:
    missing = [row for row in emails if not (row.phone or "").strip()]
    missing.sort(key=lambda row: (-email_priority(row)[0], row.email.lower()))
    return missing[: max(limit, 0)]
