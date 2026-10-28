"""Match collected services against the CISA KEV catalog (intelligence only)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from osint_hub.models import Bundle, HotCveMatch, InternetService

FINGERPRINT_WINDOW_DAYS = 90
MAX_FINGERPRINT_PER_SERVICE = 3
MAX_FINGERPRINT_TOTAL = 25
GENERIC_TOKENS = {
    "linux",
    "windows",
    "apache",
    "httpd",
    "http",
    "https",
    "ssl",
    "tls",
    "tcp",
    "udp",
    "server",
    "software",
    "system",
    "kernel",
    "open",
    "source",
    "microsoft",
    "apple",
    "google",
    "oracle",
    "ibm",
    "gnu",
    "web",
    "network",
    "multiple",
    "products",
    "product",
    "unknown",
}
GENERIC_PRODUCTS = {
    "php",
    "openssl",
    "openssh",
    "nginx",
    "apache",
    "httpd",
    "mysql",
    "mariadb",
    "postgresql",
    "postgres",
    "wordpress",
    "iis",
    "tomcat",
    "node",
    "nodejs",
    "python",
    "java",
    "ssh",
    "ftp",
    "smtp",
    "imap",
    "pop3",
    "dns",
    "bind",
    "chrome",
    "chromium",
}
SHORT_OK = {"php"}
TOKEN_RE = re.compile(r"[a-z0-9]+")


def _parse_added(value: str) -> datetime | None:
    text = (value or "").strip()[:10]
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _tokens(*parts: str) -> list[str]:
    found: list[str] = []
    for part in parts:
        for token in TOKEN_RE.findall(part.lower()):
            if token in GENERIC_TOKENS:
                continue
            if len(token) < 4 and token not in SHORT_OK:
                continue
            if token not in found:
                found.append(token)
    return found


def _whole_word(token: str, text: str) -> bool:
    if not token or not text:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", text.lower()) is not None


def _product_haystack(service: InternetService) -> str:
    return " ".join(
        part
        for part in (
            service.product,
            service.version,
            service.service,
            service.http_title or "",
            service.banner or "",
            service.info,
            " ".join(service.cpe),
            " ".join(service.http_components),
        )
        if part
    ).lower()


def _catalog_by_cve(kev: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in kev:
        cve = (row.get("cve_id") or "").upper()
        if cve.startswith("CVE-"):
            out[cve] = row
    return out


def _fingerprint_hit(row: dict[str, str], hay: str) -> bool:
    product_tokens = _tokens(row.get("product") or "")
    vendor_tokens = _tokens(row.get("vendor") or "")
    distinctive = [token for token in product_tokens if token not in GENERIC_PRODUCTS]
    if not distinctive:
        return False
    if not all(_whole_word(token, hay) for token in distinctive):
        return False
    if vendor_tokens and not all(_whole_word(token, hay) for token in vendor_tokens):
        return False
    return True


def match_hot_cves(bundle: Bundle, kev: list[dict[str, str]]) -> list[HotCveMatch]:
    catalog = _catalog_by_cve(kev)
    if not catalog:
        return []

    matches: list[HotCveMatch] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        row: dict[str, str],
        source: str,
        matched_service: str,
        *,
        confidence: str,
        evidence: str,
    ) -> bool:
        key = (row["cve_id"], source, matched_service)
        if key in seen:
            return False
        seen.add(key)
        matches.append(
            HotCveMatch(
                cve_id=row["cve_id"],
                vendor=row.get("vendor") or "",
                product=row.get("product") or "",
                name=row.get("name") or "",
                date_added=row.get("date_added") or "",
                source=source,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                evidence=evidence,
                matched_service=matched_service,
                required_action=row.get("required_action") or "",
                short_description=row.get("short_description") or "",
                known_ransomware=row.get("known_ransomware") or "",
            )
        )
        return True

    for host in bundle.hosts:
        if not host.in_scope:
            continue
        for cve in host.vulns:
            row = catalog.get(cve.upper())
            if row:
                add(
                    row,
                    "shodan",
                    host.entity_id,
                    confidence="confirmed",
                    evidence=f"Shodan CVE tag on attributed host {host.ip}",
                )
        for service in host.services:
            if not service.in_scope:
                continue
            for cve in service.vulns:
                row = catalog.get(cve.upper())
                if row:
                    add(
                        row,
                        "shodan",
                        service.entity_id,
                        confidence="confirmed",
                        evidence=f"Shodan CVE tag on {service.ip}:{service.port}",
                    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=FINGERPRINT_WINDOW_DAYS)
    recent = [
        row
        for row in kev
        if (added := _parse_added(row.get("date_added") or "")) is not None and added >= cutoff
    ]
    fingerprint_total = 0
    for host in bundle.hosts:
        if not host.in_scope:
            continue
        for service in host.services:
            if not service.in_scope:
                continue
            hay = _product_haystack(service)
            if not hay.strip():
                continue
            per_service = 0
            for row in recent:
                if not _fingerprint_hit(row, hay):
                    continue
                product = row.get("product") or "product"
                evidence = (
                    f"Whole-word {product} fingerprint on {service.ip}:{service.port}"
                    + (f" ({service.product} {service.version})".rstrip() if service.product else "")
                )
                if add(
                    row,
                    "fingerprint",
                    service.entity_id,
                    confidence="suspected",
                    evidence=evidence,
                ):
                    per_service += 1
                    fingerprint_total += 1
                if per_service >= MAX_FINGERPRINT_PER_SERVICE or fingerprint_total >= MAX_FINGERPRINT_TOTAL:
                    break
            if fingerprint_total >= MAX_FINGERPRINT_TOTAL:
                break
        if fingerprint_total >= MAX_FINGERPRINT_TOTAL:
            break

    return matches
