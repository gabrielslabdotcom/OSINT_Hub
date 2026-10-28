"""Compile a high-value ops dossier from a run's evidence. Intelligence only — no PoCs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from osint_hub.correlate import EXPOSURE_PATTERNS, HIGH_VALUE_PORTS, _haystack, _phrase_in
from osint_hub.models import (
    Bundle,
    Correlation,
    Host,
    HotCveMatch,
    InternetService,
    Phase2Dossier,
    Phase2Link,
    Phase2MailPosture,
    Phase2Person,
    Phase2Service,
    Phase2Task,
)
from osint_hub.people import email_priority
from osint_hub.util import dump_model, iso_now, read_json, write_json

NVD = "https://nvd.nist.gov/vuln/detail/{cve}"
KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _location(host: Host) -> str:
    return ", ".join(part for part in (host.city, host.country) if part)


def _exposure_label(service: InternetService) -> str:
    hay = _haystack(service)
    for needle, label in EXPOSURE_PATTERNS:
        if _phrase_in(needle, hay):
            return label
    return HIGH_VALUE_PORTS.get(service.port, "")


def _mail_posture(bundle: Bundle) -> Phase2MailPosture:
    txts = [r for r in bundle.dns_records if r.rtype == "TXT"]
    spf = [r for r in txts if r.value.lower().startswith("v=spf1")]
    dmarc = [r for r in txts if "v=dmarc1" in r.value.lower()]
    providers: list[str] = []
    for record in spf:
        lower = record.value.lower()
        if "spf.protection.outlook.com" in lower:
            providers.append("Microsoft 365")
        if "_spf.google.com" in lower:
            providers.append("Google Workspace")
        if "include:" in lower:
            providers.extend(re.findall(r"include:([^\s]+)", lower)[:6])
    policy = "missing"
    for record in dmarc:
        match = re.search(r"\bp=([a-z]+)", record.value.lower())
        if match:
            policy = match.group(1)
            break
    spoofable = policy in {"none", "missing"}
    if spoofable:
        note = "DMARC p=none or missing does not reject spoofed mail. Harden to p=quarantine/reject; this is not a remote exploit."
    else:
        note = f"DMARC policy is p={policy}."
    return Phase2MailPosture(
        spf=bool(spf),
        dmarc_policy=policy,
        spoofable=spoofable,
        providers=list(dict.fromkeys(providers)),
        note=note,
        mailbox_count=len(bundle.emails),
    )


def _people(bundle: Bundle, mail: Phase2MailPosture) -> list[Phase2Person]:
    if not bundle.emails:
        return []
    breaches_by_email: dict[str, list[str]] = {}
    for row in bundle.breaches:
        breaches_by_email.setdefault(row.email.lower(), []).append(row.name)
    people: list[Phase2Person] = []
    for row in bundle.emails:
        role_score, role_why = email_priority(row)
        hits = breaches_by_email.get(row.email.lower(), [])
        score = role_score + (3 if hits else 0) + (1 if row.phone else 0)
        reasons = [role_why]
        if hits:
            reasons.append("HIBP breach membership — credential-reuse risk on in-scope portals")
        if mail.spoofable:
            reasons.append("mail auth does not reject spoofing")
        name = " ".join(part for part in (row.first_name, row.last_name) if part)
        people.append(
            Phase2Person(
                rank=score,
                full_name=name or row.email,
                first_name=row.first_name,
                last_name=row.last_name,
                email=row.email,
                phone=row.phone,
                linkedin=row.linkedin,
                position=row.position,
                department=row.department,
                seniority=row.seniority,
                type=row.type,
                source=row.source,
                confidence=row.confidence,
                why="; ".join(reasons),
                breaches=hits,
                entity_ids=[row.entity_id],
            )
        )
    people.sort(key=lambda item: (-item.rank, item.email))
    for index, person in enumerate(people, 1):
        person.rank = index
    return people


def _kev_for(host: Host, service: InternetService, hits: list[HotCveMatch]) -> list[HotCveMatch]:
    matched: list[HotCveMatch] = []
    seen: set[str] = set()
    keys = {service.entity_id, host.entity_id, *service.vulns, *host.vulns}
    for hit in hits:
        if hit.matched_service in {service.entity_id, host.entity_id} or hit.cve_id in keys:
            if hit.cve_id in seen:
                continue
            seen.add(hit.cve_id)
            matched.append(hit)
    return matched


def _analysis_paths(run_dir: Path) -> list[dict[str, Any]]:
    for name in ("analysis_claude.json", "analysis_local.json"):
        path = run_dir / name
        if not path.is_file():
            continue
        payload = read_json(path)
        if isinstance(payload, dict):
            return list(payload.get("exploitation_paths") or [])
    return []


def _path_for(service: InternetService, host: Host, paths: list[dict[str, Any]]) -> dict[str, Any] | None:
    needle = {service.entity_id, host.entity_id, f"{service.ip}:{service.port}"}
    for path in paths:
        ids = {str(item) for item in (path.get("entity_ids") or [])}
        finding = str(path.get("finding") or "").lower()
        if ids & needle:
            return path
        if service.ip in finding and str(service.port) in finding:
            return path
        product = (service.product or service.service or "").lower()
        if product and product in finding:
            return path
    return None


def _service_cards(bundle: Bundle, run_dir: Path) -> list[Phase2Service]:
    paths = _analysis_paths(run_dir)
    cards: list[Phase2Service] = []
    for host in bundle.hosts:
        if not host.in_scope:
            continue
        for service in host.services:
            if not service.in_scope:
                continue
            kev_hits = _kev_for(host, service, bundle.hot_cves)
            confirmed = [hit for hit in kev_hits if hit.confidence == "confirmed"]
            suspected = [hit for hit in kev_hits if hit.confidence != "confirmed"]
            shodan_cves = list(dict.fromkeys([*service.vulns, *host.vulns]))
            non_kev = [cve for cve in shodan_cves if cve not in {hit.cve_id for hit in kev_hits}]
            exposure = _exposure_label(service)
            tls = service.ssl_expired or service.ssl_self_signed
            if confirmed:
                category, score = "kev_confirmed", 100
            elif non_kev:
                category, score = "shodan_cve", 80
            elif exposure:
                category, score = "high_value", 60
            elif tls:
                category, score = "tls", 40
            elif suspected:
                category, score = "kev_suspected", 30
            else:
                continue
            path = _path_for(service, host, paths)
            tasks = [
                "Confirm the indexed product and version still match this host.",
                "Confirm the port is still internet-reachable from an authorized vantage point.",
                "Confirm whether authentication or VPN is required before treating this as exposed.",
            ]
            if confirmed:
                action = confirmed[0].required_action or "Apply the vendor/CISA required action for this KEV item."
                tasks.append(action)
            elif tls:
                tasks.append("Replace expired or self-signed certificates with a valid in-scope chain.")
            evidence_bits = [
                service.http_title or "",
                service.banner or "",
                exposure,
                f"tags={','.join(host.tags[:6])}" if host.tags else "",
            ]
            cards.append(
                Phase2Service(
                    rank=score,
                    category=category,
                    ip=service.ip,
                    port=service.port,
                    transport=service.transport or "tcp",
                    product=service.product or service.service,
                    version=service.version,
                    hostnames=service.hostnames or host.hostnames,
                    title=service.http_title or "",
                    server=service.http_server,
                    components=service.http_components,
                    cpe=service.cpe,
                    tags=host.tags,
                    last_seen=host.last_update,
                    location=_location(host),
                    cves=shodan_cves,
                    kev=[
                        {
                            "cve_id": hit.cve_id,
                            "name": hit.name,
                            "required_action": hit.required_action,
                            "short_description": hit.short_description,
                            "confidence": hit.confidence,
                        }
                        for hit in kev_hits
                    ],
                    ssl_expired=service.ssl_expired,
                    ssl_self_signed=service.ssl_self_signed,
                    tls_versions=service.tls_versions,
                    evidence=" · ".join(part for part in evidence_bits if part)[:400],
                    entity_ids=[service.entity_id, host.entity_id],
                    defender_check=str((path or {}).get("defender_check") or ""),
                    sequence=[str(step) for step in ((path or {}).get("sequence") or []) if step],
                    tasks=tasks,
                )
            )
    cards.sort(key=lambda item: (-item.rank, item.ip, item.port))
    for index, card in enumerate(cards, 1):
        card.rank = index
    return cards[:40]


def _links_for_service(card: Phase2Service) -> list[Phase2Link]:
    links: list[Phase2Link] = []
    seen: set[str] = set()
    for row in card.kev:
        cve = row.get("cve_id") or ""
        if cve and cve not in seen:
            links.append(Phase2Link(label=cve, url=NVD.format(cve=cve)))
            seen.add(cve)
    for cve in card.cves:
        if cve not in seen:
            links.append(Phase2Link(label=cve, url=NVD.format(cve=cve)))
            seen.add(cve)
    if card.kev:
        links.append(Phase2Link(label="CISA KEV catalog", url=KEV_CATALOG))
    return links


def _tasks(
    bundle: Bundle,
    mail: Phase2MailPosture,
    services: list[Phase2Service],
    people: list[Phase2Person],
) -> list[Phase2Task]:
    tasks: list[Phase2Task] = []
    priority = 1
    if mail.spoofable:
        tasks.append(
            Phase2Task(
                id="mail:dmarc",
                kind="mail_auth",
                title="Harden DMARC for spoofed-mail rejection",
                why=mail.note,
                entity_ids=[],
                next_action="Publish DMARC p=quarantine then p=reject; keep SPF aligned.",
                steps=[
                    "Confirm current SPF and DMARC TXT on the apex.",
                    "Move DMARC from p=none/missing to p=quarantine, then p=reject.",
                    "Enable MFA on mail and VPN/OWA portals that accept these identities.",
                ],
                priority=priority,
            )
        )
        priority += 1
    for card in services[:12]:
        cve_bit = card.kev[0]["cve_id"] if card.kev else (card.cves[0] if card.cves else card.product)
        tasks.append(
            Phase2Task(
                id=f"svc:{card.entity_ids[0]}:{card.category}",
                kind="service_verify",
                title=f"Verify {card.ip}:{card.port} ({card.product or 'service'})",
                why=f"{card.category.replace('_', ' ')} — {cve_bit}",
                entity_ids=card.entity_ids,
                next_action=card.tasks[0] if card.tasks else "Confirm exposure and patch status.",
                steps=card.tasks,
                links=_links_for_service(card),
                priority=priority,
            )
        )
        priority += 1
    for person in people[:8]:
        steps = [
            "Confirm this identity is in-scope for the authorized assessment.",
            "Check whether the mailbox is still active and whether MFA is required on related portals.",
        ]
        if person.breaches:
            steps.append("Treat HIBP membership as credential-reuse risk — do not replay passwords; notify the owner.")
        if mail.spoofable:
            steps.append("Prioritize mail-auth hardening so this identity cannot be trivially spoofed.")
        tasks.append(
            Phase2Task(
                id=f"person:{person.email}",
                kind="identity_review",
                title=f"Review identity {person.full_name}",
                why=person.why,
                entity_ids=person.entity_ids,
                next_action=steps[0],
                steps=steps,
                priority=priority,
            )
        )
        priority += 1
    if bundle.github_findings:
        tasks.append(
            Phase2Task(
                id="github:review",
                kind="github",
                title="Review GitHub code-search hits for secrets or internal hostnames",
                why=f"{len(bundle.github_findings)} in-repo mention(s) of the domain.",
                entity_ids=[row.entity_id for row in bundle.github_findings[:8]],
                next_action="Open each hit and confirm whether credentials or internal names leaked.",
                steps=[
                    "Open the listed files and confirm the match is still public.",
                    "Rotate any live credentials; do not paste secrets into this console.",
                ],
                priority=priority,
            )
        )
    return tasks


def _preserve_status(run_dir: Path, dossier: Phase2Dossier) -> None:
    path = run_dir / "phase2.json"
    if not path.is_file():
        return
    try:
        previous = read_json(path)
    except (OSError, ValueError):
        return
    rows = previous.get("tasks") if isinstance(previous, dict) else None
    if not isinstance(rows, list):
        return
    done = {str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("status") == "done"}
    for task in dossier.tasks:
        if task.id in done:
            task.status = "done"


def compile_phase2(bundle: Bundle, run_dir: Path, correlations: list[Correlation] | None = None) -> Phase2Dossier:
    del correlations
    mail = _mail_posture(bundle)
    services = _service_cards(bundle, run_dir)
    people = _people(bundle, mail)
    if not mail.spoofable and not people:
        people = []
    dossier = Phase2Dossier(
        domain=bundle.domain,
        generated_at=iso_now(),
        mail_posture=mail,
        services=services,
        people=people,
        tasks=_tasks(bundle, mail, services, people),
    )
    _preserve_status(run_dir, dossier)
    return dossier


def write_phase2(
    run_dir: Path,
    bundle: Bundle,
    correlations: list[Correlation] | None = None,
) -> Path:
    dossier = compile_phase2(bundle, run_dir, correlations)
    path = run_dir / "phase2.json"
    write_json(path, dump_model(dossier))
    return path


def patch_task(run_dir: Path, task_id: str, status: str) -> Phase2Dossier:
    if status not in {"open", "done"}:
        raise ValueError(f"Invalid task status: {status}")
    path = run_dir / "phase2.json"
    if not path.is_file():
        raise FileNotFoundError("phase2.json not found — generate a report first")
    payload = read_json(path)
    dossier = Phase2Dossier.model_validate(payload)
    found = False
    for task in dossier.tasks:
        if task.id == task_id:
            task.status = status  # type: ignore[assignment]
            found = True
            break
    if not found:
        raise FileNotFoundError(f"Task not found: {task_id}")
    write_json(path, dump_model(dossier))
    return dossier
