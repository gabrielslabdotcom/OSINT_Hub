"""Consolidate a bundle + correlations into markdown (lab Step 2 shape)."""

from __future__ import annotations

from pathlib import Path

from osint_hub.correlate import correlate, extra_txt_hints
from osint_hub.models import Bundle, Correlation, HotCveMatch
from osint_hub.util import dump_model, write_json


def _plain(value: object, *, limit: int = 400) -> str:
    """Neutralize HTML/markdown metacharacters in collector-controlled strings."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("`", "'").replace("[", "(").replace("]", ")")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _one_line(value: object, *, limit: int = 400) -> str:
    return " ".join(_plain(value, limit=limit).split())


def _append_hot_cve(sections: list[str], hit: HotCveMatch) -> None:
    product = " ".join(part for part in (hit.vendor, hit.product) if part).strip() or "unknown product"
    sections.append(
        f"  {_one_line(hit.cve_id)}  {_one_line(product)}  added {_one_line(hit.date_added or 'unknown')}  "
        f"via {_one_line(hit.source)}  on {_one_line(hit.matched_service)}"
    )
    if hit.name:
        sections.append(f"    {_one_line(hit.name)}")
    if hit.evidence:
        sections.append(f"    Evidence: {_one_line(hit.evidence, limit=600)}")
    if hit.confidence == "confirmed":
        sections.append(
            f"    Known-exploited CVE listed by CISA on {_one_line(hit.date_added or 'an unknown date')}; "
            "confirm patch/exposure on this host."
        )
    else:
        sections.append("    Possible product overlap — confirm version/patch; not a verified CVE on this host.")


def build_report(bundle: Bundle, correlations: list[Correlation] | None = None) -> str:
    correlations = correlations if correlations is not None else correlate(bundle)
    sections: list[str] = [
        f"# OSINT Report: {_one_line(bundle.domain)}",
        f"Target: {_one_line(bundle.domain)}",
        f"Collection Date: {_one_line(bundle.collected_at)}",
        "",
        "## DNS Records",
    ]
    if not bundle.dns_records:
        sections.append("  (none)")
    for record in bundle.dns_records:
        if record.priority is not None:
            sections.append(
                f"  {_one_line(record.rtype)}: {_one_line(record.name)} -> {_one_line(record.value)} "
                f"(priority {record.priority})"
            )
        else:
            sections.append(f"  {_one_line(record.rtype)}: {_one_line(record.name)} -> {_one_line(record.value)}")

    hints = extra_txt_hints(bundle.dns_records)
    if hints:
        sections.append("")
        sections.append("## DNS TXT hints")
        for hint in hints:
            sections.append(f"  - {_one_line(hint, limit=600)}")

    sections.append("")
    sections.append("## Certificate Transparency Logs")
    if not bundle.certificates:
        sections.append("  (none)")
    for cert in bundle.certificates:
        sections.append(
            f"  CN={_one_line(cert.common_name)}  Issuer={_one_line(cert.issuer)}  "
            f"Expires={_one_line(cert.not_after)}"
        )

    sections.append("")
    sections.append("## Discovered hostnames")
    for name in bundle.discovered_hostnames:
        sections.append(f"  - {_one_line(name)}")

    sections.append("")
    sections.append("## GitHub Exposure")
    if not bundle.github_findings:
        sections.append("  (none — collector skipped or no hits)")
    for finding in bundle.github_findings:
        sections.append(f"  Repo: {_one_line(finding.repo)}  File: {_one_line(finding.file)}")
        sections.append(f"  Match: {_plain(finding.match, limit=1200)}")
        sections.append(f"  Author: {_one_line(finding.author or 'N/A')}")
        if finding.url:
            sections.append(f"  URL: {_one_line(finding.url, limit=500)}")
        sections.append("")

    sections.append("## Internet-Facing Services")
    attributed = [host for host in bundle.hosts if host.in_scope and host.services]
    shared = [host for host in bundle.hosts if not host.in_scope or not host.services]
    services = [svc for host in attributed for svc in host.services if svc.in_scope]
    if not services:
        sections.append("  (none attributed to this domain — collector skipped, no hits, or shared/CDN only)")
    for host in attributed:
        org = f"  org={_one_line(host.org)}" if host.org else ""
        asn = f"  asn={_one_line(host.asn)}" if host.asn else ""
        if org or asn:
            sections.append(f"  {_one_line(host.ip)}{org}{asn}")
        for svc in host.services:
            if not svc.in_scope:
                continue
            title = svc.http_title or svc.banner or "N/A"
            sections.append(
                f'  {_one_line(svc.ip)}:{svc.port}  {_one_line(svc.service)}  "{_one_line(title)}"'
            )

    if shared:
        sections.append("")
        sections.append("## Shared / CDN IPs (not attributed)")
        for host in shared:
            org = host.org or "unknown"
            asn = host.asn or "unknown"
            sections.append(f"  {_one_line(host.ip)}  org={_one_line(org)}  asn={_one_line(asn)}")

    confirmed = [hit for hit in bundle.hot_cves if hit.confidence == "confirmed"]
    suspected = [hit for hit in bundle.hot_cves if hit.confidence != "confirmed"]
    sections.append("")
    sections.append("## Hot / known-exploited CVEs")
    if not bundle.hosts:
        sections.append("  Hot CVE matching needs internet-facing service data — set `SHODAN_API_KEY`.")
    elif not bundle.hot_cves:
        sections.append("  (none matched against CISA KEV)")
    else:
        if confirmed:
            sections.append("  Confirmed (Shodan CVE tag ∩ CISA KEV on an attributed host):")
            for hit in confirmed:
                _append_hot_cve(sections, hit)
        if suspected:
            sections.append("  Suspected (product fingerprint only — not a verified CVE on this host):")
            for hit in suspected:
                _append_hot_cve(sections, hit)

    if bundle.emails:
        sections.append("")
        sections.append("## Mailboxes")
        for row in bundle.emails:
            name = " ".join(part for part in (row.first_name, row.last_name) if part)
            extra = " ".join(
                part
                for part in (name, row.position, row.department, row.seniority, row.type, row.source)
                if part
            )
            sections.append(f"  {_one_line(row.email)}" + (f"  {_one_line(extra)}" if extra else ""))
            if row.phone:
                sections.append(f"    phone {_one_line(row.phone)}")
            if row.linkedin:
                sections.append(f"    {_one_line(row.linkedin)}")
    if bundle.breaches:
        sections.append("")
        sections.append("## Breach memberships (HIBP)")
        for row in bundle.breaches:
            sections.append(
                f"  {_one_line(row.email)}  {_one_line(row.name)}"
                + (f"  {_one_line(row.breach_date)}" if row.breach_date else "")
            )
    if bundle.ip_intel:
        sections.append("")
        sections.append("## IP intel")
        for row in bundle.ip_intel:
            bits = [_one_line(row.ip)]
            if row.org:
                bits.append(_one_line(row.org))
            if row.asn:
                bits.append(_one_line(row.asn))
            if row.greynoise_classification:
                bits.append(f"greynoise={_one_line(row.greynoise_classification)}")
            if row.abuse_score is not None:
                bits.append(f"abuse={row.abuse_score}")
            sections.append("  " + "  ".join(bits))
    if bundle.url_scans:
        sections.append("")
        sections.append("## URLScan")
        for row in bundle.url_scans:
            sections.append(
                f'  {_one_line(row.url, limit=500)}  {_one_line(row.ip)}  "{_one_line(row.title or "N/A")}"'
            )
    if bundle.leaks:
        sections.append("")
        sections.append("## LeakIX events (metadata only)")
        for row in bundle.leaks:
            host = row.hostname or row.ip
            sections.append(
                f"  {_one_line(host)}:{row.port}  {_one_line(row.kind)}  {_one_line(row.plugin or row.event)}"
            )
    if bundle.vt_domain:
        vt = bundle.vt_domain
        sections.append("")
        sections.append("## VirusTotal domain")
        sections.append(
            f"  malicious={vt.malicious} suspicious={vt.suspicious} harmless={vt.harmless} undetected={vt.undetected}"
        )
        if vt.categories:
            sections.append("  categories: " + ", ".join(_one_line(item) for item in vt.categories))

    sections.append("")
    sections.append("## Deterministic correlations")
    if not correlations:
        sections.append("  (none fired)")
    for rel in correlations:
        sections.append(f"  Data points: {', '.join(_one_line(point) for point in rel.data_points)}")
        sections.append(f"  Connection:  {_one_line(rel.relationship, limit=600)}")
        sections.append(f"  Relevance:   {_one_line(rel.offensive_relevance, limit=600)}")
        sections.append("")

    return "\n".join(sections).rstrip() + "\n"


def write_report(run_dir: Path, bundle: Bundle) -> tuple[Path, Path, list[Correlation]]:
    from osint_hub.phase2 import write_phase2

    correlations = correlate(bundle)
    write_json(run_dir / "correlations.json", [dump_model(item) for item in correlations])
    markdown = build_report(bundle, correlations)
    report_path = run_dir / "report.md"
    report_path.write_text(markdown, encoding="utf-8")
    write_phase2(run_dir, bundle, correlations)
    return report_path, run_dir / "correlations.json", correlations
