"""Consolidate a bundle + correlations into markdown (lab Step 2 shape)."""

from __future__ import annotations

from pathlib import Path

from osint_hub.correlate import correlate, extra_txt_hints
from osint_hub.models import Bundle, Correlation, HotCveMatch
from osint_hub.util import dump_model, write_json


def _append_hot_cve(sections: list[str], hit: HotCveMatch) -> None:
    product = " ".join(part for part in (hit.vendor, hit.product) if part).strip() or "unknown product"
    sections.append(
        f"  {hit.cve_id}  {product}  added {hit.date_added or 'unknown'}  via {hit.source}  on {hit.matched_service}"
    )
    if hit.name:
        sections.append(f"    {hit.name}")
    if hit.evidence:
        sections.append(f"    Evidence: {hit.evidence}")
    if hit.confidence == "confirmed":
        sections.append(
            f"    Known-exploited CVE listed by CISA on {hit.date_added or 'an unknown date'}; "
            "confirm patch/exposure on this host."
        )
    else:
        sections.append("    Possible product overlap — confirm version/patch; not a verified CVE on this host.")


def build_report(bundle: Bundle, correlations: list[Correlation] | None = None) -> str:
    correlations = correlations if correlations is not None else correlate(bundle)
    sections: list[str] = [
        f"# OSINT Report: {bundle.domain}",
        f"Target: {bundle.domain}",
        f"Collection Date: {bundle.collected_at}",
        "",
        "## DNS Records",
    ]
    if not bundle.dns_records:
        sections.append("  (none)")
    for record in bundle.dns_records:
        if record.priority is not None:
            sections.append(f"  {record.rtype}: {record.name} -> {record.value} (priority {record.priority})")
        else:
            sections.append(f"  {record.rtype}: {record.name} -> {record.value}")

    hints = extra_txt_hints(bundle.dns_records)
    if hints:
        sections.append("")
        sections.append("## DNS TXT hints")
        for hint in hints:
            sections.append(f"  - {hint}")

    sections.append("")
    sections.append("## Certificate Transparency Logs")
    if not bundle.certificates:
        sections.append("  (none)")
    for cert in bundle.certificates:
        sections.append(f"  CN={cert.common_name}  Issuer={cert.issuer}  Expires={cert.not_after}")

    sections.append("")
    sections.append("## Discovered hostnames")
    for name in bundle.discovered_hostnames:
        sections.append(f"  - {name}")

    sections.append("")
    sections.append("## GitHub Exposure")
    if not bundle.github_findings:
        sections.append("  (none — collector skipped or no hits)")
    for finding in bundle.github_findings:
        sections.append(f"  Repo: {finding.repo}  File: {finding.file}")
        sections.append(f"  Match: {finding.match}")
        sections.append(f"  Author: {finding.author or 'N/A'}")
        if finding.url:
            sections.append(f"  URL: {finding.url}")
        sections.append("")

    sections.append("## Internet-Facing Services")
    attributed = [host for host in bundle.hosts if host.in_scope and host.services]
    shared = [host for host in bundle.hosts if not host.in_scope or not host.services]
    services = [svc for host in attributed for svc in host.services if svc.in_scope]
    if not services:
        sections.append("  (none attributed to this domain — collector skipped, no hits, or shared/CDN only)")
    for host in attributed:
        org = f"  org={host.org}" if host.org else ""
        asn = f"  asn={host.asn}" if host.asn else ""
        if org or asn:
            sections.append(f"  {host.ip}{org}{asn}")
        for svc in host.services:
            if not svc.in_scope:
                continue
            title = svc.http_title or svc.banner or "N/A"
            sections.append(f'  {svc.ip}:{svc.port}  {svc.service}  "{title}"')

    if shared:
        sections.append("")
        sections.append("## Shared / CDN IPs (not attributed)")
        for host in shared:
            org = host.org or "unknown"
            asn = host.asn or "unknown"
            sections.append(f"  {host.ip}  org={org}  asn={asn}")

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
            sections.append(f"  {row.email}" + (f"  {extra}" if extra else ""))
            if row.phone:
                sections.append(f"    phone {row.phone}")
            if row.linkedin:
                sections.append(f"    {row.linkedin}")
    if bundle.breaches:
        sections.append("")
        sections.append("## Breach memberships (HIBP)")
        for row in bundle.breaches:
            sections.append(f"  {row.email}  {row.name}" + (f"  {row.breach_date}" if row.breach_date else ""))
    if bundle.ip_intel:
        sections.append("")
        sections.append("## IP intel")
        for row in bundle.ip_intel:
            bits = [row.ip]
            if row.org:
                bits.append(row.org)
            if row.asn:
                bits.append(row.asn)
            if row.greynoise_classification:
                bits.append(f"greynoise={row.greynoise_classification}")
            if row.abuse_score is not None:
                bits.append(f"abuse={row.abuse_score}")
            sections.append("  " + "  ".join(bits))
    if bundle.url_scans:
        sections.append("")
        sections.append("## URLScan")
        for row in bundle.url_scans:
            sections.append(f'  {row.url}  {row.ip}  "{row.title or "N/A"}"')
    if bundle.leaks:
        sections.append("")
        sections.append("## LeakIX events (metadata only)")
        for row in bundle.leaks:
            host = row.hostname or row.ip
            sections.append(f"  {host}:{row.port}  {row.kind}  {row.plugin or row.event}")
    if bundle.vt_domain:
        vt = bundle.vt_domain
        sections.append("")
        sections.append("## VirusTotal domain")
        sections.append(
            f"  malicious={vt.malicious} suspicious={vt.suspicious} harmless={vt.harmless} undetected={vt.undetected}"
        )
        if vt.categories:
            sections.append("  categories: " + ", ".join(vt.categories))

    sections.append("")
    sections.append("## Deterministic correlations")
    if not correlations:
        sections.append("  (none fired)")
    for rel in correlations:
        sections.append(f"  Data points: {', '.join(rel.data_points)}")
        sections.append(f"  Connection:  {rel.relationship}")
        sections.append(f"  Relevance:   {rel.offensive_relevance}")
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
