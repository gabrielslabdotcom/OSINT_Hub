"""Deterministic cross-source joins — produce lab-shaped correlation records."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from osint_hub.models import Bundle, Certificate, Correlation, DnsRecord, InternetService
from osint_hub.util import contains_hostname_token

EXPOSURE_PATTERNS = (
    ("jenkins", "Jenkins CI"),
    ("grafana", "Grafana"),
    ("outlook web", "Outlook Web Access"),
    ("rdweb", "RD Web Access"),
    ("fortinet", "Fortinet VPN/firewall"),
    ("pulse secure", "Pulse Secure VPN"),
    ("citrix", "Citrix gateway"),
    ("globalprotect", "Palo Alto GlobalProtect"),
    ("palo alto", "Palo Alto"),
    ("cisco asa", "Cisco ASA"),
    ("anyconnect", "Cisco AnyConnect"),
    ("sonicwall", "SonicWall"),
    ("vmware horizon", "VMware Horizon"),
    ("phpmyadmin", "phpMyAdmin"),
    ("kubernetes", "Kubernetes"),
    ("docker registry", "Docker registry"),
    ("sonarqube", "SonarQube"),
    ("kibana", "Kibana"),
    ("gitlab", "GitLab"),
    ("confluence", "Confluence"),
    ("sharepoint", "SharePoint"),
    ("jira", "Jira"),
    ("tomcat", "Apache Tomcat"),
    ("wordpress", "WordPress"),
)

HIGH_VALUE_PORTS = {
    21: "FTP",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017: "MongoDB",
}


def _parse_expiry(value: str) -> datetime | None:
    text = (value or "").strip().replace("Z", "")
    if not text:
        return None
    for candidate in (text[:19], text[:10]):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(candidate, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _haystack(service: InternetService) -> str:
    parts = [
        service.product,
        service.version,
        service.service,
        service.http_title or "",
        service.banner or "",
        service.info,
        service.http_server,
        " ".join(service.cpe),
        " ".join(service.http_components),
    ]
    return " ".join(part for part in parts if part).lower()


def _phrase_in(needle: str, hay: str) -> bool:
    text = needle.lower()
    if " " in text:
        return text in hay
    return re.search(rf"(?<![a-z0-9]){re.escape(text)}(?![a-z0-9])", hay) is not None


def correlate(bundle: Bundle) -> list[Correlation]:
    domain = bundle.domain
    findings: list[Correlation] = []

    findings.extend(_hostname_alignment(bundle, domain))
    findings.extend(_ip_convergence(bundle))
    findings.extend(_tooling_exposure(bundle))
    findings.extend(_hot_cves(bundle))
    findings.extend(_expired_certs(bundle))
    findings.extend(_mail_auth(bundle, domain))
    findings.extend(_vt_and_names(bundle, domain))
    findings.extend(_ip_intel_notes(bundle))
    findings.extend(_mailbox_breaches(bundle, domain))
    findings.extend(_urlscan_and_leaks(bundle))
    return findings


def _hostname_alignment(bundle: Bundle, domain: str) -> list[Correlation]:
    names: set[str] = set(bundle.discovered_hostnames)
    for cert in bundle.certificates:
        names.update(n for n in cert.names if not n.startswith("*."))
        names.add(cert.common_name)
    names = {n.lower().rstrip(".") for n in names if n and "*" not in n}

    out: list[Correlation] = []
    for finding in bundle.github_findings:
        blob = f"{finding.file} {finding.match}"
        hits = sorted(name for name in names if name != domain and contains_hostname_token(blob, name))
        if not hits:
            continue
        cert_hits = [
            cert.common_name
            for cert in bundle.certificates
            if cert.common_name in hits or any(n in hits for n in cert.names)
        ]
        data_points = [f"github:{finding.repo}:{finding.file}", *[f"host:{h}" for h in hits[:8]]]
        if cert_hits:
            data_points.extend(f"cert:{cn}" for cn in cert_hits[:4])
        out.append(
            Correlation(
                data_points=data_points,
                relationship=(
                    f"GitHub {finding.repo} mentions in-scope hostname(s) {', '.join(hits[:6])}"
                    + (f"; also present in CT as {', '.join(cert_hits[:4])}" if cert_hits else "")
                ),
                offensive_relevance=(
                    "Public code corroborates live DNS/CT names — useful for mapping internal "
                    "hostnames, credentials patterns, or forgotten subdomains."
                ),
            )
        )
    return out


def _ip_convergence(bundle: Bundle) -> list[Correlation]:
    dns_ips: dict[str, list[str]] = {}
    for record in bundle.dns_records:
        if record.rtype in {"A", "AAAA"}:
            dns_ips.setdefault(record.value, []).append(record.name)
    out: list[Correlation] = []
    for host in bundle.hosts:
        names = dns_ips.get(host.ip)
        if not names:
            continue
        org = host.org or host.asn or "unknown org"
        if not host.in_scope or not host.services:
            out.append(
                Correlation(
                    data_points=[f"dns:{n}" for n in names[:8]] + [f"host:{host.ip}"],
                    relationship=(
                        f"DNS names {', '.join(sorted(set(names))[:8])} resolve to {host.ip} ({org}), "
                        "which looks like a shared/CDN address — Shodan banners on this IP were not attributed to the target."
                    ),
                    offensive_relevance="Do not treat this IP’s indexed software as the target’s stack.",
                )
            )
            continue
        ports = ", ".join(f"{svc.port}/{svc.service}" for svc in host.services[:8]) or "no open services indexed"
        out.append(
            Correlation(
                data_points=[f"dns:{n}" for n in names[:8]] + [f"host:{host.ip}", *[s.entity_id for s in host.services[:6]]],
                relationship=(
                    f"DNS names {', '.join(sorted(set(names))[:8])} resolve to {host.ip} ({org}), "
                    f"with in-scope services {ports}."
                ),
                offensive_relevance="Same IP across DNS and an attributed internet scan is a confirmed internet-facing node for that name.",
            )
        )
    return out


def _tooling_exposure(bundle: Bundle) -> list[Correlation]:
    out: list[Correlation] = []
    for host in bundle.hosts:
        if not host.in_scope:
            continue
        for service in host.services:
            if not service.in_scope:
                continue
            hay = _haystack(service)
            label = ""
            for needle, name in EXPOSURE_PATTERNS:
                if _phrase_in(needle, hay):
                    label = name
                    break
            if not label:
                label = HIGH_VALUE_PORTS.get(service.port, "")
            if not label:
                continue
            title = service.http_title or service.service
            out.append(
                Correlation(
                    data_points=[service.entity_id, f"host:{host.ip}"],
                    relationship=f"{label} fingerprint on {host.ip}:{service.port} ({title}).",
                    offensive_relevance=(
                        f"Internet-exposed {label} is a high-value recon/admin surface if it is "
                        "unauthenticated, outdated, or reachable without VPN."
                    ),
                )
            )
    return out


def _hot_cves(bundle: Bundle) -> list[Correlation]:
    out: list[Correlation] = []
    for hit in bundle.hot_cves:
        via = "Shodan CVE tag" if hit.source == "shodan" else "product fingerprint"
        product = " ".join(part for part in (hit.vendor, hit.product) if part).strip() or "unknown product"
        listed = hit.date_added or "an unknown date"
        suspected = hit.confidence == "suspected" or hit.source == "fingerprint"
        out.append(
            Correlation(
                data_points=[hit.entity_id, hit.matched_service, hit.cve_id],
                relationship=(
                    f"{hit.cve_id} ({product}) matched via {via} on {hit.matched_service}; "
                    f"CISA KEV listed it on {listed}."
                    + (f" Evidence: {hit.evidence}." if hit.evidence else "")
                ),
                offensive_relevance=(
                    "Possible product overlap — confirm version/patch; not a verified CVE on this host."
                    if suspected
                    else f"Known-exploited CVE listed by CISA on {listed}; confirm patch/exposure on this host."
                ),
            )
        )
    return out


def _expired_certs(bundle: Bundle) -> list[Correlation]:
    now = datetime.now(timezone.utc)
    earliest: dict[str, tuple[datetime, Certificate]] = {}
    for cert in bundle.certificates:
        expiry = _parse_expiry(cert.not_after)
        if expiry is None or expiry >= now:
            continue
        previous = earliest.get(cert.common_name)
        if previous is None or expiry < previous[0]:
            earliest[cert.common_name] = (expiry, cert)
    out: list[Correlation] = []
    for common_name, (_when, cert) in sorted(earliest.items()):
        out.append(
            Correlation(
                data_points=[cert.entity_id, f"host:{common_name}"],
                relationship=f"Certificate for {common_name} expired {cert.not_after} (issuer {cert.issuer}).",
                offensive_relevance="Expired certs often mark neglected hosts (legacy apps, forgotten staging) worth extra scrutiny.",
            )
        )
    return out


def _mail_auth(bundle: Bundle, domain: str) -> list[Correlation]:
    txts = [r for r in bundle.dns_records if r.rtype == "TXT"]
    spf = [r for r in txts if r.value.lower().startswith("v=spf1")]
    dmarc = [r for r in txts if "v=dmarc1" in r.value.lower()]
    if not spf and not dmarc:
        return []

    providers: list[str] = []
    for record in spf:
        lower = record.value.lower()
        if "spf.protection.outlook.com" in lower:
            providers.append("Microsoft 365")
        if "_spf.google.com" in lower:
            providers.append("Google Workspace")
        if "include:" in lower:
            includes = re.findall(r"include:([^\s]+)", lower)
            providers.extend(includes[:6])

    policy = "missing"
    for record in dmarc:
        match = re.search(r"\bp=([a-z]+)", record.value.lower())
        if match:
            policy = match.group(1)
            break

    data_points = [r.entity_id for r in spf + dmarc]
    spoof_note = (
        "DMARC p=none (or missing) does not reject spoofed mail — relevant to phishing pretexting, not a remote exploit."
        if policy in {"none", "missing"}
        else f"DMARC policy is p={policy}."
    )
    provider_text = ", ".join(dict.fromkeys(providers)) or "unknown mail providers"
    return [
        Correlation(
            data_points=data_points,
            relationship=f"Mail authentication for {domain}: SPF present={bool(spf)}, DMARC p={policy}, providers={provider_text}.",
            offensive_relevance=spoof_note,
        )
    ]


def _vt_and_names(bundle: Bundle, domain: str) -> list[Correlation]:
    out: list[Correlation] = []
    vt = bundle.vt_domain
    if vt and (vt.malicious or vt.suspicious):
        out.append(
            Correlation(
                data_points=[vt.entity_id],
                relationship=(
                    f"VirusTotal last_analysis_stats for {domain}: malicious={vt.malicious}, "
                    f"suspicious={vt.suspicious}, harmless={vt.harmless}."
                ),
                offensive_relevance="Vendor detections are reputation context, not a confirmed exploit on this host.",
            )
        )
    dns_ips = {r.value for r in bundle.dns_records if r.rtype in {"A", "AAAA"}}
    if vt:
        overlap = [ip for ip in vt.resolutions if ip in dns_ips]
        if overlap:
            out.append(
                Correlation(
                    data_points=[vt.entity_id, *[f"host:{ip}" for ip in overlap[:8]]],
                    relationship=f"VirusTotal resolutions overlap live DNS IPs: {', '.join(overlap[:8])}.",
                    offensive_relevance="Passive DNS agrees with current resolution — useful attribution, not extra software.",
                )
            )
    extra = [n for n in bundle.discovered_hostnames if n != domain]
    if extra:
        out.append(
            Correlation(
                data_points=[f"host:{n}" for n in extra[:8]],
                relationship=f"{len(extra)} in-scope hostnames from DNS/CT/SecurityTrails/PDCP/Censys/VT.",
                offensive_relevance="Expanded names are recon surface only after they resolve and attribute.",
            )
        )
    return out


def _ip_intel_notes(bundle: Bundle) -> list[Correlation]:
    out: list[Correlation] = []
    intel = {row.ip: row for row in bundle.ip_intel}
    for host in bundle.hosts:
        row = intel.get(host.ip)
        if not row:
            continue
        if (row.greynoise_classification or "").lower() == "noise":
            out.append(
                Correlation(
                    data_points=[row.entity_id, host.entity_id],
                    relationship=(
                        f"{host.ip} is GreyNoise classification=noise"
                        + (f" ({row.greynoise_name})" if row.greynoise_name else "")
                        + "."
                    ),
                    offensive_relevance="Treat as internet background / scanner noise, not this target’s stack.",
                )
            )
        if not host.in_scope or not host.services:
            org = row.org or host.org or "unknown org"
            out.append(
                Correlation(
                    data_points=[row.entity_id, host.entity_id],
                    relationship=f"{host.ip} IPinfo/org={org} looks like shared/CDN or unattributed.",
                    offensive_relevance="Do not inherit other tenants’ services or CVEs on this address.",
                )
            )
        if row.abuse_score is not None and row.abuse_score >= 50:
            out.append(
                Correlation(
                    data_points=[row.entity_id, host.entity_id],
                    relationship=f"{host.ip} AbuseIPDB confidence {row.abuse_score} ({row.abuse_usage_type or 'unknown usage'}).",
                    offensive_relevance="Reputation only — not evidence of a vulnerability on the authorized domain.",
                )
            )
    return out


def _mailbox_breaches(bundle: Bundle, domain: str) -> list[Correlation]:
    if not bundle.emails:
        return []
    suffix = "@" + domain
    in_domain = [e for e in bundle.emails if e.email.endswith(suffix)]
    if not in_domain:
        return []
    names = ", ".join(e.email for e in in_domain[:8])
    out = [
        Correlation(
            data_points=[e.entity_id for e in in_domain[:8]],
            relationship=f"Hunter domain-search returned {len(in_domain)} mailbox(es) on {domain}: {names}.",
            offensive_relevance="Identities for phishing/pretexting against this domain’s portals — not a remote exploit.",
        )
    ]
    if bundle.breaches:
        sample = ", ".join(f"{b.email} ({b.name})" for b in bundle.breaches[:6])
        out.append(
            Correlation(
                data_points=[b.entity_id for b in bundle.breaches[:8]],
                relationship=f"HIBP listed {len(bundle.breaches)} breach membership(s): {sample}.",
                offensive_relevance="Credential-stuffing risk against in-scope login portals if those passwords were reused.",
            )
        )
    return out


def _urlscan_and_leaks(bundle: Bundle) -> list[Correlation]:
    out: list[Correlation] = []
    if bundle.url_scans:
        sample = ", ".join(s.url for s in bundle.url_scans[:4])
        out.append(
            Correlation(
                data_points=[s.entity_id for s in bundle.url_scans[:6]],
                relationship=f"URLScan indexed {len(bundle.url_scans)} in-scope page(s), e.g. {sample}.",
                offensive_relevance="Public crawl of this domain’s URLs — confirm titles/tech against attributed services.",
            )
        )
    if bundle.leaks:
        kinds = ", ".join(sorted({row.kind or row.plugin or "event" for row in bundle.leaks})[:8])
        out.append(
            Correlation(
                data_points=[row.entity_id for row in bundle.leaks[:6]],
                relationship=f"LeakIX reported {len(bundle.leaks)} in-scope event(s) (types: {kinds}). Contents are not stored.",
                offensive_relevance="Event type only — confirm the host/port is still attributed; do not treat as a dump of secrets.",
            )
        )
    return out


def extra_txt_hints(records: list[DnsRecord]) -> list[str]:
    hints: list[str] = []
    for record in records:
        if record.rtype != "TXT":
            continue
        value = record.value.lower()
        if "atlassian-domain-verification" in value:
            hints.append("Atlassian (Jira/Confluence/Trello) domain verification TXT")
        if value.startswith("ms="):
            hints.append("Microsoft 365 domain verification TXT")
        if "amazonses" in value:
            hints.append("Amazon SES TXT")
        if "google-site-verification" in value:
            hints.append("Google site verification TXT")
    return hints
