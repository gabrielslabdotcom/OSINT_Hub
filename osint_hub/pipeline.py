"""Orchestrate parallel collection, host expansion, bundle + manifest writes."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from osint_hub.collectors import (
    abuseipdb,
    censys,
    crtsh,
    dns,
    github,
    greynoise,
    hibp,
    hunter,
    ipinfo,
    kev,
    leakix,
    pdcp,
    phone_enrich,
    securitytrails,
    shodan,
    tomba,
    urlscan,
    virustotal,
)
from osint_hub.collectors.shodan import _merge_host
from osint_hub.hot_cves import match_hot_cves
from osint_hub.config import Settings, default_runs_dir
from osint_hub.models import (
    Bundle,
    Certificate,
    CollectorResult,
    CollectorStatus,
    DnsRecord,
    EmailRecord,
    Host,
    IpIntel,
    LeakRecord,
    Manifest,
    RepoFinding,
    UrlScanRecord,
    VtDomain,
)
from osint_hub.people import COMBINED_CAP, merge_email_records
from osint_hub.util import dump_model, iso_now, is_in_scope, new_run_dir, normalize_domain, write_json

console = Console()


@dataclass
class RunContext:
    domain: str
    run_dir: Path
    bundle: Bundle
    manifest: Manifest


def _as_records(result: CollectorResult) -> list[DnsRecord]:
    return list(result.data or []) if result.status == "ok" else []


def _as_certs(result: CollectorResult) -> list[Certificate]:
    return list(result.data or []) if result.status == "ok" else []


def _as_hosts(result: CollectorResult) -> list[Host]:
    return list(result.data or []) if result.status == "ok" else []


def _as_findings(result: CollectorResult) -> list[RepoFinding]:
    return list(result.data or []) if result.status == "ok" else []


def expand_hostnames(
    domain: str,
    dns_records: list[DnsRecord],
    certs: list[Certificate],
    extra_names: list[str] | None = None,
) -> list[str]:
    names: list[str] = [domain]
    for record in dns_records:
        for candidate in (record.name, record.value):
            if is_in_scope(candidate, domain) and "*" not in candidate and candidate not in names:
                names.append(candidate)
    for cert in certs:
        for candidate in [cert.common_name, *cert.names]:
            if candidate.startswith("*."):
                continue
            if is_in_scope(candidate, domain) and candidate not in names:
                names.append(candidate)
    for candidate in extra_names or []:
        if is_in_scope(candidate, domain) and "*" not in candidate and candidate not in names:
            names.append(candidate)
    return names


def _as_names(result: CollectorResult) -> list[str]:
    if result.status != "ok" or result.data is None:
        return []
    if isinstance(result.data, dict):
        return [str(name) for name in (result.data.get("names") or [])]
    return [str(name) for name in result.data if isinstance(name, str)]


def _as_emails(result: CollectorResult) -> list[EmailRecord]:
    return list(result.data or []) if result.status == "ok" else []


def _as_leaks(result: CollectorResult) -> list[LeakRecord]:
    return list(result.data or []) if result.status == "ok" else []


def _as_scans(result: CollectorResult) -> list[UrlScanRecord]:
    return list(result.data or []) if result.status == "ok" else []


def _as_intel(result: CollectorResult) -> list[IpIntel]:
    return list(result.data or []) if result.status == "ok" else []


def _as_vt(result: CollectorResult) -> VtDomain | None:
    if result.status != "ok" or not result.data:
        return None
    row = result.data[0]
    return row if isinstance(row, VtDomain) else None


def _censys_hosts(result: CollectorResult) -> list[Host]:
    if result.status != "ok" or not isinstance(result.data, dict):
        return []
    return list(result.data.get("hosts") or [])


def _merge_intel(*groups: list[IpIntel]) -> list[IpIntel]:
    by_ip: dict[str, IpIntel] = {}
    for group in groups:
        for row in group:
            current = by_ip.get(row.ip) or IpIntel(ip=row.ip)
            if row.org and not current.org:
                current.org = row.org
            if row.asn and not current.asn:
                current.asn = row.asn
            if row.hostname and not current.hostname:
                current.hostname = row.hostname
            if row.greynoise_classification:
                current.greynoise_classification = row.greynoise_classification
            if row.greynoise_noise is not None:
                current.greynoise_noise = row.greynoise_noise
            if row.greynoise_riot is not None:
                current.greynoise_riot = row.greynoise_riot
            if row.greynoise_name:
                current.greynoise_name = row.greynoise_name
            if row.greynoise_last_seen:
                current.greynoise_last_seen = row.greynoise_last_seen
            if row.abuse_score is not None:
                current.abuse_score = row.abuse_score
            if row.abuse_usage_type:
                current.abuse_usage_type = row.abuse_usage_type
            if row.abuse_isp:
                current.abuse_isp = row.abuse_isp
            by_ip[row.ip] = current
    return list(by_ip.values())


def _apply_intel(hosts: list[Host], intel: list[IpIntel]) -> None:
    by_ip = {row.ip: row for row in intel}
    for host in hosts:
        row = by_ip.get(host.ip)
        if not row:
            continue
        if row.org and not host.org:
            host.org = row.org
        if row.asn and not host.asn:
            host.asn = row.asn
        if row.greynoise_classification.lower() == "noise" and not host.services:
            host.in_scope = False


def extract_ips(dns_records: list[DnsRecord]) -> list[str]:
    ips: list[str] = []
    for record in dns_records:
        if record.rtype in {"A", "AAAA"} and record.value not in ips:
            ips.append(record.value)
    return ips


def _status_from_result(result: CollectorResult) -> CollectorStatus:
    return CollectorStatus(
        name=result.name,
        status=result.status,
        records=result.records,
        error=result.error,
        duration_ms=result.duration_ms,
    )


def _write_source(run_dir: Path, name: str, result: CollectorResult) -> None:
    raw = result.data
    if isinstance(raw, list):
        dumped: Any = [dump_model(item) for item in raw]
    elif isinstance(raw, dict):
        dumped = {
            key: [dump_model(item) for item in value] if isinstance(value, list) else dump_model(value)
            for key, value in raw.items()
        }
    else:
        dumped = dump_model(raw) if raw is not None else []
    payload = {
        "status": result.status,
        "records": result.records,
        "error": result.error,
        "duration_ms": result.duration_ms,
        "data": dumped,
    }
    write_json(run_dir / "sources" / f"{name}.json", payload)


def print_summary(manifest: Manifest) -> None:
    table = Table(title=f"OSINT_Hub collectors — {manifest.domain}")
    table.add_column("Collector")
    table.add_column("Status")
    table.add_column("Records", justify="right")
    table.add_column("ms", justify="right")
    table.add_column("Notes")
    for row in manifest.collectors:
        color = {"ok": "green", "skipped": "yellow", "error": "red"}.get(row.status, "white")
        table.add_row(
            row.name,
            f"[{color}]{row.status}[/{color}]",
            str(row.records),
            str(row.duration_ms or 0),
            row.error or "",
        )
    console.print(table)


ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


async def _emit(on_progress: ProgressCallback | None, event: dict[str, Any]) -> None:
    if on_progress is None:
        return
    result = on_progress(event)
    if inspect.isawaitable(result):
        await result


def _result_event(
    stage: str,
    result: CollectorResult,
    *,
    message: str | None = None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "collector": result.name,
        "status": result.status,
        "message": message or f"{result.name} [{result.status}]",
        "records": result.records,
        "error": result.error,
        "duration_ms": result.duration_ms,
    }


async def collect_domain(
    domain: str,
    settings: Settings,
    *,
    out_dir: Path | None = None,
    on_progress: ProgressCallback | None = None,
) -> RunContext:
    domain = normalize_domain(domain)
    runs_root = out_dir or default_runs_dir()
    run_dir = new_run_dir(runs_root, domain)
    started_at = iso_now()
    timeout = httpx.Timeout(settings.http_timeout)
    headers = {"User-Agent": settings.user_agent}

    await _emit(
        on_progress,
        {
            "stage": "started",
            "collector": None,
            "status": "running",
            "message": f"Opened run {run_dir.name}",
            "run_id": run_dir.name,
            "domain": domain,
        },
    )

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            t_dns = progress.add_task("DNS (apex)…", total=None)
            t_crt = progress.add_task("crt.sh…", total=None)
            await _emit(
                on_progress,
                {
                    "stage": "dns_apex",
                    "collector": "dns",
                    "status": "running",
                    "message": "DNS (apex)…",
                },
            )
            await _emit(
                on_progress,
                {
                    "stage": "crtsh",
                    "collector": "crtsh",
                    "status": "running",
                    "message": "crt.sh…",
                },
            )

            dns_task = asyncio.create_task(dns.collect(domain, settings))
            crt_task = asyncio.create_task(crtsh.collect(domain, settings, client))
            dns_result, crt_result = await asyncio.gather(dns_task, crt_task)
            progress.update(t_dns, description=f"DNS (apex) [{dns_result.status}]")
            progress.update(t_crt, description=f"crt.sh [{crt_result.status}]")
            progress.remove_task(t_dns)
            progress.remove_task(t_crt)
            await _emit(on_progress, _result_event("dns_apex", dns_result, message=f"DNS (apex) [{dns_result.status}]"))
            await _emit(on_progress, _result_event("crtsh", crt_result, message=f"crt.sh [{crt_result.status}]"))

            dns_records = _as_records(dns_result)
            certs = _as_certs(crt_result)

            t_subs = progress.add_task("Subdomain sources…", total=None)
            await _emit(on_progress, {"stage": "securitytrails", "collector": "securitytrails", "status": "running", "message": "SecurityTrails…"})
            await _emit(on_progress, {"stage": "pdcp", "collector": "pdcp", "status": "running", "message": "PDCP/Chaos…"})
            await _emit(on_progress, {"stage": "virustotal", "collector": "virustotal", "status": "running", "message": "VirusTotal…"})
            await _emit(on_progress, {"stage": "censys", "collector": "censys", "status": "running", "message": "Censys…"})
            st_result, pd_result, vt_result, ce_result = await asyncio.gather(
                securitytrails.collect(domain, settings, client),
                pdcp.collect(domain, settings, client),
                virustotal.collect(domain, settings, client),
                censys.collect(domain, settings, client),
            )
            progress.remove_task(t_subs)
            await _emit(on_progress, _result_event("securitytrails", st_result, message=f"SecurityTrails [{st_result.status}]"))
            await _emit(on_progress, _result_event("pdcp", pd_result, message=f"PDCP [{pd_result.status}]"))
            await _emit(on_progress, _result_event("virustotal", vt_result, message=f"VirusTotal [{vt_result.status}]"))
            await _emit(on_progress, _result_event("censys", ce_result, message=f"Censys [{ce_result.status}]"))

            vt_domain = _as_vt(vt_result)
            extra_names = [
                *_as_names(st_result),
                *_as_names(pd_result),
                *_as_names(ce_result),
                *(vt_domain.subdomains if vt_domain else []),
            ][: settings.dns_max_hosts]
            hostnames = expand_hostnames(domain, dns_records, certs, extra_names)

            extra = [name for name in hostnames if name != domain]
            t_dns2 = progress.add_task(f"DNS ({len(extra)} discovered hosts)…", total=None)
            await _emit(
                on_progress,
                {
                    "stage": "dns_expand",
                    "collector": "dns",
                    "status": "running",
                    "message": f"DNS ({len(extra)} discovered hosts)…",
                    "records": len(extra),
                },
            )
            if extra:
                extra_result = await dns.collect(domain, settings, extra_names=extra)
                extra_records = _as_records(extra_result)
                seen = {(r.name, r.rtype, r.value) for r in dns_records}
                for record in extra_records:
                    key = (record.name, record.rtype, record.value)
                    if key not in seen:
                        dns_records.append(record)
                        seen.add(key)
                dns_result = CollectorResult(
                    name="dns",
                    status="ok" if dns_result.status == "ok" or extra_result.status == "ok" else extra_result.status,
                    records=len(dns_records),
                    error=dns_result.error or extra_result.error,
                    duration_ms=(dns_result.duration_ms or 0) + (extra_result.duration_ms or 0),
                    data=dns_records,
                )
            progress.remove_task(t_dns2)
            await _emit(
                on_progress,
                _result_event("dns_expand", dns_result, message=f"DNS expansion [{dns_result.status}]"),
            )

            ips = extract_ips(dns_records)[: settings.shodan_max_hosts]
            t_dom = progress.add_task("GitHub / Shodan / Hunter / Tomba / URLScan / LeakIX…", total=None)
            await _emit(on_progress, {"stage": "github", "collector": "github", "status": "running", "message": "GitHub…"})
            await _emit(on_progress, {"stage": "shodan", "collector": "shodan", "status": "running", "message": "Shodan…"})
            await _emit(on_progress, {"stage": "hunter", "collector": "hunter", "status": "running", "message": "Hunter…"})
            await _emit(on_progress, {"stage": "tomba", "collector": "tomba", "status": "running", "message": "Tomba…"})
            await _emit(on_progress, {"stage": "urlscan", "collector": "urlscan", "status": "running", "message": "URLScan…"})
            await _emit(on_progress, {"stage": "leakix", "collector": "leakix", "status": "running", "message": "LeakIX…"})
            gh_result, sh_result, hu_result, tb_result, us_result, lx_result = await asyncio.gather(
                github.collect(domain, settings, client),
                shodan.collect(domain, settings, client, ips),
                hunter.collect(domain, settings, client),
                tomba.collect(domain, settings, client),
                urlscan.collect(domain, settings, client),
                leakix.collect(domain, settings, client),
            )
            progress.remove_task(t_dom)
            await _emit(on_progress, _result_event("github", gh_result, message=f"GitHub [{gh_result.status}]"))
            await _emit(on_progress, _result_event("shodan", sh_result, message=f"Shodan [{sh_result.status}]"))
            await _emit(on_progress, _result_event("hunter", hu_result, message=f"Hunter [{hu_result.status}]"))
            await _emit(on_progress, _result_event("tomba", tb_result, message=f"Tomba [{tb_result.status}]"))
            await _emit(on_progress, _result_event("urlscan", us_result, message=f"URLScan [{us_result.status}]"))
            await _emit(on_progress, _result_event("leakix", lx_result, message=f"LeakIX [{lx_result.status}]"))

            t_ip = progress.add_task("IP intel…", total=None)
            await _emit(on_progress, {"stage": "ipinfo", "collector": "ipinfo", "status": "running", "message": "IPinfo…"})
            await _emit(on_progress, {"stage": "greynoise", "collector": "greynoise", "status": "running", "message": "GreyNoise…"})
            await _emit(on_progress, {"stage": "abuseipdb", "collector": "abuseipdb", "status": "running", "message": "AbuseIPDB…"})
            ip_result, gn_result, ab_result = await asyncio.gather(
                ipinfo.collect(settings, client, ips),
                greynoise.collect(settings, client, ips),
                abuseipdb.collect(settings, client, ips),
            )
            progress.remove_task(t_ip)
            await _emit(on_progress, _result_event("ipinfo", ip_result, message=f"IPinfo [{ip_result.status}]"))
            await _emit(on_progress, _result_event("greynoise", gn_result, message=f"GreyNoise [{gn_result.status}]"))
            await _emit(on_progress, _result_event("abuseipdb", ab_result, message=f"AbuseIPDB [{ab_result.status}]"))

            emails = merge_email_records(_as_emails(hu_result), _as_emails(tb_result), cap=COMBINED_CAP)
            t_phone = progress.add_task("Phone enrich…", total=None)
            await _emit(
                on_progress,
                {"stage": "phone_enrich", "collector": "phone_enrich", "status": "running", "message": "Phone enrich…"},
            )
            pe_result = await phone_enrich.collect(emails, settings, client)
            progress.remove_task(t_phone)
            await _emit(
                on_progress,
                _result_event("phone_enrich", pe_result, message=f"Phone enrich [{pe_result.status}]"),
            )
            t_hibp = progress.add_task("HIBP…", total=None)
            await _emit(on_progress, {"stage": "hibp", "collector": "hibp", "status": "running", "message": "HIBP…"})
            hibp_result = await hibp.collect(settings, client, emails)
            progress.remove_task(t_hibp)
            await _emit(on_progress, _result_event("hibp", hibp_result, message=f"HIBP [{hibp_result.status}]"))

            t_kev = progress.add_task("CISA KEV…", total=None)
            await _emit(on_progress, {"stage": "hot_cves", "collector": "kev", "status": "running", "message": "CISA KEV…"})
            kev_result = await kev.collect(settings, client)
            progress.remove_task(t_kev)
            await _emit(on_progress, _result_event("hot_cves", kev_result, message=f"CISA KEV [{kev_result.status}]"))

    await _emit(
        on_progress,
        {
            "stage": "writing",
            "collector": None,
            "status": "running",
            "message": "Writing bundle and manifest…",
            "run_id": run_dir.name,
        },
    )
    extra_results = [
        ("dns", dns_result),
        ("crtsh", crt_result),
        ("securitytrails", st_result),
        ("pdcp", pd_result),
        ("virustotal", vt_result),
        ("censys", ce_result),
        ("github", gh_result),
        ("shodan", sh_result),
        ("hunter", hu_result),
        ("tomba", tb_result),
        ("urlscan", us_result),
        ("leakix", lx_result),
        ("ipinfo", ip_result),
        ("greynoise", gn_result),
        ("abuseipdb", ab_result),
        ("phone_enrich", pe_result),
        ("hibp", hibp_result),
        ("kev", kev_result),
    ]
    for name, result in extra_results:
        _write_source(run_dir, name, result)

    hosts = _as_hosts(sh_result)
    for incoming in _censys_hosts(ce_result):
        existing = next((host for host in hosts if host.ip == incoming.ip), None)
        if existing:
            _merge_host(existing, incoming)
        else:
            hosts.append(incoming)
    intel = _merge_intel(_as_intel(ip_result), _as_intel(gn_result), _as_intel(ab_result))
    _apply_intel(hosts, intel)
    kev_rows = list(kev_result.data or []) if kev_result.status == "ok" else []
    hot_cves = match_hot_cves(
        Bundle(
            domain=domain,
            collected_at=started_at,
            hosts=hosts,
        ),
        kev_rows,
    )
    bundle = Bundle(
        domain=domain,
        collected_at=started_at,
        dns_records=dns_records,
        certificates=certs,
        hosts=hosts,
        github_findings=_as_findings(gh_result),
        discovered_hostnames=expand_hostnames(domain, dns_records, certs, extra_names),
        hot_cves=hot_cves,
        emails=emails,
        breaches=list(hibp_result.data or []) if hibp_result.status == "ok" else [],
        ip_intel=intel,
        url_scans=_as_scans(us_result),
        leaks=_as_leaks(lx_result),
        vt_domain=vt_domain,
    )
    write_json(run_dir / "bundle.json", dump_model(bundle))

    manifest = Manifest(
        domain=domain,
        started_at=started_at,
        finished_at=iso_now(),
        run_dir=str(run_dir),
        collectors=[_status_from_result(result) for _name, result in extra_results],
    )
    write_json(run_dir / "manifest.json", dump_model(manifest))
    print_summary(manifest)
    console.print(f"[green]Run directory[/green] {run_dir}")
    await _emit(
        on_progress,
        {
            "stage": "collect_done",
            "collector": None,
            "status": "ok",
            "message": f"Collection complete — {run_dir.name}",
            "run_id": run_dir.name,
            "domain": domain,
        },
    )
    return RunContext(domain=domain, run_dir=run_dir, bundle=bundle, manifest=manifest)


def load_bundle(run_dir: Path) -> Bundle:
    from osint_hub.util import read_json

    return Bundle.model_validate(read_json(run_dir / "bundle.json"))
