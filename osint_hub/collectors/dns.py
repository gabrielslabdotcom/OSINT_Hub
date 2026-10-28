"""DNS collector — A/AAAA/MX/TXT/NS/CNAME via the system resolver (no API key)."""

from __future__ import annotations

import asyncio
import time

import dns.exception
import dns.resolver

from osint_hub.config import Settings
from osint_hub.models import CollectorResult, DnsRecord
from osint_hub.util import is_in_scope

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")


def _resolve_name(name: str, resolver: dns.resolver.Resolver) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(name, rtype)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        except dns.exception.DNSException:
            continue
        for rr in answers:
            if rtype == "MX":
                exchange = str(rr.exchange).rstrip(".")
                records.append(
                    DnsRecord(
                        name=name,
                        rtype=rtype,
                        value=exchange or ".",
                        priority=int(rr.preference),
                    )
                )
            elif rtype == "TXT":
                text = "".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rr.strings)
                records.append(DnsRecord(name=name, rtype=rtype, value=text))
            else:
                records.append(DnsRecord(name=name, rtype=rtype, value=str(rr).rstrip(".")))
    return records


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    return resolver


def resolve_hosts_sync(names: list[str], domain: str, settings: Settings) -> list[DnsRecord]:
    resolver = _make_resolver()
    seen: set[tuple[str, str, str]] = set()
    records: list[DnsRecord] = []
    limited = names[: settings.dns_max_hosts]
    for name in limited:
        if not is_in_scope(name, domain) and name != domain:
            continue
        for record in _resolve_name(name, resolver):
            key = (record.name, record.rtype, record.value)
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    return records


async def collect(domain: str, settings: Settings, extra_names: list[str] | None = None) -> CollectorResult:
    started = time.perf_counter()
    names = [domain]
    if extra_names:
        for name in extra_names:
            if name not in names:
                names.append(name)
    try:
        records = await asyncio.to_thread(resolve_hosts_sync, names, domain, settings)
    except Exception as exc:  # noqa: BLE001 — surface collector failure in the manifest
        elapsed = int((time.perf_counter() - started) * 1000)
        return CollectorResult(
            name="dns",
            status="error",
            error=str(exc),
            duration_ms=elapsed,
            data=[],
        )
    elapsed = int((time.perf_counter() - started) * 1000)
    return CollectorResult(
        name="dns",
        status="ok",
        records=len(records),
        duration_ms=elapsed,
        data=records,
    )
