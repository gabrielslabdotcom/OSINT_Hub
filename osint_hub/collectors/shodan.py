"""Shodan host lookups for IPs discovered via DNS. Requires SHODAN_API_KEY; skipped otherwise."""

from __future__ import annotations

import time
from typing import Any

import httpx

from osint_hub.collectors.base import client_headers, get_with_retry
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, Host, InternetService
from osint_hub.util import is_in_scope

HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SEARCH_URL = "https://api.shodan.io/shodan/host/search"
BANNER_CHARS = 400


def _service_label(entry: dict) -> str:
    product = entry.get("product") or ""
    version = entry.get("version") or ""
    if product and version:
        return f"{product}/{version}"
    if product:
        return str(product)
    module = (entry.get("_shodan") or {}).get("module")
    if module:
        return str(module)
    return str(entry.get("data") or "unknown").splitlines()[0][:80]


def _cve_ids(raw: object) -> list[str]:
    ids: list[str] = []
    if isinstance(raw, dict):
        ids.extend(str(key) for key in raw)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                ids.append(item)
            elif isinstance(item, dict):
                for key in ("cve", "id", "cve_id"):
                    if item.get(key):
                        ids.append(str(item[key]))
                        break
    seen: list[str] = []
    for item in ids:
        cve = item.strip().upper()
        if cve.startswith("CVE-") and cve not in seen:
            seen.append(cve)
    return seen


def _norm_name(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _iter_names(value: object) -> list[str]:
    names: list[str] = []
    if isinstance(value, str):
        for part in value.replace(",", " ").split():
            text = part.strip()
            if text.upper().startswith("DNS:"):
                text = text[4:]
            text = _norm_name(text.split(":")[0])
            if text:
                names.append(text)
    elif isinstance(value, list):
        for item in value:
            names.extend(_iter_names(item))
    elif isinstance(value, dict):
        for key in ("CN", "cn", "commonName", "name", "host"):
            if value.get(key):
                names.extend(_iter_names(value[key]))
    return names


def _banner_names(entry: dict) -> list[str]:
    names = _iter_names(entry.get("hostnames") or [])
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    names.extend(_iter_names(http.get("host") if http else None))
    ssl = entry.get("ssl") if isinstance(entry.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl, dict) and isinstance(ssl.get("cert"), dict) else {}
    if cert:
        names.extend(_iter_names(cert.get("subject")))
        extensions = cert.get("extensions") if isinstance(cert.get("extensions"), dict) else {}
        if extensions:
            names.extend(_iter_names(extensions.get("subject_alt_name") or extensions.get("subjectAltName")))
        names.extend(_iter_names(cert.get("subject_alt_name") or cert.get("subjectAltName")))
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def _unique(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def _cpe_list(entry: dict) -> list[str]:
    raw = entry.get("cpe23") or entry.get("cpe") or []
    if isinstance(raw, str):
        raw = [raw]
    return _unique([str(item) for item in raw if item])


def _http_components(http: dict) -> list[str]:
    components = http.get("components")
    if isinstance(components, dict):
        return _unique([str(name) for name in components if name])
    if isinstance(components, list):
        names: list[str] = []
        for item in components:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                names.append(str(item.get("name") or item.get("product") or ""))
        return _unique(names)
    return []


def _redirects(http: dict) -> str:
    location = http.get("location") or http.get("redirects") or ""
    if isinstance(location, list):
        parts = [str(item) for item in location[:4] if item]
        return " -> ".join(parts)[:240]
    return str(location or "")[:240]


def _tls_versions(ssl: dict) -> list[str]:
    versions = ssl.get("versions") or []
    if not isinstance(versions, list):
        return []
    return _unique([str(item) for item in versions if item and not str(item).startswith("-")])


def _ssl_flags(entry: dict, host_tags: list[str]) -> tuple[bool, bool, list[str]]:
    ssl = entry.get("ssl") if isinstance(entry.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl, dict) and isinstance(ssl.get("cert"), dict) else {}
    tags = {tag.lower() for tag in host_tags}
    tags.update(str(tag).lower() for tag in (entry.get("tags") or []) if tag)
    expired = bool(cert.get("expired")) or "expired" in tags
    self_signed = "self-signed" in tags or bool(cert.get("self_signed"))
    return expired, self_signed, _tls_versions(ssl if isinstance(ssl, dict) else {})


def _banner_text(entry: dict) -> str | None:
    banner = entry.get("data")
    if not banner:
        return None
    lines = [line.strip() for line in str(banner).splitlines() if line.strip()][:3]
    text = " | ".join(lines)[:BANNER_CHARS]
    return text or None


def _str_tags(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return _unique([str(item) for item in raw if item])


def _parse_host(payload: dict, domain: str) -> Host:
    ip = str(payload.get("ip_str") or payload.get("ip") or "")
    org = str(payload.get("org") or "").strip()
    asn = str(payload.get("asn") or "").strip()
    isp = str(payload.get("isp") or "").strip()
    os_name = str(payload.get("os") or "").strip()
    last_update = str(payload.get("last_update") or "").strip()
    country = str(payload.get("country_name") or payload.get("country_code") or "").strip()
    city = str(payload.get("city") or "").strip()
    tags = _str_tags(payload.get("tags"))
    raw_hostnames = [_norm_name(str(h)) for h in (payload.get("hostnames") or []) if str(h).strip()]
    off_domain = [name for name in raw_hostnames if name and not is_in_scope(name, domain)]
    scoped_hostnames = [name for name in raw_hostnames if name and is_in_scope(name, domain)]
    dedicated = bool(raw_hostnames) and not off_domain

    services: list[InternetService] = []
    service_vulns: list[str] = []
    for entry in payload.get("data") or []:
        if not isinstance(entry, dict):
            continue
        evidence = _banner_names(entry)
        if dedicated:
            attributed = True
        else:
            attributed = any(is_in_scope(name, domain) for name in evidence)
        if not attributed:
            continue
        http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
        title = http.get("title") if http else None
        names = [name for name in [*scoped_hostnames, *evidence] if is_in_scope(name, domain)]
        product = str(entry.get("product") or "").strip()
        version = str(entry.get("version") or "").strip()
        expired, self_signed, tls_versions = _ssl_flags(entry, tags)
        vulns = _cve_ids(entry.get("vulns"))
        for cve in vulns:
            if cve not in service_vulns:
                service_vulns.append(cve)
        services.append(
            InternetService(
                ip=ip,
                port=int(entry.get("port") or 0),
                service=_service_label(entry),
                product=product,
                version=version,
                http_title=str(title) if title else None,
                banner=_banner_text(entry),
                hostnames=sorted(set(names)),
                in_scope=True,
                transport=str(entry.get("transport") or "tcp"),
                cpe=_cpe_list(entry),
                info=str(entry.get("info") or "")[:200],
                http_server=str((http or {}).get("server") or ""),
                http_components=_http_components(http or {}),
                redirects=_redirects(http or {}),
                vulns=vulns,
                ssl_expired=expired,
                ssl_self_signed=self_signed,
                tls_versions=tls_versions,
            )
        )

    if dedicated:
        vulns = _cve_ids(payload.get("vulns"))
        for cve in service_vulns:
            if cve not in vulns:
                vulns.append(cve)
    else:
        vulns = service_vulns

    return Host(
        ip=ip,
        hostnames=scoped_hostnames,
        services=services,
        vulns=vulns,
        org=org,
        asn=asn,
        in_scope=bool(services) or bool(scoped_hostnames),
        tags=tags,
        os=os_name,
        isp=isp,
        last_update=last_update,
        country=country,
        city=city,
    )


def _fill_service(existing: InternetService, incoming: InternetService) -> None:
    if incoming.product and not existing.product:
        existing.product = incoming.product
    if incoming.version and not existing.version:
        existing.version = incoming.version
    if incoming.http_title and not existing.http_title:
        existing.http_title = incoming.http_title
    if incoming.banner and (not existing.banner or len(incoming.banner) > len(existing.banner)):
        existing.banner = incoming.banner
    if incoming.transport and not existing.transport:
        existing.transport = incoming.transport
    if incoming.info and not existing.info:
        existing.info = incoming.info
    if incoming.http_server and not existing.http_server:
        existing.http_server = incoming.http_server
    if incoming.redirects and not existing.redirects:
        existing.redirects = incoming.redirects
    existing.ssl_expired = existing.ssl_expired or incoming.ssl_expired
    existing.ssl_self_signed = existing.ssl_self_signed or incoming.ssl_self_signed
    for name in incoming.hostnames:
        if name not in existing.hostnames:
            existing.hostnames.append(name)
    for item in incoming.cpe:
        if item not in existing.cpe:
            existing.cpe.append(item)
    for item in incoming.http_components:
        if item not in existing.http_components:
            existing.http_components.append(item)
    for item in incoming.tls_versions:
        if item not in existing.tls_versions:
            existing.tls_versions.append(item)
    for cve in incoming.vulns:
        if cve not in existing.vulns:
            existing.vulns.append(cve)


def _merge_host(existing: Host, incoming: Host) -> None:
    if incoming.org and not existing.org:
        existing.org = incoming.org
    if incoming.asn and not existing.asn:
        existing.asn = incoming.asn
    if incoming.isp and not existing.isp:
        existing.isp = incoming.isp
    if incoming.os and not existing.os:
        existing.os = incoming.os
    if incoming.last_update and not existing.last_update:
        existing.last_update = incoming.last_update
    if incoming.country and not existing.country:
        existing.country = incoming.country
    if incoming.city and not existing.city:
        existing.city = incoming.city
    for name in incoming.hostnames:
        if name not in existing.hostnames:
            existing.hostnames.append(name)
    for tag in incoming.tags:
        if tag not in existing.tags:
            existing.tags.append(tag)
    by_port = {s.port: s for s in existing.services}
    for service in incoming.services:
        current = by_port.get(service.port)
        if current:
            _fill_service(current, service)
        else:
            existing.services.append(service)
            by_port[service.port] = service
    for cve in incoming.vulns:
        if cve not in existing.vulns:
            existing.vulns.append(cve)
    existing.in_scope = existing.in_scope or incoming.in_scope or bool(existing.services)


def _ingest_search_match(match: dict[str, Any], domain: str, hosts_by_ip: dict[str, Host], dns_ips: set[str]) -> None:
    if not match.get("ip_str"):
        return
    host = _parse_host(
        {
            "ip_str": match.get("ip_str"),
            "hostnames": match.get("hostnames") or [],
            "org": match.get("org") or "",
            "asn": match.get("asn") or "",
            "isp": match.get("isp") or "",
            "os": match.get("os") or "",
            "last_update": match.get("timestamp") or match.get("last_update") or "",
            "country_name": match.get("location", {}).get("country_name") if isinstance(match.get("location"), dict) else match.get("country_name"),
            "city": match.get("location", {}).get("city") if isinstance(match.get("location"), dict) else match.get("city"),
            "tags": match.get("tags") or [],
            "vulns": match.get("vulns"),
            "data": [match],
        },
        domain,
    )
    if not host.services and host.ip not in dns_ips:
        return
    existing = hosts_by_ip.get(host.ip)
    if existing:
        _merge_host(existing, host)
    else:
        hosts_by_ip[host.ip] = host


async def collect(
    domain: str,
    settings: Settings,
    client: httpx.AsyncClient,
    ips: list[str],
) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_shodan:
        return CollectorResult(
            name="shodan",
            status="skipped",
            error="SHODAN_API_KEY not set",
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=[],
        )

    headers = client_headers(settings)
    hosts_by_ip: dict[str, Host] = {}
    errors: list[str] = []

    unique_ips = []
    for ip in ips:
        if ip not in unique_ips:
            unique_ips.append(ip)
    unique_ips = unique_ips[: settings.shodan_max_hosts]
    dns_ips = set(unique_ips)

    try:
        queries = [f"hostname:{domain}", f'ssl.cert.subject.cn:"{domain}"']
        for query in queries:
            search = await get_with_retry(
                client,
                SEARCH_URL,
                params={"key": settings.shodan_api_key, "query": query},
                headers=headers,
            )
            if search.status_code == 401:
                raise RuntimeError("Shodan API key rejected (401)")
            if search.status_code == 200:
                for match in (search.json() or {}).get("matches") or []:
                    if isinstance(match, dict):
                        _ingest_search_match(match, domain, hosts_by_ip, dns_ips)
            elif search.status_code not in (404,):
                errors.append(f"{query} HTTP {search.status_code}")

        looked = 0
        for ip in unique_ips:
            if looked >= settings.shodan_max_hosts:
                break
            response = await get_with_retry(
                client,
                HOST_URL.format(ip=ip),
                params={"key": settings.shodan_api_key},
                headers=headers,
            )
            if response.status_code == 404:
                continue
            if response.status_code == 401:
                raise RuntimeError("Shodan API key rejected (401)")
            if response.status_code >= 400:
                errors.append(f"{ip}: HTTP {response.status_code}")
                continue
            host = _parse_host(response.json(), domain)
            existing = hosts_by_ip.get(host.ip)
            if existing:
                _merge_host(existing, host)
            else:
                hosts_by_ip[host.ip] = host
            looked += 1

        extra_ips = [ip for ip in hosts_by_ip if ip not in dns_ips]
        for ip in extra_ips:
            if looked >= settings.shodan_max_hosts:
                break
            if ip in unique_ips:
                continue
            response = await get_with_retry(
                client,
                HOST_URL.format(ip=ip),
                params={"key": settings.shodan_api_key},
                headers=headers,
            )
            if response.status_code != 200:
                continue
            host = _parse_host(response.json(), domain)
            existing = hosts_by_ip.get(host.ip)
            if existing:
                _merge_host(existing, host)
            else:
                hosts_by_ip[host.ip] = host
            looked += 1
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.perf_counter() - started) * 1000)
        return CollectorResult(
            name="shodan",
            status="error",
            error=str(exc),
            duration_ms=elapsed,
            data=[],
        )

    hosts = list(hosts_by_ip.values())
    elapsed = int((time.perf_counter() - started) * 1000)
    error = "; ".join(errors) if errors else None
    return CollectorResult(
        name="shodan",
        status="ok" if not (error and not hosts) else "error",
        records=sum(len(h.services) for h in hosts),
        error=error,
        duration_ms=elapsed,
        data=hosts,
    )
