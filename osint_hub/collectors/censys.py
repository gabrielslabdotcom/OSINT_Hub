"""Censys Platform Search. Requires CENSYS_API_TOKEN (legacy ID/secret still accepted)."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, failed, post_with_retry, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, Host, InternetService
from osint_hub.util import is_in_scope

PLATFORM_SEARCH = "https://api.platform.censys.io/v3/global/search/query"
LEGACY_CERT_SEARCH = "https://search.censys.io/api/v2/certificates/search"
LEGACY_HOST_SEARCH = "https://search.censys.io/api/v2/hosts/search"
PLATFORM_HINT = "Censys Platform token rejected or search is not entitled on this plan."
LEGACY_HINT = "Censys Legacy Search is disabled or rejected these credentials."
PAGE_SIZE = 15


def _scope_name(value: object, domain: str) -> str | None:
    host = str(value or "").strip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    if host and is_in_scope(host, domain) and "*" not in host:
        return host
    return None


def _add_name(found: list[str], value: object, domain: str) -> None:
    host = _scope_name(value, domain)
    if host and host not in found:
        found.append(host)


def _resource(block: object) -> dict:
    if not isinstance(block, dict):
        return {}
    inner = block.get("resource")
    return inner if isinstance(inner, dict) else block


def _from_platform(payload: object, domain: str) -> tuple[list[str], list[Host]]:
    if not isinstance(payload, dict):
        return [], []
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    hits = (result or {}).get("hits") or []
    names: list[str] = []
    hosts: list[Host] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        cert = _resource(hit.get("certificate_v1"))
        for name in cert.get("names") or []:
            _add_name(names, name, domain)
        parsed = cert.get("parsed") if isinstance(cert.get("parsed"), dict) else {}
        for name in parsed.get("names") or []:
            _add_name(names, name, domain)

        web = _resource(hit.get("webproperty_v1"))
        _add_name(names, web.get("hostname"), domain)

        host_asset = hit.get("host_v1") if isinstance(hit.get("host_v1"), dict) else {}
        resource = _resource(host_asset)
        ip = str(resource.get("ip") or "").strip()
        dns = resource.get("dns") if isinstance(resource.get("dns"), dict) else {}
        scoped = []
        for name in dns.get("names") or []:
            host = _scope_name(name, domain)
            if host and host not in scoped:
                scoped.append(host)
            _add_name(names, name, domain)
        if not ip or not scoped:
            continue
        services: list[InternetService] = []
        raw_services = host_asset.get("matched_services") or resource.get("services") or []
        for svc in raw_services:
            if not isinstance(svc, dict):
                continue
            port = int(svc.get("port") or 0)
            label = str(svc.get("protocol") or svc.get("service_name") or svc.get("extended_service_name") or "unknown")
            services.append(
                InternetService(
                    ip=ip,
                    port=port,
                    service=label,
                    product=label,
                    hostnames=scoped,
                    in_scope=True,
                )
            )
        asn_block = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
        hosts.append(
            Host(
                ip=ip,
                hostnames=scoped,
                services=services,
                org=str(asn_block.get("name") or ""),
                asn=str(asn_block.get("asn") or ""),
                in_scope=True,
            )
        )
        if len(hosts) >= PAGE_SIZE:
            break
    return names, hosts


def _legacy_cert_names(payload: object, domain: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    hits = ((payload.get("result") or {}) if isinstance(payload.get("result"), dict) else payload).get("hits") or []
    found: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        names = hit.get("names") or (hit.get("parsed") or {}).get("names") or []
        for name in names:
            _add_name(found, name, domain)
    return found


def _legacy_hosts(payload: object, domain: str) -> list[Host]:
    if not isinstance(payload, dict):
        return []
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    hits = (result or {}).get("hits") or []
    hosts: list[Host] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        ip = str(hit.get("ip") or "").strip()
        if not ip:
            continue
        dns = hit.get("dns") if isinstance(hit.get("dns"), dict) else {}
        scoped = []
        for name in dns.get("names") or []:
            host = _scope_name(name, domain)
            if host and host not in scoped:
                scoped.append(host)
        if isinstance(hit.get("name"), str):
            extra = _scope_name(hit.get("name"), domain)
            if extra and extra not in scoped:
                scoped.insert(0, extra)
        if not scoped:
            continue
        services: list[InternetService] = []
        for svc in hit.get("services") or hit.get("matched_services") or []:
            if not isinstance(svc, dict):
                continue
            port = int(svc.get("port") or 0)
            label = str(svc.get("extended_service_name") or svc.get("service_name") or "unknown")
            services.append(
                InternetService(
                    ip=ip,
                    port=port,
                    service=label,
                    product=label,
                    hostnames=scoped,
                    in_scope=True,
                )
            )
        hosts.append(
            Host(
                ip=ip,
                hostnames=scoped,
                services=services,
                org=str(((hit.get("autonomous_system") or {}).get("name") or "")),
                asn=str(((hit.get("autonomous_system") or {}).get("asn") or "")),
                in_scope=True,
            )
        )
        if len(hosts) >= PAGE_SIZE:
            break
    return hosts


def _scrub(text: str, settings: Settings) -> str:
    body = text[:200]
    for secret in (settings.censys_api_token, settings.censys_api_secret, settings.censys_api_id):
        if secret and secret in body:
            body = body.replace(secret, "<redacted>")
    return body


async def _collect_platform(domain: str, settings: Settings, client: httpx.AsyncClient) -> tuple[list[str], list[Host]]:
    token = settings.censys_api_token or ""
    headers = client_headers(settings, {"Authorization": f"Bearer {token}"})
    params = {}
    if settings.censys_organization_id:
        params["organization_id"] = settings.censys_organization_id
    query = (
        f'cert.names: "{domain}" or host.dns.names: "{domain}" or web.hostname: "{domain}"'
    )
    response = await post_with_retry(
        client,
        PLATFORM_SEARCH,
        json={"query": query, "page_size": PAGE_SIZE},
        params=params or None,
        headers=headers,
    )
    if response.status_code in {401, 403}:
        raise RuntimeError(f"{PLATFORM_HINT} (HTTP {response.status_code})")
    if response.status_code >= 400:
        raise RuntimeError(f"Censys Platform HTTP {response.status_code}: {_scrub(response.text, settings)}")
    return _from_platform(response.json(), domain)


async def _collect_legacy(domain: str, settings: Settings, client: httpx.AsyncClient) -> tuple[list[str], list[Host]]:
    headers = client_headers(settings)
    auth = (settings.censys_api_id or "", settings.censys_api_secret or "")
    certs = await client.get(
        LEGACY_CERT_SEARCH,
        params={"q": f"names:{domain}", "per_page": 25},
        headers=headers,
        auth=auth,
    )
    if certs.status_code in {401, 403}:
        raise RuntimeError(LEGACY_HINT)
    if certs.status_code >= 400:
        raise RuntimeError(f"Censys certs HTTP {certs.status_code}: {_scrub(certs.text, settings)}")
    hosts_resp = await client.get(
        LEGACY_HOST_SEARCH,
        params={"q": f"dns.names:{domain}", "per_page": PAGE_SIZE},
        headers=headers,
        auth=auth,
    )
    if hosts_resp.status_code in {401, 403}:
        raise RuntimeError(LEGACY_HINT)
    if hosts_resp.status_code >= 400 and hosts_resp.status_code != 404:
        raise RuntimeError(f"Censys hosts HTTP {hosts_resp.status_code}: {_scrub(hosts_resp.text, settings)}")
    names = _legacy_cert_names(certs.json(), domain)
    parsed_hosts = _legacy_hosts(hosts_resp.json() if hosts_resp.status_code == 200 else {}, domain)
    for host in parsed_hosts:
        for name in host.hostnames:
            if name not in names:
                names.append(name)
    return names, parsed_hosts


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_censys:
        return skipped("censys", "CENSYS_API_TOKEN not set", started)
    try:
        if settings.censys_api_token:
            names, parsed_hosts = await _collect_platform(domain, settings, client)
        else:
            names, parsed_hosts = await _collect_legacy(domain, settings, client)
        payload = {"names": names, "hosts": parsed_hosts}
    except Exception as exc:  # noqa: BLE001
        return failed("censys", str(exc), started)
    return CollectorResult(
        name="censys",
        status="ok",
        records=len(names) + len(parsed_hosts),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data=payload,
    )
