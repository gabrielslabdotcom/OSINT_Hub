"""GitHub code search for the target domain. Requires GITHUB_TOKEN; skipped otherwise."""

from __future__ import annotations

import time

import httpx

from osint_hub.collectors.base import client_headers, get_with_retry
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, RepoFinding
from osint_hub.util import contains_hostname_token

SEARCH_URL = "https://api.github.com/search/code"


async def collect(domain: str, settings: Settings, client: httpx.AsyncClient) -> CollectorResult:
    started = time.perf_counter()
    if not settings.has_github:
        return CollectorResult(
            name="github",
            status="skipped",
            error="GITHUB_TOKEN not set",
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=[],
        )

    headers = client_headers(
        settings,
        {
            "Accept": "application/vnd.github.text-match+json",
            "Authorization": f"Bearer {settings.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    params = {"q": f'"{domain}"', "per_page": min(settings.github_max_results, 100)}
    try:
        response = await get_with_retry(client, SEARCH_URL, params=params, headers=headers)
        if response.status_code == 401:
            raise RuntimeError("GitHub token rejected (401)")
        if response.status_code == 403:
            raise RuntimeError("GitHub API forbidden or rate-limited (403)")
        if response.status_code == 422:
            raise RuntimeError("GitHub search query rejected (422)")
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub HTTP {response.status_code}")
        payload = response.json()
        findings = _parse_items(payload, domain)
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.perf_counter() - started) * 1000)
        return CollectorResult(
            name="github",
            status="error",
            error=str(exc),
            duration_ms=elapsed,
            data=[],
        )
    elapsed = int((time.perf_counter() - started) * 1000)
    return CollectorResult(
        name="github",
        status="ok",
        records=len(findings),
        duration_ms=elapsed,
        data=findings,
    )


def _parse_items(payload: object, domain: str) -> list[RepoFinding]:
    if not isinstance(payload, dict):
        return []
    findings: list[RepoFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        repo = (item.get("repository") or {}).get("full_name") or "unknown"
        path = item.get("path") or item.get("name") or "unknown"
        author = (item.get("repository") or {}).get("owner", {}).get("login")
        url = item.get("html_url")
        fragments: list[str] = []
        for match in item.get("text_matches") or []:
            fragment = (match or {}).get("fragment")
            if fragment:
                fragments.append(str(fragment).strip())
        match_text = "\n".join(fragments) if fragments else "(no text match fragment returned)"
        blob = f"{repo} {path} {match_text}"
        if not contains_hostname_token(blob, domain):
            continue
        key = (repo, path, match_text[:120])
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            RepoFinding(repo=repo, file=path, match=match_text, author=author, url=url)
        )
    return findings
