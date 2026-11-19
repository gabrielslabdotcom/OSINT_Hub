"""Optional User Scanner adapter for email/username profile checks."""

from __future__ import annotations

import asyncio
import importlib.util
import time
from types import ModuleType
from typing import Any

from osint_hub.collectors.base import failed, skipped
from osint_hub.config import Settings
from osint_hub.models import CollectorResult, ProfileFinding, ScanDepth

NAME = "user_scanner"

QUICK_EMAIL_CATEGORIES = ("social", "dev")
QUICK_USER_CATEGORIES = ("social", "dev")
STANDARD_EMAIL_CATEGORIES = ("social", "dev", "learning", "jobs", "community", "creator")
STANDARD_USER_CATEGORIES = ("social", "dev", "community", "creator", "learning", "entertainment")

QUICK_MODULE_CAP = 40
STANDARD_MODULE_CAP = 120


def available() -> bool:
    return importlib.util.find_spec("user_scanner") is not None


def _status_from_upstream(status_value: Any, *, is_email: bool) -> str:
    label = str(getattr(status_value, "name", status_value) or "").upper()
    if label in {"TAKEN"}:
        return "found"
    if label in {"AVAILABLE"}:
        return "not_found"
    if label in {"SKIPPED"}:
        return "skipped"
    # ERROR and unknown map to unknown — never treat failures as not-found.
    _ = is_email
    return "unknown"


def _metadata(extra: dict[str, Any] | None, media: dict[str, Any] | None, reason: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if isinstance(extra, dict):
        for key, value in extra.items():
            if value is None or value == "":
                continue
            meta[str(key)] = value
    if isinstance(media, dict) and media:
        meta["media"] = {str(key): value for key, value in media.items() if value}
    if reason:
        meta["reason"] = reason
    return meta


def map_result(raw: Any, *, seed: str, seed_type: str) -> ProfileFinding | None:
    platform = str(getattr(raw, "site_name", "") or "").strip()
    if not platform:
        return None
    status = _status_from_upstream(getattr(raw, "status", None), is_email=seed_type == "email")
    reason = ""
    if hasattr(raw, "get_reason"):
        try:
            reason = str(raw.get_reason() or "")
        except Exception:  # noqa: BLE001
            reason = str(getattr(raw, "reason", "") or "")
    else:
        reason = str(getattr(raw, "reason", "") or "")
    return ProfileFinding(
        seed_type=seed_type,  # type: ignore[arg-type]
        seed=seed,
        platform=platform,
        category=str(getattr(raw, "category", "") or ""),
        status=status,  # type: ignore[arg-type]
        url=str(getattr(raw, "url", "") or ""),
        metadata=_metadata(getattr(raw, "extra", None), getattr(raw, "media", None), reason),
        source=NAME,
    )


def _categories_for(scan_depth: ScanDepth, *, is_email: bool) -> list[str] | None:
    if scan_depth == "full":
        return None
    if scan_depth == "quick":
        return list(QUICK_EMAIL_CATEGORIES if is_email else QUICK_USER_CATEGORIES)
    return list(STANDARD_EMAIL_CATEGORIES if is_email else STANDARD_USER_CATEGORIES)


def _module_cap(scan_depth: ScanDepth) -> int | None:
    if scan_depth == "quick":
        return QUICK_MODULE_CAP
    if scan_depth == "standard":
        return STANDARD_MODULE_CAP
    return None


def _load_modules(is_email: bool, categories: list[str] | None, *, no_nsfw: bool) -> list[ModuleType]:
    from user_scanner.core import engine

    available_cats = engine.load_categories(is_email=is_email, no_nsfw=no_nsfw)
    selected = list(available_cats.keys()) if categories is None else categories
    modules: list[ModuleType] = []
    seen: set[str] = set()
    for name in selected:
        path = next((path for cat, path in available_cats.items() if cat.lower() == name.lower()), None)
        if path is None:
            continue
        for module in engine.load_modules(path):
            key = getattr(module, "__file__", None) or module.__name__
            if key in seen:
                continue
            seen.add(key)
            modules.append(module)
    return modules


async def _check_one(module: ModuleType, target: str, configs: Any, semaphore: asyncio.Semaphore) -> Any:
    from user_scanner.core import engine

    async with semaphore:
        return await engine.check(module, target, configs)


async def _scan_target(
    target: str,
    *,
    is_email: bool,
    scan_depth: ScanDepth,
    configs: Any,
    concurrency: int,
) -> list[Any]:
    modules = _load_modules(is_email, _categories_for(scan_depth, is_email=is_email), no_nsfw=configs.no_nsfw)
    cap = _module_cap(scan_depth)
    if cap is not None:
        modules = modules[:cap]
    if not modules:
        return []
    semaphore = asyncio.Semaphore(max(concurrency, 1))
    return list(await asyncio.gather(*[_check_one(module, target, configs, semaphore) for module in modules]))


def _bundle_findings(findings: list[ProfileFinding]) -> list[ProfileFinding]:
    """Keep found/unknown/skipped; drop routine not-found noise from the bundle."""
    return [row for row in findings if row.status != "not_found"]


async def collect(
    *,
    emails: list[str],
    usernames: list[str],
    settings: Settings,
    scan_depth: ScanDepth = "standard",
    allow_loud: bool = False,
) -> CollectorResult:
    started = time.perf_counter()
    if not available():
        return skipped(NAME, "user-scanner not installed (pip install -e '.[people]')", started)
    if not emails and not usernames:
        return skipped(NAME, "no email or username seeds", started)

    loud_enabled = bool(settings.people_scan_allow_loud and allow_loud)
    try:
        from user_scanner.core.helpers import ScanConfig
    except Exception as exc:  # noqa: BLE001
        return failed(NAME, f"user-scanner import failed: {exc}", started)

    configs = ScanConfig(
        allow_loud=loud_enabled,
        no_nsfw=not settings.people_scan_include_nsfw,
        show_all=False,
        verbose=False,
        timeout=min(float(settings.http_timeout), 30.0),
    )
    findings: list[ProfileFinding] = []
    diagnostics = {
        "emails_scanned": 0,
        "usernames_scanned": 0,
        "found": 0,
        "not_found": 0,
        "unknown": 0,
        "skipped": 0,
        "allow_loud": loud_enabled,
        "scan_depth": scan_depth,
    }

    async def _run_all() -> None:
        for email in emails:
            diagnostics["emails_scanned"] += 1
            raw_rows = await _scan_target(
                email,
                is_email=True,
                scan_depth=scan_depth,
                configs=configs,
                concurrency=settings.people_scan_max_concurrency,
            )
            for raw in raw_rows:
                mapped = map_result(raw, seed=email, seed_type="email")
                if mapped is None:
                    continue
                findings.append(mapped)
                diagnostics[mapped.status] = diagnostics.get(mapped.status, 0) + 1
        for username in usernames:
            diagnostics["usernames_scanned"] += 1
            raw_rows = await _scan_target(
                username,
                is_email=False,
                scan_depth=scan_depth,
                configs=configs,
                concurrency=settings.people_scan_max_concurrency,
            )
            for raw in raw_rows:
                mapped = map_result(raw, seed=username, seed_type="username")
                if mapped is None:
                    continue
                findings.append(mapped)
                diagnostics[mapped.status] = diagnostics.get(mapped.status, 0) + 1

    try:
        await asyncio.wait_for(_run_all(), timeout=settings.people_scan_timeout)
    except TimeoutError:
        if findings:
            return CollectorResult(
                name=NAME,
                status="ok",
                records=len(_bundle_findings(findings)),
                error=f"timed out after {settings.people_scan_timeout}s",
                duration_ms=int((time.perf_counter() - started) * 1000),
                data={"findings": _bundle_findings(findings), "diagnostics": diagnostics},
            )
        return failed(NAME, f"timed out after {settings.people_scan_timeout}s", started)
    except Exception as exc:  # noqa: BLE001
        if findings:
            return CollectorResult(
                name=NAME,
                status="ok",
                records=len(_bundle_findings(findings)),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
                data={"findings": _bundle_findings(findings), "diagnostics": diagnostics},
            )
        return failed(NAME, str(exc), started)

    kept = _bundle_findings(findings)
    return CollectorResult(
        name=NAME,
        status="ok",
        records=len(kept),
        duration_ms=int((time.perf_counter() - started) * 1000),
        data={"findings": kept, "diagnostics": diagnostics},
    )
