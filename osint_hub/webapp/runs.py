"""Filesystem helpers for listing and resolving local run directories."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from osint_hub.config import default_runs_dir
from osint_hub.util import read_json, resolve_run_dir

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")


def _runs_root() -> Path:
    return default_runs_dir().expanduser().resolve()


def _is_listed_run_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    return (path / "manifest.json").is_file() or (path / "bundle.json").is_file()


def _assert_under_runs_root(run_dir: Path) -> None:
    root = _runs_root()
    if run_dir == root or not run_dir.is_relative_to(root):
        raise FileNotFoundError(f"Run not found: {run_dir.name}")


def _validate_run_id(run_id: str) -> None:
    if not RUN_ID_RE.fullmatch(run_id) or ".." in run_id or "/" in run_id or "\\" in run_id:
        raise FileNotFoundError(f"Run not found: {run_id}")


def artifacts_for(run_dir: Path) -> dict[str, bool]:
    return {
        "bundle": (run_dir / "bundle.json").is_file(),
        "manifest": (run_dir / "manifest.json").is_file(),
        "report": (run_dir / "report.md").is_file(),
        "correlations": (run_dir / "correlations.json").is_file(),
        "analysis_local": (run_dir / "analysis_local.json").is_file(),
        "analysis_claude": (run_dir / "analysis_claude.json").is_file(),
        "targets": (run_dir / "target_list.json").is_file(),
        "phase2": (run_dir / "phase2.json").is_file(),
        "raw_response": (run_dir / "raw_response.txt").is_file(),
    }


def collector_counts(manifest: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in manifest.get("collectors") or []:
        name = row.get("name")
        if name:
            counts[str(name)] = int(row.get("records") or 0)
    return counts


def summarize_run(run_dir: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    if manifest is None and (run_dir / "manifest.json").is_file():
        manifest = read_json(run_dir / "manifest.json")
    manifest = manifest or {}
    return {
        "run_id": run_dir.name,
        "domain": manifest.get("domain"),
        "started_at": manifest.get("started_at"),
        "finished_at": manifest.get("finished_at"),
        "collectors": manifest.get("collectors") or [],
        "counts": collector_counts(manifest),
        "artifacts": artifacts_for(run_dir),
    }


def list_runs() -> list[dict[str, Any]]:
    root = default_runs_dir()
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), reverse=True):
        if not _is_listed_run_dir(path):
            continue
        items.append(summarize_run(path))
    items.sort(key=lambda row: str(row.get("started_at") or row["run_id"]), reverse=True)
    return items


def resolve_run_id(run_id: str) -> Path:
    _validate_run_id(run_id)
    return resolve_run_dir(default_runs_dir() / run_id)


def delete_run(run_id: str) -> None:
    _validate_run_id(run_id)
    run_dir = (_runs_root() / run_id).resolve()
    _assert_under_runs_root(run_dir)
    if not _is_listed_run_dir(run_dir):
        raise FileNotFoundError(f"Run not found: {run_id}")
    shutil.rmtree(run_dir)


def delete_all_runs() -> int:
    root = default_runs_dir()
    if not root.is_dir():
        return 0
    deleted = 0
    for path in list(root.iterdir()):
        resolved = path.resolve()
        try:
            _assert_under_runs_root(resolved)
        except FileNotFoundError:
            continue
        if not _is_listed_run_dir(resolved):
            continue
        shutil.rmtree(resolved)
        deleted += 1
    return deleted
