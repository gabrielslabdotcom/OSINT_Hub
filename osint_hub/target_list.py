"""Prioritized target list from LLM analysis JSON (lab Step 5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from osint_hub.util import read_json, write_json

console = Console()
RANK_MAP = {"high": 3, "medium": 2, "low": 1}


def load_best_analysis(run_dir: Path) -> tuple[str, dict[str, Any]]:
    for provider in ("claude", "local"):
        path = run_dir / f"analysis_{provider}.json"
        if path.is_file():
            console.print(f"[dim]Using {provider} analysis[/dim]")
            return provider, read_json(path)
    raise FileNotFoundError("No analysis_*.json found. Run `osint-hub analyze` first.")


def build_target_list(run_dir: Path) -> Path:
    _provider, analysis = load_best_analysis(run_dir)
    vectors = list(analysis.get("attack_vectors", []))
    vectors.sort(
        key=lambda v: RANK_MAP.get(v.get("confidence", "low"), 0) + RANK_MAP.get(v.get("impact", "low"), 0),
        reverse=True,
    )

    table = Table(title=f"Prioritized Target List — {run_dir.name}")
    table.add_column("#", justify="right", style="bold")
    table.add_column("Attack Vector")
    table.add_column("Target")
    table.add_column("Confidence", justify="center")
    table.add_column("Impact", justify="center")
    table.add_column("Score", justify="center")

    paths = list(analysis.get("exploitation_paths") or [])

    def _path_for(vector: dict[str, Any]) -> dict[str, Any]:
        target = str(vector.get("target") or "").lower()
        for path in paths:
            blob = f"{path.get('finding') or ''} {' '.join(path.get('entity_ids') or [])}".lower()
            if target and target in blob:
                return path
        return {}

    export: list[dict[str, Any]] = []
    for index, vector in enumerate(vectors, 1):
        confidence = vector.get("confidence", "low")
        impact = vector.get("impact", "low")
        score = RANK_MAP.get(confidence, 0) + RANK_MAP.get(impact, 0)
        conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(confidence, "white")
        imp_color = {"high": "green", "medium": "yellow", "low": "red"}.get(impact, "white")
        table.add_row(
            str(index),
            str(vector.get("vector", "")),
            str(vector.get("target", "")),
            f"[{conf_color}]{confidence}[/{conf_color}]",
            f"[{imp_color}]{impact}[/{imp_color}]",
            str(score),
        )
        path = _path_for(vector) or (paths[index - 1] if index - 1 < len(paths) else {})
        seq = path.get("sequence") or []
        export.append(
            {
                "priority": index,
                "vector": vector.get("vector"),
                "target": vector.get("target"),
                "confidence": confidence,
                "impact": impact,
                "rationale": vector.get("rationale"),
                "finding": path.get("finding") or vector.get("target"),
                "next_action": seq[0] if seq else None,
            }
        )

    console.print(table)
    export_path = run_dir / "target_list.json"
    write_json(export_path, export)
    console.print(f"\n[green]Target list exported to {export_path}[/green]")
    bundle_path = run_dir / "bundle.json"
    if bundle_path.is_file():
        from osint_hub.phase2 import write_phase2
        from osint_hub.pipeline import load_bundle

        write_phase2(run_dir, load_bundle(run_dir))
    return export_path
