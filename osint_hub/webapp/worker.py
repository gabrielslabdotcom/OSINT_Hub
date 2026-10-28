"""Execute queued investigate / analyze jobs against the existing pipeline."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from osint_hub.analyze import analyze_run
from osint_hub.config import default_runs_dir, load_settings
from osint_hub.pipeline import collect_domain, load_bundle
from osint_hub.report import write_report
from osint_hub.target_list import build_target_list
from osint_hub.webapp.runs import resolve_run_id

if TYPE_CHECKING:
    from osint_hub.webapp.jobs import Job, JobRunner


async def execute_job(runner: JobRunner, job: Job) -> None:
    if job.kind == "investigate":
        await _investigate(runner, job)
        return
    if job.kind == "analyze":
        await _analyze(runner, job)
        return
    raise ValueError(f"Unknown job kind {job.kind!r}")


async def _investigate(runner: JobRunner, job: Job) -> None:
    if not job.domain:
        raise ValueError("Investigate job is missing a domain")
    settings = load_settings()

    async def on_progress(event: dict) -> None:
        await runner.emit(job, event)

    ctx = await collect_domain(
        job.domain,
        settings,
        out_dir=default_runs_dir(),
        on_progress=on_progress,
    )
    job.run_id = ctx.run_dir.name
    job.domain = ctx.domain
    await runner.emit(
        job,
        {
            "stage": "report",
            "collector": None,
            "status": "running",
            "message": "Writing correlations and report…",
            "run_id": job.run_id,
        },
    )
    _path, _corr_path, correlations = await asyncio.to_thread(write_report, ctx.run_dir, ctx.bundle)
    await runner.emit(
        job,
        {
            "stage": "report",
            "collector": None,
            "status": "ok",
            "message": f"Wrote report ({len(correlations)} correlations)",
            "run_id": job.run_id,
            "records": len(correlations),
        },
    )
    if job.analyze in {"local", "claude"}:
        await _run_analysis(runner, job, ctx.run_dir, ctx.bundle, settings, job.analyze)
        await asyncio.to_thread(build_target_list, ctx.run_dir)
        await runner.emit(
            job,
            {
                "stage": "targets",
                "collector": None,
                "status": "ok",
                "message": "Wrote target list",
                "run_id": job.run_id,
            },
        )


async def _analyze(runner: JobRunner, job: Job) -> None:
    if not job.run_id or not job.provider:
        raise ValueError("Analyze job is missing run_id or provider")
    settings = load_settings()
    run_dir = resolve_run_id(job.run_id)
    bundle = load_bundle(run_dir)
    if not (run_dir / "report.md").is_file():
        await asyncio.to_thread(write_report, run_dir, bundle)
    await _run_analysis(runner, job, run_dir, bundle, settings, job.provider)


async def _run_analysis(runner: JobRunner, job: Job, run_dir, bundle, settings, provider: str) -> None:
    await runner.emit(
        job,
        {
            "stage": "analyze",
            "collector": None,
            "status": "running",
            "message": f"Sending dossier to {provider}…",
            "run_id": run_dir.name,
            "provider": provider,
        },
    )
    result = await asyncio.to_thread(analyze_run, run_dir, bundle, settings, provider)
    if not result:
        raise RuntimeError(
            f"LLM JSON parse failed for {provider}. Inspect raw_response.txt in the run directory."
        )
    await runner.emit(
        job,
        {
            "stage": "analyze",
            "collector": None,
            "status": "ok",
            "message": f"Analysis saved ({provider})",
            "run_id": run_dir.name,
            "provider": provider,
        },
    )
