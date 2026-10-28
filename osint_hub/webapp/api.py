"""JSON API for the investigation console. Never returns secret material."""

from __future__ import annotations

import json
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from osint_hub import __version__
from osint_hub.analyze import diff_analyses
from osint_hub.config import Settings, load_settings
from osint_hub.llm import claude_sdk_available
from osint_hub.pipeline import load_bundle
from osint_hub.phase2 import patch_task, write_phase2
from osint_hub.report import write_report
from osint_hub.target_list import build_target_list
from osint_hub.util import dump_model, normalize_domain, read_json
from osint_hub.webapp.jobs import JobBusyError, JobRunner
from osint_hub.webapp.runs import artifacts_for, delete_all_runs, delete_run, list_runs, resolve_run_id, summarize_run

router = APIRouter()

AnalyzeChoice = Literal["none", "local", "claude"]
ProviderChoice = Literal["local", "claude"]


class InvestigateBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    analyze: AnalyzeChoice = "none"


class AnalyzeBody(BaseModel):
    provider: ProviderChoice = "local"


class Phase2TaskBody(BaseModel):
    task_id: str = Field(min_length=1, max_length=200)
    status: Literal["open", "done"]


def _runner(request: Request) -> JobRunner:
    return request.app.state.jobs


def _job_or_404(request: Request, job_id: str):
    job = _runner(request).get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _run_dir(run_id: str):
    try:
        return resolve_run_id(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Run not found") from exc


def _probe_ollama(settings: Settings) -> bool:
    try:
        with httpx.Client(timeout=1.5) as client:
            response = client.get(
                f"{settings.ollama_base_url.rstrip('/')}/api/tags",
                headers=settings.ollama_headers(),
            )
            return response.status_code < 500
    except httpx.HTTPError:
        return False


@router.get("/status")
def status() -> dict[str, Any]:
    settings = load_settings()
    return {
        "version": __version__,
        "collectors": {
            "dns": {"configured": True, "needs_key": False, "label": "DNS"},
            "crtsh": {"configured": True, "needs_key": False, "label": "crt.sh"},
            "github": {"configured": settings.has_github, "needs_key": True, "label": "GitHub"},
            "shodan": {"configured": settings.has_shodan, "needs_key": True, "label": "Shodan"},
            "kev": {"configured": True, "needs_key": False, "label": "CISA KEV"},
            "securitytrails": {"configured": settings.has_securitytrails, "needs_key": True, "label": "SecurityTrails"},
            "pdcp": {"configured": settings.has_pdcp, "needs_key": True, "label": "PDCP/Chaos"},
            "virustotal": {"configured": settings.has_virustotal, "needs_key": True, "label": "VirusTotal"},
            "censys": {"configured": settings.has_censys, "needs_key": True, "label": "Censys"},
            "hunter": {"configured": settings.has_hunter, "needs_key": True, "label": "Hunter"},
            "tomba": {"configured": settings.has_tomba, "needs_key": True, "label": "Tomba"},
            "phone_enrich": {
                "configured": settings.has_hunter or settings.has_tomba,
                "needs_key": True,
                "label": "Phone enrich",
            },
            "urlscan": {"configured": settings.has_urlscan, "needs_key": True, "label": "URLScan"},
            "leakix": {"configured": settings.has_leakix, "needs_key": True, "label": "LeakIX"},
            "ipinfo": {"configured": settings.has_ipinfo, "needs_key": True, "label": "IPinfo"},
            "greynoise": {"configured": settings.has_greynoise, "needs_key": True, "label": "GreyNoise"},
            "abuseipdb": {"configured": settings.has_abuseipdb, "needs_key": True, "label": "AbuseIPDB"},
            "hibp": {"configured": settings.has_hibp, "needs_key": True, "label": "HIBP"},
        },
        "llm": {
            "local": {
                "configured": True,
                "reachable": _probe_ollama(settings),
                "model": settings.ollama_model,
                "label": "Ollama",
            },
            "claude": {
                "configured": settings.has_claude,
                "reachable": settings.has_claude and claude_sdk_available(),
                "model": settings.anthropic_model if settings.has_claude else None,
                "label": "Claude",
            },
        },
        "env_hint": "Set API keys in .env — the console never stores them.",
    }


@router.get("/runs")
def get_runs() -> dict[str, Any]:
    return {"runs": list_runs()}


@router.post("/runs", status_code=202)
async def start_run(body: InvestigateBody, request: Request) -> dict[str, Any]:
    try:
        domain = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        job = await _runner(request).submit_investigate(domain, body.analyze)
    except JobBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return job.snapshot()


@router.delete("/runs")
def delete_runs() -> dict[str, Any]:
    try:
        deleted = delete_all_runs()
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not delete run directories") from exc
    return {"ok": True, "deleted": deleted}


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    summary = summarize_run(run_dir)
    if (run_dir / "bundle.json").is_file():
        bundle = load_bundle(run_dir)
        summary["counts"] = {
            **(summary.get("counts") or {}),
            "dns": len(bundle.dns_records),
            "crtsh": len(bundle.certificates),
            "github": len(bundle.github_findings),
            "shodan": sum(len(host.services) for host in bundle.hosts),
            "kev": len(bundle.hot_cves),
            "hosts": len(bundle.hosts),
            "hostnames": len(bundle.discovered_hostnames),
            "hot_cves": len(bundle.hot_cves),
            "emails": len(bundle.emails),
            "breaches": len(bundle.breaches),
            "url_scans": len(bundle.url_scans),
            "leaks": len(bundle.leaks),
            "ip_intel": len(bundle.ip_intel),
        }
    return summary


@router.delete("/runs/{run_id}")
def delete_one_run(run_id: str) -> dict[str, Any]:
    try:
        delete_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Run not found") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not delete run directory") from exc
    return {"ok": True, "run_id": run_id}


@router.get("/runs/{run_id}/bundle")
def get_bundle(run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    try:
        return dump_model(load_bundle(run_dir))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="bundle.json not found") from exc


@router.get("/runs/{run_id}/correlations")
def get_correlations(run_id: str) -> Any:
    run_dir = _run_dir(run_id)
    path = run_dir / "correlations.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="correlations.json not found — generate a report first")
    return read_json(path)


@router.get("/runs/{run_id}/report")
def get_report(run_id: str) -> dict[str, str]:
    run_dir = _run_dir(run_id)
    path = run_dir / "report.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="report.md not found — generate a report first")
    return {"markdown": path.read_text(encoding="utf-8")}


@router.get("/runs/{run_id}/analysis/{provider}")
def get_analysis(run_id: str, provider: ProviderChoice) -> Any:
    run_dir = _run_dir(run_id)
    path = run_dir / f"analysis_{provider}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"analysis_{provider}.json not found")
    return read_json(path)


@router.get("/runs/{run_id}/targets")
def get_targets(run_id: str) -> Any:
    run_dir = _run_dir(run_id)
    path = run_dir / "target_list.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="target_list.json not found")
    return read_json(path)


@router.get("/runs/{run_id}/compare")
def get_compare(run_id: str) -> Any:
    run_dir = _run_dir(run_id)
    try:
        return diff_analyses(run_dir)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Compare artifacts not found") from exc


@router.post("/runs/{run_id}/report")
def post_report(run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    try:
        bundle = load_bundle(run_dir)
        _report, _corr, correlations = write_report(run_dir, bundle)
        return {"ok": True, "correlations": len(correlations), "artifacts": artifacts_for(run_dir)}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="bundle.json not found") from exc


@router.post("/runs/{run_id}/analyze", status_code=202)
async def post_analyze(run_id: str, body: AnalyzeBody, request: Request) -> dict[str, Any]:
    _run_dir(run_id)
    try:
        job = await _runner(request).submit_analyze(run_id, body.provider)
    except JobBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return job.snapshot()


@router.get("/runs/{run_id}/phase2")
def get_phase2(run_id: str) -> Any:
    run_dir = _run_dir(run_id)
    path = run_dir / "phase2.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="phase2.json not found — generate a report first")
    return read_json(path)


@router.post("/runs/{run_id}/phase2")
def post_phase2(run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    try:
        bundle = load_bundle(run_dir)
        path = write_phase2(run_dir, bundle)
        return {"ok": True, "path": path.name, "phase2": read_json(path), "artifacts": artifacts_for(run_dir)}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="bundle.json not found") from exc


@router.patch("/runs/{run_id}/phase2")
def patch_phase2(run_id: str, body: Phase2TaskBody) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    try:
        dossier = patch_task(run_dir, body.task_id, body.status)
        return dump_model(dossier)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="phase2.json not found — generate a report first") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/runs/{run_id}/targets")
def post_targets(run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    try:
        path = build_target_list(run_dir)
        return {"ok": True, "path": path.name, "targets": read_json(path)}
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="No analysis JSON yet — run Analyze · local or Analyze · Claude first.",
        ) from exc


@router.get("/jobs/{job_id}")
def get_job(job_id: str, request: Request) -> dict[str, Any]:
    return _job_or_404(request, job_id).snapshot()


@router.get("/jobs/{job_id}/events")
async def job_events(job_id: str, request: Request) -> StreamingResponse:
    job = _job_or_404(request, job_id)
    runner = _runner(request)

    async def gen():
        async for event in runner.subscribe(job):
            yield f"data: {json.dumps(event, default=str)}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/jobs")
def list_jobs(request: Request) -> dict[str, Any]:
    jobs = sorted(_runner(request).jobs.values(), key=lambda job: job.created_at, reverse=True)
    return {"jobs": [job.snapshot() for job in jobs[:40]]}
