"""In-memory job queue for collection and analysis (single-operator, local)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

from osint_hub.util import iso_now

JobKind = Literal["investigate", "analyze"]
JobStatus = Literal["queued", "running", "completed", "failed"]
AnalyzeChoice = Literal["none", "local", "claude"]

MAX_ACTIVE_JOBS = 4
MAX_RETAINED_JOBS = 40


class JobBusyError(RuntimeError):
    """Raised when too many investigate/analyze jobs are already in flight."""


@dataclass
class Job:
    id: str
    kind: JobKind
    status: JobStatus
    domain: str | None = None
    run_id: str | None = None
    analyze: AnalyzeChoice = "none"
    provider: str | None = None
    error: str | None = None
    created_at: str = field(default_factory=iso_now)
    finished_at: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    waiters: list[asyncio.Queue[dict[str, Any] | None]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "kind": self.kind,
            "status": self.status,
            "domain": self.domain,
            "run_id": self.run_id,
            "analyze": self.analyze,
            "provider": self.provider,
            "error": self.error,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "events": list(self.events),
        }


class JobRunner:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run_worker(), name="osint-hub-jobs")

    def _active_count(self) -> int:
        return sum(1 for job in self.jobs.values() if job.status in {"queued", "running"})

    def _prune(self) -> None:
        finished = [
            job
            for job in self.jobs.values()
            if job.status in {"completed", "failed"} and not job.waiters
        ]
        finished.sort(key=lambda job: job.finished_at or job.created_at)
        while len(self.jobs) > MAX_RETAINED_JOBS and finished:
            old = finished.pop(0)
            self.jobs.pop(old.id, None)

    def _enqueue(self, job: Job) -> None:
        if self._active_count() >= MAX_ACTIVE_JOBS:
            raise JobBusyError("Too many jobs in flight — wait for the current investigation to finish.")
        self._prune()
        self.jobs[job.id] = job

    async def submit_investigate(self, domain: str, analyze: AnalyzeChoice) -> Job:
        job = Job(
            id=str(uuid.uuid4()),
            kind="investigate",
            status="queued",
            domain=domain,
            analyze=analyze,
        )
        self._enqueue(job)
        await self._queue.put(job.id)
        return job

    async def submit_analyze(self, run_id: str, provider: str) -> Job:
        job = Job(
            id=str(uuid.uuid4()),
            kind="analyze",
            status="queued",
            run_id=run_id,
            provider=provider,
            analyze="none",
        )
        self._enqueue(job)
        await self._queue.put(job.id)
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    async def emit(self, job: Job, event: dict[str, Any]) -> None:
        payload = {"ts": iso_now(), **event}
        if job.run_id is None and payload.get("run_id"):
            job.run_id = str(payload["run_id"])
        if job.domain is None and payload.get("domain"):
            job.domain = str(payload["domain"])
        job.events.append(payload)
        for waiter in list(job.waiters):
            await waiter.put(payload)

    async def subscribe(self, job: Job) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        for event in job.events:
            await queue.put(event)
        job.waiters.append(queue)
        if job.status in {"completed", "failed"}:
            await queue.put(None)
        try:
            while True:
                item = await queue.get()
                if item is None:
                    return
                yield item
        finally:
            if queue in job.waiters:
                job.waiters.remove(queue)

    async def _finish(self, job: Job, status: JobStatus, error: str | None = None) -> None:
        job.status = status
        job.error = error
        job.finished_at = iso_now()
        closing = {
            "stage": "job",
            "collector": None,
            "status": status,
            "message": error or f"Job {status}",
            "run_id": job.run_id,
            "domain": job.domain,
        }
        await self.emit(job, closing)
        for waiter in list(job.waiters):
            await waiter.put(None)
        self._prune()

    async def _run_worker(self) -> None:
        from osint_hub.webapp.worker import execute_job

        while True:
            job_id = await self._queue.get()
            job = self.jobs.get(job_id)
            if job is None:
                continue
            job.status = "running"
            try:
                await execute_job(self, job)
                await self._finish(job, "completed")
            except Exception as exc:  # noqa: BLE001 — surface any pipeline failure to the UI
                await self._finish(job, "failed", error=str(exc))
