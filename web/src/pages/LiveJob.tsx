import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, subscribeJob } from "../api";
import { CollectorConstellation, statesFromEvents } from "../components/CollectorConstellation";
import type { JobEvent, JobSnapshot } from "../types";

export function LiveJob() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState<JobSnapshot | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let disposed = false;
    api
      .job(jobId)
      .then((snapshot) => {
        if (disposed) return;
        setJob(snapshot);
        if (snapshot.status === "completed" && snapshot.run_id) {
          navigate(`/runs/${snapshot.run_id}`, { replace: true });
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Job not found"));

    const stop = subscribeJob(jobId, (event) => {
      setEvents((current) => [...current, event]);
      if (event.run_id) {
        setJob((current) =>
          current ? { ...current, run_id: event.run_id ?? current.run_id, domain: event.domain ?? current.domain } : current,
        );
      }
      if (event.stage === "job" && event.status === "completed") {
        const runId = event.run_id;
        if (runId) navigate(`/runs/${runId}`, { replace: true });
      }
      if (event.stage === "job" && event.status === "failed") {
        setError(event.message || "Investigation failed");
      }
    });
    return () => {
      disposed = true;
      stop();
    };
  }, [jobId, navigate]);

  const states = useMemo(() => statesFromEvents(events), [events]);
  const latest = events.at(-1);
  const domain = job?.domain ?? latest?.domain ?? "target";

  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="stamp text-amber">Live collection</p>
      <h1 className="mt-3 font-mono text-3xl">{domain}</h1>
      <p className="mt-2 text-sm text-muted">
        {latest?.message ?? "Queued behind any in-flight investigation…"}
      </p>
      <div className="mt-8">
        <CollectorConstellation domain={domain} states={states} caption={job?.run_id ?? undefined} />
      </div>
      <ol className="mt-6 max-h-48 overflow-auto border border-line bg-ink-2/40 px-4 py-3 text-left">
        {events.map((event, index) => (
          <li key={`${event.ts}-${index}`} className="font-mono text-[11px] leading-6 text-muted">
            <span className="text-amber">{event.stage}</span>
            <span className="mx-2 text-line">·</span>
            {event.message}
          </li>
        ))}
      </ol>
      {error && (
        <p className="mt-6 text-sm text-rust">
          {error}{" "}
          {job?.run_id && (
            <Link className="text-amber underline" to={`/runs/${job.run_id}`}>
              Open partial dossier
            </Link>
          )}
        </p>
      )}
    </div>
  );
}
