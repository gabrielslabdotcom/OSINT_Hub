import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { StatusRail } from "../components/StatusRail";
import type { HubStatus, RunSummary } from "../types";

type AnalyzeChoice = "none" | "local" | "claude";

export function Launch() {
  const navigate = useNavigate();
  const [domain, setDomain] = useState("");
  const [analyze, setAnalyze] = useState<AnalyzeChoice>("none");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [status, setStatus] = useState<HubStatus | null>(null);
  const [listError, setListError] = useState<string | null>(null);

  useEffect(() => {
    api.runs().then((payload) => setRuns(payload.runs)).catch(() => setRuns([]));
    api.status().then(setStatus).catch(() => setStatus(null));
  }, []);

  async function refreshRuns() {
    const payload = await api.runs();
    setRuns(payload.runs);
  }

  async function removeRun(run: RunSummary) {
    const label = run.domain ?? run.run_id;
    if (!window.confirm(`Permanently delete dossier ${label}?\n${run.run_id}`)) return;
    setListError(null);
    try {
      await api.deleteRun(run.run_id);
      setRuns((current) => current.filter((item) => item.run_id !== run.run_id));
    } catch (err) {
      setListError(err instanceof Error ? err.message : "Could not delete dossier");
      try {
        await refreshRuns();
      } catch {
        /* keep optimistic list */
      }
    }
  }

  async function clearAll() {
    const count = runs.length;
    if (count === 0) return;
    if (
      !window.confirm(
        `Permanently delete ${count} dossier${count === 1 ? "" : "s"} from disk? This cannot be undone.`,
      )
    ) {
      return;
    }
    setListError(null);
    try {
      await api.deleteAllRuns();
      await refreshRuns();
    } catch (err) {
      setListError(err instanceof Error ? err.message : "Could not clear dossiers");
      try {
        await refreshRuns();
      } catch {
        /* keep current list */
      }
    }
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const target = domain.trim();
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const job = await api.investigate(target, analyze);
      navigate(`/jobs/${job.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start investigation");
      setBusy(false);
    }
  }

  const claude = status?.llm.claude;
  const claudeReady = Boolean(claude?.reachable);
  const claudeLabel = !claude?.configured
    ? "Analyze · Claude (no key)"
    : claudeReady
      ? "Analyze · Claude"
      : "Analyze · Claude (SDK missing)";
  const ollamaReady = Boolean(status?.llm.local?.reachable);

  return (
    <div className="grid gap-12 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.9fr)]">
      <section>
        <p className="stamp text-amber">Authorized targets only</p>
        <h1 className="mt-4 max-w-xl text-4xl font-medium leading-tight tracking-tight sm:text-5xl">
          Open a dossier.
        </h1>
        <p className="mt-4 max-w-xl text-sm leading-6 text-muted">
          Live DNS, certificate transparency, GitHub, Shodan, CISA KEV, and any optional
          collectors whose keys are set — then deterministic correlations. Empty keys skip.
          Keys stay in{" "}
          <span className="font-mono text-paper/80">.env</span>. This console never stores them.
        </p>

        <form onSubmit={onSubmit} className="mt-10">
          <label htmlFor="domain-input" className="stamp text-muted">
            Domain
          </label>
          <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-stretch">
            <input
              id="domain-input"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="corp.example"
              autoComplete="off"
              spellCheck={false}
              className="min-h-14 flex-1 border border-line bg-ink-2 px-4 font-mono text-xl text-paper outline-none placeholder:text-muted/40 focus:border-amber/70"
            />
            <button
              type="submit"
              disabled={busy || !domain.trim()}
              className="min-h-14 bg-amber px-8 font-medium text-ink transition hover:bg-amber-2 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Opening…" : "Investigate"}
            </button>
          </div>

          <fieldset className="mt-6">
            <legend className="stamp text-muted">After collection</legend>
            <div className="mt-3 flex flex-wrap gap-2">
              <AnalyzeToggle
                current={analyze}
                value="none"
                label="Report only"
                onChange={setAnalyze}
              />
              <AnalyzeToggle
                current={analyze}
                value="local"
                label={ollamaReady ? "Analyze · Ollama" : "Analyze · Ollama (offline)"}
                onChange={setAnalyze}
              />
              <AnalyzeToggle
                current={analyze}
                value="claude"
                label={claudeLabel}
                onChange={setAnalyze}
              />
            </div>
          </fieldset>
          {error && <p className="mt-4 text-sm text-rust">{error}</p>}
        </form>

        <div className="mt-10 border-t border-line pt-6">
          <p className="stamp text-muted">Collector readiness</p>
          <StatusRail />
          <p className="mt-3 text-xs text-muted">{status?.env_hint ?? "Set API keys in .env."}</p>
          <p className="mt-2 text-xs text-muted">⌘K jumps to a recent dossier.</p>
        </div>
      </section>

      <aside>
        <div className="flex items-baseline justify-between gap-3">
          <p className="stamp text-muted">Recent dossiers</p>
          <button
            type="button"
            disabled={runs.length === 0}
            onClick={() => void clearAll()}
            className="stamp text-muted hover:text-rust disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear all
          </button>
        </div>
        <ol className="mt-4 divide-y divide-line border border-line">
          {runs.length === 0 && (
            <li className="px-4 py-6 text-sm text-muted">No runs yet. Investigate a domain to start a case file.</li>
          )}
          {runs.slice(0, 12).map((run) => (
            <li key={run.run_id} className="flex items-stretch">
              <Link to={`/runs/${run.run_id}`} className="min-w-0 flex-1 px-4 py-3 hover:bg-ink-2">
                <p className="font-mono text-sm">{run.domain ?? run.run_id}</p>
                <p className="mt-1 font-mono text-[11px] text-muted">
                  {run.started_at ?? run.run_id}
                </p>
              </Link>
              <button
                type="button"
                aria-label={`Remove ${run.domain ?? run.run_id}`}
                onClick={() => void removeRun(run)}
                className="shrink-0 px-3 text-muted hover:bg-ink-2 hover:text-rust"
              >
                ×
              </button>
            </li>
          ))}
        </ol>
        {listError && <p className="mt-3 text-sm text-rust">{listError}</p>}
      </aside>
    </div>
  );
}

function AnalyzeToggle({
  current,
  value,
  label,
  onChange,
}: {
  current: AnalyzeChoice;
  value: AnalyzeChoice;
  label: string;
  onChange: (value: AnalyzeChoice) => void;
}) {
  const active = current === value;
  return (
    <button
      type="button"
      onClick={() => onChange(value)}
      className={`border px-3 py-1.5 text-xs ${
        active ? "border-amber text-amber" : "border-line text-muted hover:text-paper"
      }`}
    >
      {label}
    </button>
  );
}
