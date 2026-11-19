import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { StatusRail } from "../components/StatusRail";
import type { HubStatus, InvestigationMode, RunSummary, ScanDepth } from "../types";

type AnalyzeChoice = "none" | "local" | "claude";

function splitLines(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function Launch() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<InvestigationMode>("domain");
  const [domain, setDomain] = useState("");
  const [emails, setEmails] = useState("");
  const [usernames, setUsernames] = useState("");
  const [scanDepth, setScanDepth] = useState<ScanDepth>("standard");
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

  const peopleReady = Boolean(status?.collectors?.user_scanner?.configured);
  const needsPeople = mode === "people" || mode === "both";
  const needsDomain = mode === "domain" || mode === "both";
  const canSubmit = useMemo(() => {
    if (busy) return false;
    if (needsDomain && !domain.trim()) return false;
    if (mode === "people" && !splitLines(emails).length && !splitLines(usernames).length) return false;
    if (needsPeople && !peopleReady) return false;
    return true;
  }, [busy, domain, emails, usernames, mode, needsDomain, needsPeople, peopleReady]);

  async function refreshRuns() {
    const payload = await api.runs();
    setRuns(payload.runs);
  }

  async function removeRun(run: RunSummary) {
    const label = run.target_label ?? run.domain ?? run.run_id;
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
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const analyzeChoice = mode === "people" ? "none" : analyze;
      const job = await api.investigate({
        mode,
        domain: domain.trim() || undefined,
        emails: splitLines(emails),
        usernames: splitLines(usernames),
        scan_depth: scanDepth,
        analyze: analyzeChoice,
      });
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
          Choose domain infrastructure intel, people OSINT via User Scanner, or both. Empty API keys
          skip. Keys stay in <span className="font-mono text-paper/80">.env</span>.
        </p>

        <form onSubmit={onSubmit} className="mt-10">
          <fieldset>
            <legend className="stamp text-muted">Investigation mode</legend>
            <div className="mt-3 flex flex-wrap gap-2">
              <ModeToggle current={mode} value="domain" label="Domain" onChange={setMode} />
              <ModeToggle current={mode} value="people" label="People" onChange={setMode} />
              <ModeToggle current={mode} value="both" label="Both" onChange={setMode} />
            </div>
          </fieldset>

          {needsDomain && (
            <div className="mt-6">
              <label htmlFor="domain-input" className="stamp text-muted">
                Domain
              </label>
              <input
                id="domain-input"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="corp.example"
                autoComplete="off"
                spellCheck={false}
                className="mt-3 min-h-14 w-full border border-line bg-ink-2 px-4 font-mono text-xl text-paper outline-none placeholder:text-muted/40 focus:border-amber/70"
              />
            </div>
          )}

          {needsPeople && (
            <div className="mt-6 grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="emails-input" className="stamp text-muted">
                  Emails
                </label>
                <textarea
                  id="emails-input"
                  value={emails}
                  onChange={(event) => setEmails(event.target.value)}
                  placeholder={"alice@corp.example\nbob@corp.example"}
                  rows={4}
                  className="mt-3 w-full border border-line bg-ink-2 px-4 py-3 font-mono text-sm text-paper outline-none placeholder:text-muted/40 focus:border-amber/70"
                />
              </div>
              <div>
                <label htmlFor="usernames-input" className="stamp text-muted">
                  Usernames
                </label>
                <textarea
                  id="usernames-input"
                  value={usernames}
                  onChange={(event) => setUsernames(event.target.value)}
                  placeholder={"alice\nbob.smith"}
                  rows={4}
                  className="mt-3 w-full border border-line bg-ink-2 px-4 py-3 font-mono text-sm text-paper outline-none placeholder:text-muted/40 focus:border-amber/70"
                />
              </div>
              {!peopleReady && (
                <p className="sm:col-span-2 text-sm text-amber">
                  User Scanner is not installed. Run{" "}
                  <span className="font-mono text-paper/80">pip install -e &quot;.[web,people]&quot;</span>.
                </p>
              )}
            </div>
          )}

          {needsPeople && (
            <fieldset className="mt-6">
              <legend className="stamp text-muted">Scan depth</legend>
              <div className="mt-3 flex flex-wrap gap-2">
                <DepthToggle current={scanDepth} value="quick" label="Quick" onChange={setScanDepth} />
                <DepthToggle current={scanDepth} value="standard" label="Standard" onChange={setScanDepth} />
                <DepthToggle current={scanDepth} value="full" label="Full" onChange={setScanDepth} />
              </div>
              {scanDepth === "full" && (
                <p className="mt-3 text-xs text-amber">
                  Full depth probes many platforms and can take several minutes with more false positives.
                </p>
              )}
            </fieldset>
          )}

          <div className="mt-6">
            <button
              type="submit"
              disabled={!canSubmit}
              className="min-h-14 bg-amber px-8 font-medium text-ink transition hover:bg-amber-2 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Opening…" : "Investigate"}
            </button>
          </div>

          {mode !== "people" && (
            <fieldset className="mt-6">
              <legend className="stamp text-muted">After collection</legend>
              <div className="mt-3 flex flex-wrap gap-2">
                <AnalyzeToggle current={analyze} value="none" label="Report only" onChange={setAnalyze} />
                <AnalyzeToggle
                  current={analyze}
                  value="local"
                  label={ollamaReady ? "Analyze · Ollama" : "Analyze · Ollama (offline)"}
                  onChange={setAnalyze}
                />
                <AnalyzeToggle current={analyze} value="claude" label={claudeLabel} onChange={setAnalyze} />
              </div>
            </fieldset>
          )}
          {mode === "people" && (
            <p className="mt-4 text-xs text-muted">LLM analysis is disabled for people-only runs in this release.</p>
          )}
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
            <li className="px-4 py-6 text-sm text-muted">No runs yet. Investigate a domain or person to start a case file.</li>
          )}
          {runs.slice(0, 12).map((run) => (
            <li key={run.run_id} className="flex items-stretch">
              <Link to={`/runs/${run.run_id}`} className="min-w-0 flex-1 px-4 py-3 hover:bg-ink-2">
                <p className="font-mono text-sm">{run.target_label ?? run.domain ?? run.run_id}</p>
                <p className="mt-1 font-mono text-[11px] text-muted">
                  {(run.mode ?? "domain") + " · "}
                  {run.started_at ?? run.run_id}
                </p>
              </Link>
              <button
                type="button"
                aria-label={`Remove ${run.target_label ?? run.domain ?? run.run_id}`}
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

function ModeToggle({
  current,
  value,
  label,
  onChange,
}: {
  current: InvestigationMode;
  value: InvestigationMode;
  label: string;
  onChange: (value: InvestigationMode) => void;
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

function DepthToggle({
  current,
  value,
  label,
  onChange,
}: {
  current: ScanDepth;
  value: ScanDepth;
  label: string;
  onChange: (value: ScanDepth) => void;
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
