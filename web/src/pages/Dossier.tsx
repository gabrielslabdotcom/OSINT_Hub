import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, subscribeJob } from "../api";
import { AnalysisBrief } from "../components/AnalysisBrief";
import { CertTimeline } from "../components/CertTimeline";
import { CollectorConstellation, statesFromEvents } from "../components/CollectorConstellation";
import { ComparePanel } from "../components/ComparePanel";
import { CorrelationThreads } from "../components/CorrelationThreads";
import { DnsTable } from "../components/DnsTable";
import { DossierHeader } from "../components/DossierHeader";
import { FindingCards } from "../components/FindingCards";
import { HostCards } from "../components/HostCards";
import { ExtraIntel } from "../components/ExtraIntel";
import { HotCveSection } from "../components/HotCveSection";
import { ReportView } from "../components/ReportView";
import { SurfaceChips } from "../components/SurfaceChips";
import { TargetList } from "../components/TargetList";
import type {
  Analysis,
  Bundle,
  CompareResult,
  Correlation,
  JobEvent,
  RunSummary,
  TargetRow,
} from "../types";

const SECTIONS = [
  { id: "surface", label: "Surface" },
  { id: "dns", label: "DNS" },
  { id: "certs", label: "Certs" },
  { id: "github", label: "GitHub" },
  { id: "shodan", label: "Shodan" },
  { id: "hotcves", label: "Hot CVEs" },
  { id: "intel", label: "Intel" },
  { id: "threads", label: "Threads" },
  { id: "report", label: "Report" },
  { id: "analysis", label: "Analysis" },
  { id: "targets", label: "Targets" },
  { id: "compare", label: "Compare" },
];

export function Dossier() {
  const { runId } = useParams();
  const [run, setRun] = useState<RunSummary | null>(null);
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [localAnalysis, setLocalAnalysis] = useState<Analysis | null>(null);
  const [claudeAnalysis, setClaudeAnalysis] = useState<Analysis | null>(null);
  const [analysisTab, setAnalysisTab] = useState<"local" | "claude">("local");
  const [targets, setTargets] = useState<TargetRow[] | null>(null);
  const [diff, setDiff] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [liveEvents, setLiveEvents] = useState<JobEvent[]>([]);

  const load = useCallback(async (id: string) => {
    const summary = await api.run(id);
    setRun(summary);
    if (summary.artifacts.bundle) setBundle(await api.bundle(id));
    if (summary.artifacts.correlations) {
      setCorrelations(await api.correlations(id));
    } else {
      setCorrelations([]);
    }
    if (summary.artifacts.report) {
      setMarkdown((await api.report(id)).markdown);
    } else {
      setMarkdown(null);
    }
    if (summary.artifacts.analysis_local) {
      setLocalAnalysis(await api.analysis(id, "local"));
    } else {
      setLocalAnalysis(null);
    }
    if (summary.artifacts.analysis_claude) {
      setClaudeAnalysis(await api.analysis(id, "claude"));
    } else {
      setClaudeAnalysis(null);
    }
    if (summary.artifacts.analysis_claude) setAnalysisTab("claude");
    else if (summary.artifacts.analysis_local) setAnalysisTab("local");
    if (summary.artifacts.targets) setTargets(await api.targets(id));
    else setTargets(null);
    if (summary.artifacts.analysis_local && summary.artifacts.analysis_claude) {
      setDiff(await api.compare(id));
    } else {
      setDiff(null);
    }
  }, []);

  useEffect(() => {
    if (!runId) return;
    setError(null);
    load(runId).catch((err) => setError(err instanceof Error ? err.message : "Failed to load dossier"));
  }, [runId, load]);

  async function withBusy(label: string, work: () => Promise<void>) {
    setBusy(label);
    setNotice(null);
    setError(null);
    try {
      await work();
      if (runId) await load(runId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  async function runAnalyze(provider: "local" | "claude") {
    if (!runId) return;
    setBusy(`analyze-${provider}`);
    setError(null);
    setNotice(`Sending dossier to ${provider}…`);
    try {
      const job = await api.analyze(runId, provider);
      const stop = subscribeJob(job.job_id, (event) => {
        setLiveEvents((current) => [...current, event]);
        if (event.stage === "job" && event.status === "completed") {
          stop();
          setBusy(null);
          setNotice(`${provider} analysis complete`);
          void load(runId);
        }
        if (event.stage === "job" && event.status === "failed") {
          stop();
          setBusy(null);
          setError(event.message);
        }
      });
    } catch (err) {
      setBusy(null);
      setError(err instanceof Error ? err.message : "Analyze failed");
    }
  }

  const githubSkipped = run?.collectors.find((row) => row.name === "github")?.status === "skipped";
  const shodanSkipped = run?.collectors.find((row) => row.name === "shodan")?.status === "skipped";
  const liveStates = useMemo(() => statesFromEvents(liveEvents), [liveEvents]);

  if (error && !run) {
    return (
      <div>
        <p className="text-rust">{error}</p>
        <Link to="/" className="mt-4 inline-block stamp text-amber">
          Back to launch
        </Link>
      </div>
    );
  }

  if (!run) {
    return <p className="stamp text-muted">Loading dossier…</p>;
  }

  return (
    <div className="space-y-10">
      <DossierHeader run={run} />

      <div className="flex flex-wrap gap-2">
        <Action
          label={busy === "report" ? "Writing…" : "Generate report"}
          disabled={Boolean(busy)}
          onClick={() => withBusy("report", async () => { await api.generateReport(run.run_id); })}
        />
        <Action
          label={busy === "analyze-local" ? "Analyzing…" : "Analyze · local"}
          disabled={Boolean(busy)}
          onClick={() => runAnalyze("local")}
        />
        <Action
          label={busy === "analyze-claude" ? "Analyzing…" : "Analyze · Claude"}
          disabled={Boolean(busy)}
          onClick={() => runAnalyze("claude")}
        />
        <Action
          label={busy === "targets" ? "Ranking…" : "Build targets"}
          disabled={Boolean(busy)}
          onClick={() => withBusy("targets", async () => { await api.buildTargets(run.run_id); })}
        />
      </div>
      {notice && <p className="text-sm text-teal">{notice}</p>}
      {error && <p className="text-sm text-rust">{error}</p>}

      {busy?.startsWith("analyze") && (
        <CollectorConstellation
          domain={run.domain ?? run.run_id}
          states={liveStates}
          caption="Waiting on the model. Collection nodes stay idle during analysis."
        />
      )}

      <nav className="sticky top-0 z-20 -mx-2 flex flex-wrap gap-1 border-b border-line bg-ink/90 px-2 py-2 backdrop-blur">
        {SECTIONS.map((section) => (
          <a
            key={section.id}
            href={`#${section.id}`}
            className="stamp px-2 py-1 text-muted hover:text-paper"
          >
            {section.label}
          </a>
        ))}
      </nav>

      {bundle ? (
        <>
          <div id="surface">
            <SurfaceChips bundle={bundle} />
          </div>
          <div id="dns">
            <DnsTable records={bundle.dns_records} />
          </div>
          <div id="certs">
            <CertTimeline certs={bundle.certificates} />
          </div>
          <div id="github">
            <FindingCards findings={bundle.github_findings} skipped={githubSkipped} />
          </div>
          <div id="shodan">
            <HostCards
              hosts={bundle.hosts}
              skipped={shodanSkipped}
              hotCveIds={(bundle.hot_cves ?? [])
                .filter((hit) => hit.confidence === "confirmed" || (!hit.confidence && hit.source === "shodan"))
                .map((hit) => hit.cve_id)}
            />
          </div>
          <div id="hotcves">
            <HotCveSection matches={bundle.hot_cves ?? []} shodanSkipped={shodanSkipped} />
          </div>
          <div id="intel">
            <ExtraIntel bundle={bundle} />
          </div>
        </>
      ) : (
        <p className="text-sm text-muted">Bundle not written yet.</p>
      )}

      <div id="threads">
        <CorrelationThreads correlations={correlations} />
      </div>
      <div id="report">
        <ReportView markdown={markdown} />
      </div>
      <div id="analysis">
        <div className="mb-4 flex gap-2">
          <Action
            label="Local"
            active={analysisTab === "local"}
            onClick={() => setAnalysisTab("local")}
          />
          <Action
            label="Claude"
            active={analysisTab === "claude"}
            onClick={() => setAnalysisTab("claude")}
          />
        </div>
        <AnalysisBrief
          provider={analysisTab}
          analysis={analysisTab === "claude" ? claudeAnalysis : localAnalysis}
        />
      </div>
      <div id="targets">
        <TargetList targets={targets} />
      </div>
      <div id="compare">
        <ComparePanel diff={diff} />
      </div>
    </div>
  );
}

function Action({
  label,
  onClick,
  disabled,
  active,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  active?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`border px-3 py-1.5 text-xs ${
        active ? "border-amber text-amber" : "border-line text-muted hover:text-paper"
      } disabled:opacity-40`}
    >
      {label}
    </button>
  );
}
