import type { Analysis } from "../types";
import { Empty } from "./DnsTable";

function rank(value: string): string {
  const lower = value.toLowerCase();
  if (lower === "high") return "text-rust";
  if (lower === "medium") return "text-amber";
  return "text-muted";
}

export function AnalysisBrief({
  analysis,
  provider,
}: {
  analysis: Analysis | null;
  provider: string;
}) {
  if (!analysis) {
    return (
      <Empty
        title={`No ${provider} analysis`}
        body="Send this dossier to Ollama (local) or Claude after the report is written. Models never see API keys from this console."
      />
    );
  }

  const vectors = [...(analysis.attack_vectors ?? [])].sort((a, b) => score(b) - score(a));

  return (
    <section className="space-y-8">
      <div>
        <h2 className="stamp text-teal">Analysis brief · {provider}</h2>
        <p className="mt-4 max-w-3xl text-[17px] leading-8 text-paper/90">{analysis.target_summary}</p>
        <div className="mt-4 flex flex-wrap gap-2">
          {(analysis.technology_stack ?? []).map((tech) => (
            <span key={tech} className="border border-line px-2 py-0.5 font-mono text-[11px] text-teal">
              {tech}
            </span>
          ))}
        </div>
      </div>

      <div>
        <h3 className="stamp text-muted">Ranked vectors</h3>
        <div className="mt-3 grid gap-3">
          {vectors.map((vector, index) => (
            <article key={`${vector.vector}-${index}`} className="border border-line bg-ink-2/50 p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="text-sm text-paper">
                  <span className="mr-2 font-mono text-amber">{String(index + 1).padStart(2, "0")}</span>
                  {vector.vector}
                </p>
                <p className="font-mono text-[11px]">
                  <span className={rank(vector.confidence)}>conf {vector.confidence}</span>
                  <span className="mx-2 text-line">/</span>
                  <span className={rank(vector.impact)}>impact {vector.impact}</span>
                </p>
              </div>
              <p className="mt-2 font-mono text-xs text-muted">{vector.target}</p>
              <p className="mt-3 text-sm leading-6 text-paper/85">{vector.rationale}</p>
              {vector.prerequisites && (
                <p className="mt-2 text-xs text-muted">Needs: {vector.prerequisites}</p>
              )}
            </article>
          ))}
        </div>
      </div>

      {(analysis.high_value_targets ?? []).length > 0 && (
        <div>
          <h3 className="stamp text-muted">High-value targets</h3>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {analysis.high_value_targets.map((target) => (
              <article key={`${target.name}-${target.type}`} className="border border-line p-4">
                <p className="text-sm">
                  {target.name} <span className="text-muted">({target.type})</span>
                </p>
                <p className="mt-2 text-sm text-paper/80">{target.value}</p>
                <p className="mt-2 text-xs text-muted">{target.access_potential}</p>
              </article>
            ))}
          </div>
        </div>
      )}

      {(analysis.exploitation_paths ?? []).length > 0 && (
        <div>
          <h3 className="stamp text-muted">Exploitation paths</h3>
          <p className="mt-2 max-w-3xl text-sm text-muted">
            Ordered actions against this run’s exact services. Playbook only — no payloads or exploit steps.
          </p>
          <div className="mt-3 grid gap-3">
            {(analysis.exploitation_paths ?? []).map((path, index) => (
              <article key={`${path.finding}-${index}`} className="border border-amber/30 bg-ink-2/50 p-4">
                <p className="text-sm text-paper">
                  <span className="mr-2 font-mono text-amber">{String(index + 1).padStart(2, "0")}</span>
                  {path.finding}
                </p>
                {path.attacker_goal && (
                  <p className="mt-2 text-sm text-paper/85">Goal: {path.attacker_goal}</p>
                )}
                <ol className="mt-3 list-decimal space-y-1 pl-5">
                  {(path.sequence ?? []).map((step) => (
                    <li key={step} className="text-sm leading-6 text-paper/80">
                      {step}
                    </li>
                  ))}
                </ol>
                {path.if_successful && (
                  <p className="mt-2 text-xs text-muted">If successful: {path.if_successful}</p>
                )}
                {path.defender_check && (
                  <p className="mt-1 text-xs text-muted">Defender check: {path.defender_check}</p>
                )}
              </article>
            ))}
          </div>
        </div>
      )}

      {(analysis.recommended_next_steps ?? []).length > 0 && (
        <div>
          <h3 className="stamp text-muted">Recommended next steps</h3>
          <ol className="mt-3 space-y-2">
            {analysis.recommended_next_steps.map((step, index) => (
              <li key={step} className="flex gap-3 text-sm leading-6">
                <span className="font-mono text-amber">{String(index + 1).padStart(2, "0")}</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}

function score(vector: { confidence: string; impact: string }): number {
  const rankMap: Record<string, number> = { high: 3, medium: 2, low: 1 };
  return (rankMap[vector.confidence?.toLowerCase()] ?? 0) + (rankMap[vector.impact?.toLowerCase()] ?? 0);
}
