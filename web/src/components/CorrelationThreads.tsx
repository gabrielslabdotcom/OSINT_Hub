import type { Correlation } from "../types";
import { Empty } from "./DnsTable";

export function CorrelationThreads({ correlations }: { correlations: Correlation[] }) {
  if (correlations.length === 0) {
    return (
      <Empty
        title="No correlations fired"
        body="Deterministic joins need overlapping DNS, CT, GitHub, or Shodan evidence. Generate a report after collectors finish."
      />
    );
  }

  return (
    <section>
      <h2 className="stamp text-teal">Correlation threads</h2>
      <p className="mt-2 text-sm text-muted">Rule-based joins computed before any LLM runs.</p>
      <ol className="mt-5 space-y-5">
        {correlations.map((row, index) => (
          <li key={`${row.relationship}-${index}`} className="flex gap-4">
            <div className="flex w-6 flex-col items-center">
              <span className="stamp text-amber">{String(index + 1).padStart(2, "0")}</span>
              <span className="mt-1 w-px flex-1 bg-line" />
            </div>
            <div className="flex-1 border border-line bg-ink-2/50 p-4">
              <div className="flex flex-wrap gap-2">
                {row.data_points.map((point) => (
                  <span key={point} className="border border-amber/30 px-2 py-0.5 font-mono text-[11px] text-amber">
                    {point}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-sm leading-6 text-paper/90">{row.relationship}</p>
              <p className="mt-2 text-sm italic text-muted">{row.offensive_relevance}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
