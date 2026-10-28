import type { TargetRow } from "../types";
import { Empty } from "./DnsTable";

function rankClass(value: string): string {
  const lower = value.toLowerCase();
  if (lower === "high") return "text-rust";
  if (lower === "medium") return "text-amber";
  return "text-muted";
}

export function TargetList({ targets }: { targets: TargetRow[] | null }) {
  if (!targets || targets.length === 0) {
    return (
      <Empty
        title="No target list"
        body="Build targets after an analysis JSON exists. The ranking uses confidence + impact from the LLM brief."
      />
    );
  }

  return (
    <section>
      <h2 className="stamp text-teal">Prioritized targets</h2>
      <div className="mt-4 overflow-x-auto border border-line">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="bg-ink-3">
            <tr className="stamp text-muted">
              <th className="px-3 py-2 font-medium">#</th>
              <th className="px-3 py-2 font-medium">Vector</th>
              <th className="px-3 py-2 font-medium">Target</th>
              <th className="px-3 py-2 font-medium">Conf</th>
              <th className="px-3 py-2 font-medium">Impact</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((row) => (
              <tr key={`${row.priority}-${row.vector}`} className="border-t border-line/80 align-top">
                <td className="px-3 py-2 font-mono text-amber">{row.priority}</td>
                <td className="px-3 py-2">
                  <p>{row.vector}</p>
                  <p className="mt-1 text-xs text-muted">{row.rationale}</p>
                  {row.next_action && (
                    <p className="mt-1 text-xs text-amber/80">Next: {row.next_action}</p>
                  )}
                </td>
                <td className="px-3 py-2 font-mono text-xs">{row.target}</td>
                <td className={`px-3 py-2 font-mono text-xs ${rankClass(row.confidence)}`}>
                  {row.confidence}
                </td>
                <td className={`px-3 py-2 font-mono text-xs ${rankClass(row.impact)}`}>{row.impact}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
