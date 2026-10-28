import type { CompareResult } from "../types";
import { Empty } from "./DnsTable";

export function ComparePanel({ diff }: { diff: CompareResult | null }) {
  if (!diff) {
    return (
      <Empty
        title="Nothing to compare"
        body="Run both local and Claude analysis on this dossier to diff attack-vector names."
      />
    );
  }

  return (
    <section>
      <h2 className="stamp text-teal">Local vs Claude</h2>
      <div className="mt-4 overflow-x-auto border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-ink-3 stamp text-muted">
            <tr>
              <th className="px-3 py-2 font-medium">Metric</th>
              <th className="px-3 py-2 font-medium">Local</th>
              <th className="px-3 py-2 font-medium">Claude</th>
            </tr>
          </thead>
          <tbody>
            {diff.metrics.map((row) => (
              <tr key={row.name} className="border-t border-line/80">
                <td className="px-3 py-2">{row.name}</td>
                <td className="px-3 py-2 font-mono">{row.local}</td>
                <td className="px-3 py-2 font-mono">{row.claude}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <VectorColumn title="Local only" items={diff.local_only} />
        <VectorColumn title="Both" items={diff.both} accent />
        <VectorColumn title="Claude only" items={diff.claude_only} />
      </div>
    </section>
  );
}

function VectorColumn({
  title,
  items,
  accent = false,
}: {
  title: string;
  items: string[];
  accent?: boolean;
}) {
  return (
    <div className="border border-line p-3">
      <p className={`stamp ${accent ? "text-teal" : "text-muted"}`}>{title}</p>
      <ul className="mt-3 space-y-1.5">
        {items.length === 0 && <li className="text-xs text-muted">None</li>}
        {items.map((item) => (
          <li key={item} className="text-sm leading-5">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
