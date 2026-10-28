import { useMemo, useState } from "react";
import type { DnsRecord } from "../types";
import { Ioc } from "./Ioc";

export function DnsTable({ records }: { records: DnsRecord[] }) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return records;
    return records.filter(
      (row) =>
        row.name.toLowerCase().includes(needle) ||
        row.value.toLowerCase().includes(needle) ||
        row.rtype.toLowerCase().includes(needle),
    );
  }, [query, records]);

  if (records.length === 0) {
    return <Empty title="No DNS records" body="The DNS collector returned nothing for this target." />;
  }

  return (
    <section>
      <div className="mb-3 flex items-end justify-between gap-4">
        <h2 className="stamp text-teal">DNS</h2>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter name, type, value"
          className="w-56 border-b border-line bg-transparent pb-1 font-mono text-xs text-paper outline-none placeholder:text-muted/60"
        />
      </div>
      <div className="overflow-x-auto border border-line">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="bg-ink-3 text-muted">
            <tr className="stamp">
              <th className="px-3 py-2 font-medium">Type</th>
              <th className="px-3 py-2 font-medium">Name</th>
              <th className="px-3 py-2 font-medium">Value</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={row.entity_id} className="border-t border-line/80">
                <td className="px-3 py-2 font-mono text-amber">{row.rtype}</td>
                <td className="px-3 py-2">
                  <Ioc value={row.name} />
                </td>
                <td className="px-3 py-2">
                  <Ioc value={row.value} />
                  {row.priority != null && (
                    <span className="ml-2 text-xs text-muted">pri {row.priority}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function Empty({ title, body }: { title: string; body: string }) {
  return (
    <div className="border border-dashed border-line px-4 py-6">
      <p className="stamp text-muted">{title}</p>
      <p className="mt-2 max-w-xl text-sm text-muted">{body}</p>
    </div>
  );
}
