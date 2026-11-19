import type { Bundle, ProfileFinding } from "../types";
import { Empty } from "./DnsTable";
import { Ioc } from "./Ioc";

function groupBySeed(rows: ProfileFinding[]): Map<string, ProfileFinding[]> {
  const groups = new Map<string, ProfileFinding[]>();
  for (const row of rows) {
    const key = `${row.seed_type}:${row.seed}`;
    const current = groups.get(key) ?? [];
    current.push(row);
    groups.set(key, current);
  }
  return groups;
}

export function PeopleIntel({ bundle }: { bundle: Bundle }) {
  const findings = (bundle.profile_findings ?? []).filter((row) => row.status !== "not_found");
  if (findings.length === 0) {
    return (
      <Empty
        title="No people OSINT"
        body="Install the people extra (pip install -e '.[web,people]') and launch a people or both investigation with email or username seeds."
      />
    );
  }

  const groups = groupBySeed(findings);
  return (
    <div className="space-y-8">
      <section>
        <h2 className="stamp text-teal">People OSINT</h2>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          Account-existence leads from User Scanner. Treat matches as leads to verify — not confirmed identity.
        </p>
        <div className="mt-4 space-y-5">
          {[...groups.entries()].map(([seed, rows]) => (
            <div key={seed} className="border border-line p-4">
              <p className="font-mono text-xs text-amber">{seed}</p>
              <ul className="mt-3 space-y-1">
                {rows.map((row) => (
                  <li key={row.entity_id} className="font-mono text-xs text-muted">
                    <span className="text-paper">{row.platform}</span>
                    {" · "}
                    <span className={row.status === "found" ? "text-ok" : "text-amber"}>{row.status}</span>
                    {row.category ? ` · ${row.category}` : ""}
                    {row.url ? (
                      <>
                        {" · "}
                        <Ioc value={row.url} className="text-teal" />
                      </>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
