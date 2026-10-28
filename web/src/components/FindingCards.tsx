import type { RepoFinding } from "../types";
import { Empty } from "./DnsTable";

export function FindingCards({
  findings,
  skipped,
}: {
  findings: RepoFinding[];
  skipped?: boolean;
}) {
  if (findings.length === 0) {
    return (
      <Empty
        title="No GitHub exposure"
        body={
          skipped
            ? "GitHub skipped — add GITHUB_TOKEN to .env and rerun."
            : "Code search returned no hits for this domain."
        }
      />
    );
  }

  return (
    <section>
      <h2 className="stamp text-teal">GitHub exposure</h2>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {findings.map((finding) => (
          <article key={finding.entity_id} className="border border-line bg-ink-2/60 p-4">
            <p className="font-mono text-sm text-amber">{finding.repo}</p>
            <p className="mt-1 font-mono text-xs text-muted">{finding.file}</p>
            <pre className="mt-3 overflow-x-auto whitespace-pre-wrap font-mono text-[12px] leading-5 text-paper/80">
              {finding.match}
            </pre>
            <div className="mt-3 flex items-center justify-between text-xs text-muted">
              <span>{finding.author ?? "unknown author"}</span>
              {finding.url && (
                <a
                  href={finding.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-teal hover:underline"
                >
                  Open
                </a>
              )}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
