import DOMPurify from "dompurify";
import { marked } from "marked";
import { useMemo } from "react";
import { Empty } from "./DnsTable";

marked.use({
  renderer: {
    html() {
      return "";
    },
  },
});

export function ReportView({ markdown }: { markdown: string | null }) {
  const html = useMemo(() => {
    if (!markdown) return "";
    const raw = marked.parse(markdown, { async: false }) as string;
    return DOMPurify.sanitize(raw, { USE_PROFILES: { html: true } });
  }, [markdown]);

  if (!markdown) {
    return (
      <Empty
        title="Report not written yet"
        body="Generate the markdown report to lock in correlations for this dossier."
      />
    );
  }

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="stamp text-teal">Report</h2>
        <a
          href={`data:text/markdown;charset=utf-8,${encodeURIComponent(markdown)}`}
          download="report.md"
          className="stamp text-muted hover:text-paper"
        >
          Download
        </a>
      </div>
      <article className="report-md border border-line bg-ink-2/40 p-5" dangerouslySetInnerHTML={{ __html: html }} />
    </section>
  );
}
