import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import type { RunSummary } from "../types";

function pillTone(status: string): string {
  if (status === "ok") return "border-ok/40 text-ok";
  if (status === "skipped") return "border-amber/40 text-amber";
  if (status === "error") return "border-rust/40 text-rust";
  return "border-line text-muted";
}

export function DossierHeader({ run }: { run: RunSummary }) {
  const location = useLocation();
  const navigate = useNavigate();
  const ops = location.pathname.endsWith("/ops");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onDelete() {
    const label = run.domain ?? run.run_id;
    if (!window.confirm(`Permanently delete dossier ${label}?\n${run.run_id}`)) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteRun(run.run_id);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete dossier");
      setBusy(false);
    }
  }

  return (
    <div className="border border-line bg-ink-2/70 px-6 py-5">
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <p className="stamp text-amber">Dossier</p>
        <nav className="flex gap-2">
          <Link
            to={`/runs/${run.run_id}`}
            className={`border px-3 py-1 text-xs ${
              ops ? "border-line text-muted hover:text-paper" : "border-amber text-amber"
            }`}
          >
            Evidence
          </Link>
          <Link
            to={`/runs/${run.run_id}/ops`}
            className={`border px-3 py-1 text-xs ${
              ops ? "border-amber text-amber" : "border-line text-muted hover:text-paper"
            }`}
          >
            High-value
          </Link>
          <button
            type="button"
            disabled={busy}
            onClick={() => void onDelete()}
            className="border border-line px-3 py-1 text-xs text-muted hover:border-rust/60 hover:text-rust disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "Deleting…" : "Delete dossier"}
          </button>
        </nav>
      </div>
      <h1 className="mt-2 font-mono text-3xl tracking-tight text-paper sm:text-4xl">
        {run.domain ?? run.run_id}
      </h1>
      <p className="mt-2 font-mono text-xs text-muted">
        {run.run_id}
        {run.started_at ? ` · collected ${run.started_at}` : ""}
      </p>
      {error && <p className="mt-2 text-sm text-rust">{error}</p>}
      <div className="mt-4 flex flex-wrap gap-2">
        {run.collectors.map((row) => (
          <span
            key={row.name}
            className={`rounded-full border px-2.5 py-0.5 font-mono text-[11px] ${pillTone(row.status)}`}
            title={row.error ?? undefined}
          >
            {row.name} {row.status}
            {row.records ? ` · ${row.records}` : ""}
          </span>
        ))}
      </div>
    </div>
  );
}
