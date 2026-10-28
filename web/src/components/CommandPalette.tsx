import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import type { RunSummary } from "../types";

export function CommandPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [runs, setRuns] = useState<RunSummary[]>([]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) return;
    api
      .runs()
      .then((payload) => setRuns(payload.runs))
      .catch(() => setRuns([]));
    setQuery("");
  }, [open]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return runs.slice(0, 8);
    return runs
      .filter(
        (run) =>
          run.run_id.toLowerCase().includes(needle) ||
          (run.domain ?? "").toLowerCase().includes(needle),
      )
      .slice(0, 8);
  }, [query, runs]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-start justify-center bg-ink/70 px-4 pt-[18vh] backdrop-blur-sm"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg border border-line bg-ink-2 shadow-[0_24px_80px_rgba(0,0,0,0.45)]"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="border-b border-line px-4 py-3">
          <p className="stamp text-muted">Jump to dossier</p>
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Domain or run id"
            className="mt-2 w-full bg-transparent font-mono text-sm text-paper outline-none placeholder:text-muted/60"
          />
        </div>
        <ul className="max-h-72 overflow-auto py-2">
          <li>
            <button
              type="button"
              className="flex w-full items-center justify-between px-4 py-2 text-left text-sm hover:bg-ink-3"
              onClick={() => {
                setOpen(false);
                navigate("/");
                window.setTimeout(() => document.getElementById("domain-input")?.focus(), 40);
              }}
            >
              <span>New investigation</span>
              <span className="stamp text-muted">Launch</span>
            </button>
          </li>
          {filtered.map((run) => (
            <li key={run.run_id}>
              <button
                type="button"
                className="flex w-full items-center justify-between gap-3 px-4 py-2 text-left hover:bg-ink-3"
                onClick={() => {
                  setOpen(false);
                  navigate(`/runs/${run.run_id}`);
                }}
              >
                <span className="font-mono text-sm">{run.domain ?? run.run_id}</span>
                <span className="font-mono text-[11px] text-muted">{run.started_at ?? run.run_id}</span>
              </button>
            </li>
          ))}
          {filtered.length === 0 && (
            <li className="px-4 py-3 text-sm text-muted">No matching dossiers.</li>
          )}
        </ul>
      </div>
    </div>
  );
}
