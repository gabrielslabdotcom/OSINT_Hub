import { useEffect, useState } from "react";
import { api } from "../api";
import type { HubStatus } from "../types";

function Pill({
  label,
  ok,
  hint,
}: {
  label: string;
  ok: boolean;
  hint: string;
}) {
  return (
    <span
      title={hint}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${
        ok ? "border-teal/30 text-teal" : "border-line text-muted"
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-teal" : "bg-muted/50"}`} />
      {label}
    </span>
  );
}

export function StatusRail({ compact = false }: { compact?: boolean }) {
  const [status, setStatus] = useState<HubStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .status()
      .then((value) => {
        if (!cancelled) setStatus(value);
      })
      .catch(() => {
        if (!cancelled) setStatus(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!status) {
    return <span className="stamp text-muted">keys in .env</span>;
  }

  const github = status.collectors.github;
  const shodan = status.collectors.shodan;
  const ollama = status.llm.local;
  const claude = status.llm.claude;
  const extras = Object.entries(status.collectors).filter(
    ([name, row]) => !["dns", "crtsh", "github", "shodan", "kev"].includes(name) && row.needs_key,
  );

  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${compact ? "" : "mt-3"}`}>
      <Pill
        label="GitHub"
        ok={Boolean(github?.configured)}
        hint={github?.configured ? "GITHUB_TOKEN is set" : "Add GITHUB_TOKEN to .env"}
      />
      <Pill
        label="Shodan"
        ok={Boolean(shodan?.configured)}
        hint={shodan?.configured ? "SHODAN_API_KEY is set" : "Add SHODAN_API_KEY to .env"}
      />
      {extras.map(([name, row]) => (
        <Pill
          key={name}
          label={row.label}
          ok={Boolean(row.configured)}
          hint={row.configured ? `${row.label} key is set` : `Add the ${row.label} key to .env`}
        />
      ))}
      <Pill
        label="Ollama"
        ok={Boolean(ollama?.reachable)}
        hint={
          ollama?.reachable
            ? `Reachable (${ollama.model ?? "local"})`
            : "Ollama not reachable — check OLLAMA_BASE_URL and OLLAMA_API_KEY"
        }
      />
      <Pill
        label="Claude"
        ok={Boolean(claude?.reachable)}
        hint={
          !claude?.configured
            ? "Add ANTHROPIC_API_KEY to .env"
            : claude?.reachable
              ? "ANTHROPIC_API_KEY is set"
              : "Install the Anthropic SDK: pip install -e '.[web]'"
        }
      />
    </div>
  );
}
