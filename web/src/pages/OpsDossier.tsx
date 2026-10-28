import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { DossierHeader } from "../components/DossierHeader";
import { Empty } from "../components/DnsTable";
import { Ioc } from "../components/Ioc";
import type { Phase2Dossier, Phase2Person, Phase2Service, Phase2Task, RunSummary } from "../types";

const CATEGORY: Record<string, string> = {
  kev_confirmed: "CISA KEV",
  shodan_cve: "Shodan CVE",
  high_value: "High-value surface",
  tls: "TLS issue",
  kev_suspected: "Suspected KEV overlap",
};

export function OpsDossier() {
  const { runId } = useParams();
  const [run, setRun] = useState<RunSummary | null>(null);
  const [dossier, setDossier] = useState<Phase2Dossier | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);

  const load = useCallback(async (id: string) => {
    const summary = await api.run(id);
    const next = summary.artifacts.phase2 ? await api.phase2(id) : null;
    setRun(summary);
    setDossier(next);
    setReady(true);
  }, []);

  useEffect(() => {
    if (!runId) return;
    setError(null);
    load(runId).catch((err) => setError(err instanceof Error ? err.message : "Failed to load dossier"));
  }, [runId, load]);

  async function rebuild() {
    if (!runId) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.buildPhase2(runId);
      setDossier(payload.phase2);
      await load(runId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Build failed");
    } finally {
      setBusy(false);
    }
  }

  async function toggleTask(task: Phase2Task) {
    if (!runId) return;
    const next = task.status === "done" ? "open" : "done";
    try {
      setDossier(await api.patchPhase2Task(runId, task.id, next));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update task");
    }
  }

  if (error && !run) {
    return (
      <div>
        <p className="text-rust">{error}</p>
        <Link to="/" className="mt-4 inline-block stamp text-amber">
          Back to launch
        </Link>
      </div>
    );
  }

  if (!run || !ready) {
    return <p className="stamp text-muted">Loading high-value dossier…</p>;
  }

  return (
    <div className="space-y-10">
      <DossierHeader run={run} />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void rebuild()}
          disabled={busy}
          className="border border-line px-3 py-1.5 text-xs text-muted hover:text-paper disabled:opacity-40"
        >
          {busy ? "Building…" : dossier ? "Rebuild high-value dossier" : "Build high-value dossier"}
        </button>
        {error && <p className="text-sm text-rust">{error}</p>}
      </div>

      {!dossier ? (
        <Empty
          title="No high-value dossier yet"
          body="Generate a report on the Evidence tab, or build it here. This view turns Shodan, mail-auth, and public mailboxes into verification tasks — no exploit PoCs."
        />
      ) : (
        <>
          <MailPosture dossier={dossier} />
          <TaskBoard tasks={dossier.tasks} onToggle={toggleTask} />
          <ServiceGrid services={dossier.services} />
          <PeopleGrid people={dossier.people} spoofable={dossier.mail_posture.spoofable} />
        </>
      )}
    </div>
  );
}

function MailPosture({ dossier }: { dossier: Phase2Dossier }) {
  const mail = dossier.mail_posture;
  return (
    <section>
      <h2 className="stamp text-teal">Mail posture</h2>
      <article className={`mt-3 border p-4 ${mail.spoofable ? "border-amber/40 bg-ink-2/50" : "border-line"}`}>
        <p className="font-mono text-xs text-muted">
          SPF {mail.spf ? "present" : "missing"} · DMARC p={mail.dmarc_policy} · {mail.mailbox_count}{" "}
          {mail.mailbox_count === 1 ? "mailbox" : "mailboxes"}
        </p>
        {mail.providers.length > 0 && (
          <p className="mt-2 font-mono text-xs text-muted">{mail.providers.join(" · ")}</p>
        )}
        <p className="mt-3 text-sm leading-6 text-paper/85">{mail.note}</p>
      </article>
    </section>
  );
}

function TaskBoard({
  tasks,
  onToggle,
}: {
  tasks: Phase2Task[];
  onToggle: (task: Phase2Task) => void;
}) {
  if (tasks.length === 0) {
    return (
      <Empty
        title="No tasks"
        body="No attributed Shodan surfaces, mail-auth issues, or public mailboxes were strong enough to queue work."
      />
    );
  }
  const open = tasks.filter((task) => task.status !== "done").length;
  return (
    <section>
      <h2 className="stamp text-teal">Task board</h2>
      <p className="mt-2 font-mono text-xs text-muted">
        {open} open · {tasks.length - open} done
      </p>
      <div className="mt-3 grid gap-2">
        {tasks.map((task) => (
          <label
            key={task.id}
            className={`flex cursor-pointer gap-3 border p-3 ${
              task.status === "done" ? "border-line/60 opacity-60" : "border-line bg-ink-2/40"
            }`}
          >
            <input
              type="checkbox"
              checked={task.status === "done"}
              onChange={() => onToggle(task)}
              className="mt-1"
            />
            <span>
              <span className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-[11px] text-amber">{String(task.priority).padStart(2, "0")}</span>
                <span className="text-sm text-paper">{task.title}</span>
                <span className="stamp text-muted">{task.kind.replace("_", " ")}</span>
              </span>
              <span className="mt-1 block text-sm text-paper/80">{task.why}</span>
              {task.next_action && (
                <span className="mt-1 block text-xs text-amber/80">Next: {task.next_action}</span>
              )}
            </span>
          </label>
        ))}
      </div>
    </section>
  );
}

function ServiceGrid({ services }: { services: Phase2Service[] }) {
  if (services.length === 0) {
    return (
      <Empty
        title="No exposed-service cards"
        body="Shodan skipped, returned nothing attributed, or no KEV/CVE/admin/TLS signal crossed the ranking threshold."
      />
    );
  }
  return (
    <section>
      <h2 className="stamp text-teal">Exposed services</h2>
      <p className="mt-2 max-w-3xl text-sm text-muted">
        Observed evidence plus public advisories. Confirm patch and exposure — this console does not generate exploit PoCs.
      </p>
      <div className="mt-4 grid gap-3">
        {services.map((card) => (
          <article key={`${card.ip}:${card.port}:${card.rank}`} className="border border-line bg-ink-2/50 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="text-sm text-paper">
                <span className="mr-2 font-mono text-amber">{String(card.rank).padStart(2, "0")}</span>
                <Ioc value={card.ip} className="text-amber" />:{card.port}/{card.transport || "tcp"}
              </p>
              <p className="stamp text-muted">{CATEGORY[card.category] || card.category}</p>
            </div>
            <p className="mt-2 font-mono text-xs text-muted">
              {[card.product, card.version, card.title, card.server].filter(Boolean).join(" · ")}
            </p>
            {card.hostnames.length > 0 && (
              <p className="mt-1 font-mono text-xs text-muted">{card.hostnames.join(" · ")}</p>
            )}
            <div className="mt-2 flex flex-wrap gap-1.5">
              {card.tags.map((tag) => (
                <span key={tag} className="rounded-full border border-line px-2 py-0.5 font-mono text-[11px] text-muted">
                  {tag}
                </span>
              ))}
              {card.ssl_expired && (
                <span className="rounded-full border border-rust/50 px-2 py-0.5 font-mono text-[11px] text-rust">
                  cert expired
                </span>
              )}
              {card.ssl_self_signed && (
                <span className="rounded-full border border-amber/50 px-2 py-0.5 font-mono text-[11px] text-amber">
                  self-signed
                </span>
              )}
            </div>
            {card.cves.length > 0 && (
              <p className="mt-2 font-mono text-xs text-muted">
                {card.cves.map((cve, index) => (
                  <span key={cve}>
                    {index > 0 ? " · " : ""}
                    <a className="text-teal hover:text-paper" href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">
                      {cve}
                    </a>
                  </span>
                ))}
              </p>
            )}
            {card.kev.map((hit) => (
              <p key={hit.cve_id} className="mt-2 text-sm leading-6 text-paper/85">
                <span className="font-mono text-xs text-rust">{hit.cve_id}</span> {hit.name}
                {hit.required_action ? ` — ${hit.required_action}` : ""}
                {hit.short_description ? ` ${hit.short_description}` : ""}
              </p>
            ))}
            {card.evidence && <p className="mt-2 text-xs text-muted">{card.evidence}</p>}
            {card.defender_check && (
              <p className="mt-2 text-xs text-muted">Defender check: {card.defender_check}</p>
            )}
            <ol className="mt-3 list-decimal space-y-1 pl-5">
              {card.tasks.map((step) => (
                <li key={step} className="text-sm leading-6 text-paper/80">
                  {step}
                </li>
              ))}
            </ol>
            {(card.last_seen || card.location) && (
              <p className="mt-2 font-mono text-[11px] text-muted">
                {[card.last_seen ? `seen ${card.last_seen.slice(0, 10)}` : "", card.location].filter(Boolean).join(" · ")}
              </p>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

function PeopleGrid({ people, spoofable }: { people: Phase2Person[]; spoofable: boolean }) {
  if (people.length === 0) {
    return (
      <Empty
        title="No people cards"
        body="Hunter and Tomba skip when their keys are empty, and free plans return at most 10 addresses per domain."
      />
    );
  }
  const withPhone = people.filter((person) => person.phone).length;
  return (
    <section>
      <h2 className="stamp text-teal">People</h2>
      <p className="mt-2 max-w-3xl text-sm text-muted">
        Public mailbox OSINT ranked by role, breach membership, and mail-auth risk.
        {` ${withPhone}/${people.length} mailboxes include a phone (domain-search + optional enrichment).`}
        {spoofable ? " DMARC does not reject spoofing — treat identities as spoofable, not as a phish list." : ""}
      </p>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {people.map((person) => (
          <article key={person.email} className="border border-line p-4">
            <p className="text-sm text-paper">
              <span className="mr-2 font-mono text-amber">{String(person.rank).padStart(2, "0")}</span>
              {person.full_name}
            </p>
            <p className="mt-1 font-mono text-xs">
              <Ioc value={person.email} className="text-teal" />
            </p>
            <p className="mt-2 font-mono text-xs text-muted">
              {[person.position, person.department, person.seniority, person.source].filter(Boolean).join(" · ")}
            </p>
            {person.phone && (
              <p className="mt-1 font-mono text-xs">
                <Ioc value={person.phone} />
              </p>
            )}
            {person.linkedin && (
              <p className="mt-1 truncate font-mono text-xs text-muted">{person.linkedin}</p>
            )}
            {person.breaches.length > 0 && (
              <p className="mt-2 text-xs text-amber">HIBP: {person.breaches.join(", ")}</p>
            )}
            <p className="mt-2 text-sm text-paper/80">{person.why}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
