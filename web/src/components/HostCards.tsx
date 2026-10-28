import type { Host } from "../types";
import { Empty } from "./DnsTable";
import { Ioc } from "./Ioc";

export function HostCards({
  hosts,
  skipped,
  hotCveIds,
}: {
  hosts: Host[];
  skipped?: boolean;
  hotCveIds?: string[];
}) {
  const attributed = hosts.filter((host) => (host.in_scope ?? true) && host.services.length > 0);
  const shared = hosts.filter((host) => !(host.in_scope ?? true) || host.services.length === 0);
  const kev = new Set((hotCveIds ?? []).map((cve) => cve.toUpperCase()));

  if (attributed.length === 0) {
    return (
      <section className="space-y-4">
        <Empty
          title="No internet-facing services"
          body={
            skipped
              ? "Shodan skipped — add SHODAN_API_KEY to .env and rerun."
              : shared.length
                ? "Resolved IPs look like shared/CDN addresses. Off-tenant banners were not attributed to this domain."
                : "Shodan returned no hosts for the resolved IPs."
          }
        />
        {shared.length > 0 && <SharedIps hosts={shared} />}
      </section>
    );
  }

  return (
    <section>
      <h2 className="stamp text-teal">Internet-facing services</h2>
      <div className="mt-4 space-y-4">
        {attributed.map((host) => (
          <article key={host.entity_id} className="border border-line bg-ink-2/60 p-4">
            <div className="flex flex-wrap items-baseline gap-3">
              <Ioc value={host.ip} className="text-amber text-sm" />
              {host.hostnames.map((name) => (
                <Ioc key={name} value={name} className="text-muted" />
              ))}
              {(host.org || host.asn) && (
                <span className="stamp text-muted">
                  {[host.org, host.asn].filter(Boolean).join(" · ")}
                </span>
              )}
              {host.last_update ? (
                <span className="stamp text-muted">seen {host.last_update.slice(0, 10)}</span>
              ) : null}
            </div>
            {(host.tags ?? []).length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {(host.tags ?? []).map((tag) => (
                  <span key={tag} className="rounded-full border border-line px-2 py-0.5 font-mono text-[11px] text-muted">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {(host.vulns ?? []).length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {(host.vulns ?? []).map((cve) => {
                  const hot = kev.has(cve.toUpperCase());
                  return (
                    <span
                      key={cve}
                      className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${
                        hot ? "border-rust/50 text-rust" : "border-line text-muted"
                      }`}
                      title={hot ? "Confirmed CISA KEV overlap" : "Shodan CVE tag"}
                    >
                      {cve}
                    </span>
                  );
                })}
              </div>
            )}
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              {host.services.map((svc) => (
                <div key={svc.entity_id} className="border border-line/80 px-3 py-2">
                  <p className="font-mono text-xs text-teal">
                    {svc.port}/{svc.service || "unknown"}
                  </p>
                  <p className="mt-1 truncate text-sm text-paper/85">
                    {svc.http_title || svc.banner || "No title or banner"}
                  </p>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>
      {shared.length > 0 && <div className="mt-6"><SharedIps hosts={shared} /></div>}
    </section>
  );
}

function SharedIps({ hosts }: { hosts: Host[] }) {
  return (
    <div>
      <h3 className="stamp text-muted">Shared / CDN IPs</h3>
      <p className="mt-2 text-sm text-muted">
        DNS resolved these addresses, but Shodan banners belonged to other tenants and were dropped.
      </p>
      <ul className="mt-3 space-y-1">
        {hosts.map((host) => (
          <li key={host.entity_id} className="flex flex-wrap gap-3 font-mono text-xs text-muted">
            <Ioc value={host.ip} className="text-amber" />
            <span>{[host.org || "unknown org", host.asn].filter(Boolean).join(" · ")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
