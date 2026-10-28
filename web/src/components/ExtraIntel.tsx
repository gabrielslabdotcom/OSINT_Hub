import type { Bundle } from "../types";
import { Empty } from "./DnsTable";
import { Ioc } from "./Ioc";

export function ExtraIntel({ bundle }: { bundle: Bundle }) {
  const emails = bundle.emails ?? [];
  const breaches = bundle.breaches ?? [];
  const intel = bundle.ip_intel ?? [];
  const scans = bundle.url_scans ?? [];
  const leaks = bundle.leaks ?? [];
  const vt = bundle.vt_domain;
  const empty = !emails.length && !breaches.length && !intel.length && !scans.length && !leaks.length && !vt;
  if (empty) {
    return (
      <Empty
        title="No extra intel"
        body="SecurityTrails, PDCP, VirusTotal, Censys, Hunter, Tomba, URLScan, LeakIX, IPinfo, GreyNoise, AbuseIPDB, and HIBP skip when their .env keys are empty."
      />
    );
  }

  return (
    <div className="space-y-8">
      {vt && (
        <section>
          <h2 className="stamp text-teal">VirusTotal</h2>
          <p className="mt-3 font-mono text-xs text-muted">
            malicious {vt.malicious} · suspicious {vt.suspicious} · harmless {vt.harmless}
          </p>
          {vt.categories.length > 0 && (
            <p className="mt-2 text-sm text-paper/80">{vt.categories.join(", ")}</p>
          )}
        </section>
      )}
      {emails.length > 0 && (
        <section>
          <h2 className="stamp text-teal">Mailboxes</h2>
          <p className="mt-2 font-mono text-xs text-muted">
            {emails.filter((row) => row.phone).length}/{emails.length} include a phone
          </p>
          <ul className="mt-3 space-y-1">
            {emails.map((row) => {
              const name = [row.first_name, row.last_name].filter(Boolean).join(" ");
              return (
                <li key={row.entity_id} className="font-mono text-xs text-muted">
                  {name ? <span className="text-paper">{name} · </span> : null}
                  <Ioc value={row.email} className="text-paper" />{" "}
                  {[row.position, row.department, row.seniority, row.type, row.source]
                    .filter(Boolean)
                    .join(" · ")}
                  {row.phone ? (
                    <>
                      {" · "}
                      <Ioc value={row.phone} />
                    </>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </section>
      )}
      {breaches.length > 0 && (
        <section>
          <h2 className="stamp text-teal">HIBP</h2>
          <ul className="mt-3 space-y-1">
            {breaches.map((row) => (
              <li key={row.entity_id} className="font-mono text-xs text-muted">
                <Ioc value={row.email} /> · {row.name} {row.breach_date}
              </li>
            ))}
          </ul>
        </section>
      )}
      {intel.length > 0 && (
        <section>
          <h2 className="stamp text-teal">IP intel</h2>
          <ul className="mt-3 space-y-1">
            {intel.map((row) => (
              <li key={row.entity_id} className="font-mono text-xs text-muted">
                <Ioc value={row.ip} className="text-amber" />{" "}
                {[
                  row.org ?? "",
                  row.asn ?? "",
                  row.greynoise_classification ? `gn=${row.greynoise_classification}` : "",
                  row.abuse_score != null ? `abuse=${row.abuse_score}` : "",
                ]
                  .filter((part) => part.length > 0)
                  .join(" · ")}
              </li>
            ))}
          </ul>
        </section>
      )}
      {scans.length > 0 && (
        <section>
          <h2 className="stamp text-teal">URLScan</h2>
          <ul className="mt-3 space-y-1">
            {scans.map((row) => (
              <li key={row.entity_id} className="truncate font-mono text-xs text-muted">
                {row.url} {row.title ? `· ${row.title}` : ""}
              </li>
            ))}
          </ul>
        </section>
      )}
      {leaks.length > 0 && (
        <section>
          <h2 className="stamp text-teal">LeakIX events</h2>
          <p className="mt-2 text-sm text-muted">Metadata only — payloads are not stored.</p>
          <ul className="mt-3 space-y-1">
            {leaks.map((row) => (
              <li key={row.entity_id} className="font-mono text-xs text-muted">
                {row.hostname || row.ip}:{row.port} · {row.kind} · {row.plugin || row.event}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
