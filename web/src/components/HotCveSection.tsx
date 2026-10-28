import type { HotCveMatch } from "../types";
import { Empty } from "./DnsTable";
import { Ioc } from "./Ioc";

export function HotCveSection({
  matches,
  shodanSkipped,
}: {
  matches: HotCveMatch[];
  shodanSkipped?: boolean;
}) {
  if (matches.length === 0) {
    return (
      <Empty
        title="No hot / known-exploited CVEs"
        body={
          shodanSkipped
            ? "Hot CVE matching needs internet-facing service data — set SHODAN_API_KEY."
            : "No CISA KEV overlap with this target’s attributed services."
        }
      />
    );
  }

  const confirmed = matches.filter((hit) => (hit.confidence ?? (hit.source === "shodan" ? "confirmed" : "suspected")) === "confirmed");
  const suspected = matches.filter((hit) => (hit.confidence ?? (hit.source === "shodan" ? "confirmed" : "suspected")) !== "confirmed");

  return (
    <section>
      <h2 className="stamp text-teal">Hot / known-exploited CVEs</h2>
      <p className="mt-2 text-sm text-muted">
        Confirmed hits are Shodan CVE tags that also appear in CISA KEV on an attributed host.
        Fingerprints are suspected product overlap only — confirm version and patch status.
      </p>
      <div className="mt-4 space-y-6">
        {confirmed.length > 0 && (
          <div className="space-y-3">
            <h3 className="stamp text-rust">Confirmed</h3>
            {confirmed.map((hit) => (
              <CveCard key={hit.entity_id} hit={hit} suspected={false} />
            ))}
          </div>
        )}
        {suspected.length > 0 && (
          <div className="space-y-3">
            <h3 className="stamp text-amber">Suspected</h3>
            {suspected.map((hit) => (
              <CveCard key={hit.entity_id} hit={hit} suspected />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function CveCard({ hit, suspected }: { hit: HotCveMatch; suspected: boolean }) {
  const product = [hit.vendor, hit.product].filter(Boolean).join(" ") || "unknown product";
  return (
    <article
      className={`border bg-ink-2/60 p-4 ${suspected ? "border-amber/30" : "border-rust/30"}`}
    >
      <div className="flex flex-wrap items-baseline gap-3">
        <Ioc value={hit.cve_id} className={suspected ? "text-amber text-sm" : "text-rust text-sm"} />
        <span className="text-sm text-paper/85">{product}</span>
        <span className="stamp text-muted">
          {hit.source === "shodan" ? "Shodan CVE" : "fingerprint"}
        </span>
      </div>
      {hit.name && <p className="mt-2 text-sm text-paper/80">{hit.name}</p>}
      <p className="mt-2 font-mono text-[11px] text-muted">
        CISA listed {hit.date_added || "unknown date"} · matched {hit.matched_service}
      </p>
      {hit.evidence && <p className="mt-1 font-mono text-[11px] text-muted">{hit.evidence}</p>}
      <p className="mt-2 text-sm text-muted">
        {suspected
          ? "Possible product overlap — confirm version/patch; not a verified CVE on this host."
          : `Known-exploited CVE listed by CISA on ${hit.date_added || "an unknown date"}; confirm patch/exposure on this host.`}
      </p>
    </article>
  );
}
