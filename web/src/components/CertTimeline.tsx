import { useMemo } from "react";
import type { Certificate } from "../types";
import { Empty } from "./DnsTable";
import { Ioc } from "./Ioc";

function parseExpiry(value: string): Date | null {
  const trimmed = value.replace("Z", "").trim();
  const stamp = Date.parse(value) || Date.parse(`${trimmed}Z`);
  if (Number.isNaN(stamp)) return null;
  return new Date(stamp);
}

export function CertTimeline({ certs }: { certs: Certificate[] }) {
  const now = Date.now();
  const rows = useMemo(() => {
    return [...certs]
      .map((cert) => ({ cert, expiry: parseExpiry(cert.not_after) }))
      .sort((a, b) => (a.expiry?.getTime() ?? 0) - (b.expiry?.getTime() ?? 0));
  }, [certs]);

  if (certs.length === 0) {
    return (
      <Empty
        title="No certificates"
        body="crt.sh returned no in-scope certificates, or the public API rate-limited the request."
      />
    );
  }

  const times = rows.map((row) => row.expiry?.getTime()).filter((value): value is number => Boolean(value));
  const min = Math.min(...times, now);
  const max = Math.max(...times, now);
  const span = Math.max(max - min, 1);

  return (
    <section>
      <h2 className="stamp text-teal">Certificate transparency</h2>
      <p className="mt-2 text-sm text-muted">Expired names stamp rust. Click a CN to copy.</p>
      <div className="mt-4 space-y-2">
        {rows.map(({ cert, expiry }) => {
          const expired = expiry ? expiry.getTime() < now : false;
          const left = expiry ? ((expiry.getTime() - min) / span) * 100 : 0;
          return (
            <div key={cert.entity_id} className="border border-line bg-ink-2/50 px-3 py-2">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <Ioc value={cert.common_name} className={expired ? "text-rust" : ""} />
                <span className={`font-mono text-[11px] ${expired ? "text-rust" : "text-muted"}`}>
                  {expired ? "expired " : "expires "}
                  {cert.not_after}
                </span>
              </div>
              <p className="mt-1 truncate font-mono text-[11px] text-muted">{cert.issuer}</p>
              <div className="relative mt-2 h-1 bg-ink-3">
                <span
                  className={`absolute top-0 h-1 w-1.5 ${expired ? "bg-rust" : "bg-teal"}`}
                  style={{ left: `${Math.min(Math.max(left, 0), 98)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
