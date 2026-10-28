import type { Bundle } from "../types";
import { Ioc } from "./Ioc";

function ipsFrom(bundle: Bundle): string[] {
  const found: string[] = [];
  for (const record of bundle.dns_records) {
    if ((record.rtype === "A" || record.rtype === "AAAA") && !found.includes(record.value)) {
      found.push(record.value);
    }
  }
  for (const host of bundle.hosts) {
    if (!found.includes(host.ip)) found.push(host.ip);
  }
  return found;
}

export function SurfaceChips({ bundle }: { bundle: Bundle }) {
  const ips = ipsFrom(bundle);
  const hostnames = bundle.discovered_hostnames;

  return (
    <section>
      <h2 className="stamp text-teal">Attack surface</h2>
      <p className="mt-2 text-sm text-muted">Click any IOC to copy it.</p>
      <div className="mt-4 flex flex-wrap gap-2">
        {hostnames.map((name) => (
          <span key={name} className="border border-line bg-ink-3 px-2.5 py-1">
            <Ioc value={name} />
          </span>
        ))}
        {ips.map((ip) => (
          <span key={ip} className="border border-amber/25 bg-ink-3 px-2.5 py-1">
            <Ioc value={ip} className="text-amber" />
          </span>
        ))}
        {hostnames.length === 0 && ips.length === 0 && (
          <p className="text-sm text-muted">No hostnames or IPs in this bundle yet.</p>
        )}
      </div>
    </section>
  );
}
