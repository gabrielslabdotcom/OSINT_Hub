import type { CollectorName, CollectorState, JobEvent } from "../types";

const NODES: { id: CollectorName; label: string; x: number; y: number }[] = [
  { id: "dns", label: "DNS", x: 200, y: 36 },
  { id: "crtsh", label: "crt.sh", x: 348, y: 126 },
  { id: "kev", label: "KEV", x: 292, y: 286 },
  { id: "shodan", label: "Shodan", x: 108, y: 286 },
  { id: "github", label: "GitHub", x: 52, y: 126 },
];

function tone(state: CollectorState): { fill: string; ring: string; text: string } {
  if (state === "running") return { fill: "#5eead4", ring: "#5eead4", text: "#5eead4" };
  if (state === "ok") return { fill: "#7dba6a", ring: "#7dba6a", text: "#7dba6a" };
  if (state === "skipped") return { fill: "#e8b86d", ring: "#e8b86d", text: "#e8b86d" };
  if (state === "error") return { fill: "#ef6b4a", ring: "#ef6b4a", text: "#ef6b4a" };
  return { fill: "#2a333c", ring: "#2a333c", text: "#8b938a" };
}

const EXTRA: { id: CollectorName; label: string }[] = [
  { id: "securitytrails", label: "SecurityTrails" },
  { id: "pdcp", label: "PDCP" },
  { id: "virustotal", label: "VirusTotal" },
  { id: "censys", label: "Censys" },
  { id: "hunter", label: "Hunter" },
  { id: "tomba", label: "Tomba" },
  { id: "phone_enrich", label: "Phones" },
  { id: "urlscan", label: "URLScan" },
  { id: "leakix", label: "LeakIX" },
  { id: "ipinfo", label: "IPinfo" },
  { id: "greynoise", label: "GreyNoise" },
  { id: "abuseipdb", label: "AbuseIPDB" },
  { id: "hibp", label: "HIBP" },
];

const IDLE: Record<CollectorName, CollectorState> = {
  dns: "idle",
  crtsh: "idle",
  github: "idle",
  shodan: "idle",
  kev: "idle",
  securitytrails: "idle",
  pdcp: "idle",
  virustotal: "idle",
  censys: "idle",
  hunter: "idle",
  tomba: "idle",
  phone_enrich: "idle",
  urlscan: "idle",
  leakix: "idle",
  ipinfo: "idle",
  greynoise: "idle",
  abuseipdb: "idle",
  hibp: "idle",
};

export function statesFromEvents(events: JobEvent[]): Record<CollectorName, CollectorState> {
  const next: Record<CollectorName, CollectorState> = { ...IDLE };
  for (const event of events) {
    const collector = event.collector as CollectorName | null;
    if (!collector || !(collector in next)) continue;
    if (event.status === "running") next[collector] = "running";
    if (event.status === "ok" || event.status === "skipped" || event.status === "error") {
      next[collector] = event.status;
    }
  }
  return next;
}

export function CollectorConstellation({
  domain,
  states,
  caption,
}: {
  domain: string;
  states: Record<CollectorName, CollectorState>;
  caption?: string;
}) {
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 400 350" className="h-[300px] w-full max-w-md">
        {NODES.map((node) => (
          <line
            key={`edge-${node.id}`}
            x1="200"
            y1="168"
            x2={node.x}
            y2={node.y}
            stroke={states[node.id] === "idle" ? "#2a333c" : tone(states[node.id]).ring}
            strokeOpacity={states[node.id] === "idle" ? 0.9 : 0.55}
            strokeWidth="1"
          />
        ))}
        <circle cx="200" cy="168" r="36" fill="#12171c" stroke="#e8b86d" strokeOpacity="0.55" />
        <text
          x="200"
          y="172"
          textAnchor="middle"
          fill="#e8e4d9"
          fontFamily="IBM Plex Mono, monospace"
          fontSize="10"
        >
          {domain.length > 22 ? `${domain.slice(0, 20)}…` : domain || "target"}
        </text>
        {NODES.map((node) => {
          const state = states[node.id];
          const colors = tone(state);
          return (
            <g key={node.id}>
              {state === "running" && (
                <circle cx={node.x} cy={node.y} r="18" fill="none" stroke={colors.ring} opacity="0.4">
                  <animate attributeName="r" values="14;22;14" dur="1.6s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.6;0;0.6" dur="1.6s" repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={node.x} cy={node.y} r="14" fill="#12171c" stroke={colors.ring} />
              <circle cx={node.x} cy={node.y} r="3.5" fill={colors.fill} />
              <text
                x={node.x}
                y={node.y + 28}
                textAnchor="middle"
                fill={colors.text}
                fontFamily="IBM Plex Sans, sans-serif"
                fontSize="11"
                letterSpacing="0.12em"
              >
                {node.label.toUpperCase()}
              </text>
              <text
                x={node.x}
                y={node.y + 42}
                textAnchor="middle"
                fill="#8b938a"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="9"
              >
                {state}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-4 flex max-w-xl flex-wrap justify-center gap-1.5">
        {EXTRA.map((node) => {
          const state = states[node.id] ?? "idle";
          const colors = tone(state);
          return (
            <span
              key={node.id}
              className="rounded-full border px-2 py-0.5 font-mono text-[10px]"
              style={{ borderColor: colors.ring, color: colors.text }}
            >
              {node.label} {state}
            </span>
          );
        })}
      </div>
      {caption && <p className="mt-1 max-w-md text-center text-sm text-muted">{caption}</p>}
    </div>
  );
}
