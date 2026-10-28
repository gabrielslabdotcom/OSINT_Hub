export type CollectorName =
  | "dns"
  | "crtsh"
  | "github"
  | "shodan"
  | "kev"
  | "securitytrails"
  | "pdcp"
  | "virustotal"
  | "censys"
  | "hunter"
  | "tomba"
  | "phone_enrich"
  | "urlscan"
  | "leakix"
  | "ipinfo"
  | "greynoise"
  | "abuseipdb"
  | "hibp";
export type CollectorState = "idle" | "running" | "ok" | "skipped" | "error";

export type CollectorStatus = {
  name: string;
  status: "ok" | "skipped" | "error";
  records: number;
  error: string | null;
  duration_ms: number | null;
};

export type HubStatus = {
  version: string;
  collectors: Record<
    string,
    { configured: boolean; needs_key: boolean; label: string }
  >;
  llm: Record<
    string,
    { configured: boolean; reachable: boolean; model: string | null; label: string }
  >;
  env_hint: string;
};

export type Artifacts = {
  bundle: boolean;
  manifest: boolean;
  report: boolean;
  correlations: boolean;
  analysis_local: boolean;
  analysis_claude: boolean;
  targets: boolean;
  phase2: boolean;
  raw_response: boolean;
};

export type RunSummary = {
  run_id: string;
  domain: string | null;
  started_at: string | null;
  finished_at: string | null;
  collectors: CollectorStatus[];
  counts: Record<string, number>;
  artifacts: Artifacts;
};

export type DnsRecord = {
  name: string;
  rtype: string;
  value: string;
  priority: number | null;
  entity_id: string;
};

export type Certificate = {
  common_name: string;
  issuer: string;
  not_after: string;
  names: string[];
  entity_id: string;
};

export type InternetService = {
  ip: string;
  port: number;
  service: string;
  product?: string;
  version?: string;
  http_title: string | null;
  banner: string | null;
  hostnames: string[];
  in_scope?: boolean;
  transport?: string;
  cpe?: string[];
  info?: string;
  http_server?: string;
  http_components?: string[];
  redirects?: string;
  vulns?: string[];
  ssl_expired?: boolean;
  ssl_self_signed?: boolean;
  tls_versions?: string[];
  entity_id: string;
};

export type Host = {
  ip: string;
  hostnames: string[];
  services: InternetService[];
  vulns?: string[];
  org?: string;
  asn?: string;
  in_scope?: boolean;
  tags?: string[];
  os?: string;
  isp?: string;
  last_update?: string;
  country?: string;
  city?: string;
  entity_id: string;
};

export type HotCveMatch = {
  cve_id: string;
  vendor: string;
  product: string;
  name: string;
  date_added: string;
  source: "shodan" | "fingerprint";
  confidence?: "confirmed" | "suspected";
  evidence?: string;
  matched_service: string;
  required_action?: string;
  short_description?: string;
  known_ransomware?: string;
  entity_id: string;
};

export type RepoFinding = {
  repo: string;
  file: string;
  match: string;
  author: string | null;
  url: string | null;
  entity_id: string;
};

export type EmailRecord = {
  email: string;
  first_name?: string;
  last_name?: string;
  position?: string;
  department?: string;
  type?: string;
  confidence?: number | null;
  phone?: string;
  linkedin?: string;
  seniority?: string;
  source?: string;
  entity_id: string;
};

export type BreachRecord = {
  email: string;
  name: string;
  breach_date?: string;
  entity_id: string;
};

export type IpIntel = {
  ip: string;
  org?: string;
  asn?: string;
  hostname?: string;
  greynoise_classification?: string;
  greynoise_noise?: boolean | null;
  greynoise_riot?: boolean | null;
  greynoise_name?: string;
  greynoise_last_seen?: string;
  abuse_score?: number | null;
  abuse_usage_type?: string;
  abuse_isp?: string;
  entity_id: string;
};

export type UrlScanRecord = {
  url: string;
  title?: string;
  ip?: string;
  scan_url?: string;
  entity_id: string;
};

export type LeakRecord = {
  ip?: string;
  hostname?: string;
  port?: number;
  protocol?: string;
  plugin?: string;
  event?: string;
  kind?: string;
  entity_id: string;
};

export type VtDomain = {
  domain: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  categories: string[];
  subdomains: string[];
  resolutions: string[];
  entity_id: string;
};

export type Bundle = {
  domain: string;
  collected_at: string;
  dns_records: DnsRecord[];
  certificates: Certificate[];
  hosts: Host[];
  github_findings: RepoFinding[];
  discovered_hostnames: string[];
  hot_cves?: HotCveMatch[];
  emails?: EmailRecord[];
  breaches?: BreachRecord[];
  ip_intel?: IpIntel[];
  url_scans?: UrlScanRecord[];
  leaks?: LeakRecord[];
  vt_domain?: VtDomain | null;
};

export type Correlation = {
  data_points: string[];
  relationship: string;
  offensive_relevance: string;
};

export type AttackVector = {
  vector: string;
  target: string;
  confidence: string;
  impact: string;
  rationale: string;
  prerequisites?: string;
};

export type HighValueTarget = {
  name: string;
  type: string;
  value: string;
  access_potential: string;
};

export type ExploitationPath = {
  finding: string;
  entity_ids?: string[];
  attacker_goal?: string;
  sequence?: string[];
  if_successful?: string;
  defender_check?: string;
};

export type Analysis = {
  target_summary: string;
  technology_stack: string[];
  relationships: Correlation[];
  attack_vectors: AttackVector[];
  high_value_targets: HighValueTarget[];
  recommended_next_steps: string[];
  exploitation_paths?: ExploitationPath[];
};

export type TargetRow = {
  priority: number;
  vector: string;
  target: string;
  confidence: string;
  impact: string;
  rationale: string;
  finding?: string;
  next_action?: string | null;
};

export type CompareResult = {
  metrics: { name: string; local: number; claude: number }[];
  local_only: string[];
  claude_only: string[];
  both: string[];
};

export type JobEvent = {
  ts?: string;
  stage: string;
  collector: string | null;
  status: string;
  message: string;
  records?: number | null;
  error?: string | null;
  run_id?: string | null;
  domain?: string | null;
  provider?: string | null;
  duration_ms?: number | null;
};

export type Phase2Link = { label: string; url: string };

export type Phase2Task = {
  id: string;
  kind: string;
  title: string;
  why: string;
  entity_ids: string[];
  next_action: string;
  steps: string[];
  links: Phase2Link[];
  status: "open" | "done";
  priority: number;
};

export type Phase2Service = {
  rank: number;
  category: string;
  ip: string;
  port: number;
  transport: string;
  product: string;
  version: string;
  hostnames: string[];
  title: string;
  server: string;
  components: string[];
  cpe: string[];
  tags: string[];
  last_seen: string;
  location: string;
  cves: string[];
  kev: {
    cve_id: string;
    name: string;
    required_action: string;
    short_description: string;
    confidence: string;
  }[];
  ssl_expired: boolean;
  ssl_self_signed: boolean;
  tls_versions: string[];
  evidence: string;
  entity_ids: string[];
  defender_check: string;
  sequence: string[];
  tasks: string[];
};

export type Phase2Person = {
  rank: number;
  full_name: string;
  first_name: string;
  last_name: string;
  email: string;
  phone: string;
  linkedin: string;
  position: string;
  department: string;
  seniority: string;
  type: string;
  source: string;
  confidence: number | null;
  why: string;
  breaches: string[];
  entity_ids: string[];
};

export type Phase2MailPosture = {
  spf: boolean;
  dmarc_policy: string;
  spoofable: boolean;
  providers: string[];
  note: string;
  mailbox_count: number;
};

export type Phase2Dossier = {
  domain: string;
  generated_at: string;
  mail_posture: Phase2MailPosture;
  tasks: Phase2Task[];
  services: Phase2Service[];
  people: Phase2Person[];
};

export type JobSnapshot = {
  job_id: string;
  kind: string;
  status: "queued" | "running" | "completed" | "failed";
  domain: string | null;
  run_id: string | null;
  analyze: string;
  provider: string | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  events: JobEvent[];
};
