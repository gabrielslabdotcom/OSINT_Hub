"""Canonical OSINT_Hub entities, collection bundle, and correlation records."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class DnsRecord(BaseModel):
    name: str
    rtype: str
    value: str
    priority: int | None = None
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"dns:{self.name}:{self.rtype}:{self.value}"


class Certificate(BaseModel):
    common_name: str
    issuer: str
    not_after: str
    names: list[str] = Field(default_factory=list)
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"cert:{self.common_name}:{self.not_after}"


class InternetService(BaseModel):
    ip: str
    port: int
    service: str
    product: str = ""
    version: str = ""
    http_title: str | None = None
    banner: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    in_scope: bool = True
    transport: str = ""
    cpe: list[str] = Field(default_factory=list)
    info: str = ""
    http_server: str = ""
    http_components: list[str] = Field(default_factory=list)
    redirects: str = ""
    vulns: list[str] = Field(default_factory=list)
    ssl_expired: bool = False
    ssl_self_signed: bool = False
    tls_versions: list[str] = Field(default_factory=list)
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"service:{self.ip}:{self.port}"


class Host(BaseModel):
    ip: str
    hostnames: list[str] = Field(default_factory=list)
    services: list[InternetService] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    org: str = ""
    asn: str = ""
    in_scope: bool = True
    tags: list[str] = Field(default_factory=list)
    os: str = ""
    isp: str = ""
    last_update: str = ""
    country: str = ""
    city: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"host:{self.ip}"


class HotCveMatch(BaseModel):
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    source: Literal["shodan", "fingerprint"]
    confidence: Literal["confirmed", "suspected"] = "suspected"
    evidence: str = ""
    matched_service: str
    required_action: str = ""
    short_description: str = ""
    known_ransomware: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"hotcve:{self.cve_id}:{self.source}:{self.matched_service}"


class RepoFinding(BaseModel):
    repo: str
    file: str
    match: str
    author: str | None = None
    url: str | None = None
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"finding:{self.repo}:{self.file}"


class Correlation(BaseModel):
    data_points: list[str]
    relationship: str
    offensive_relevance: str


class CollectorStatus(BaseModel):
    name: str
    status: Literal["ok", "skipped", "error"]
    records: int = 0
    error: str | None = None
    duration_ms: int | None = None


class Manifest(BaseModel):
    domain: str
    started_at: str
    finished_at: str | None = None
    run_dir: str
    collectors: list[CollectorStatus] = Field(default_factory=list)


class EmailRecord(BaseModel):
    email: str
    first_name: str = ""
    last_name: str = ""
    position: str = ""
    department: str = ""
    type: str = ""
    confidence: int | None = None
    phone: str = ""
    linkedin: str = ""
    seniority: str = ""
    source: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"email:{self.email.lower()}"


class BreachRecord(BaseModel):
    email: str
    name: str
    breach_date: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"breach:{self.email.lower()}:{self.name}"


class IpIntel(BaseModel):
    ip: str
    org: str = ""
    asn: str = ""
    hostname: str = ""
    greynoise_classification: str = ""
    greynoise_noise: bool | None = None
    greynoise_riot: bool | None = None
    greynoise_name: str = ""
    greynoise_last_seen: str = ""
    abuse_score: int | None = None
    abuse_usage_type: str = ""
    abuse_isp: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"ipintel:{self.ip}"


class UrlScanRecord(BaseModel):
    url: str
    title: str = ""
    ip: str = ""
    scan_url: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"urlscan:{self.url}"


class LeakRecord(BaseModel):
    ip: str = ""
    hostname: str = ""
    port: int = 0
    protocol: str = ""
    plugin: str = ""
    event: str = ""
    kind: str = ""
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            host = self.hostname or self.ip or "unknown"
            self.entity_id = f"leak:{host}:{self.port}:{self.plugin or self.kind}"


class VtDomain(BaseModel):
    domain: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    categories: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    resolutions: list[str] = Field(default_factory=list)
    entity_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.entity_id:
            self.entity_id = f"vt:{self.domain}"


class Bundle(BaseModel):
    domain: str
    collected_at: str
    dns_records: list[DnsRecord] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    github_findings: list[RepoFinding] = Field(default_factory=list)
    discovered_hostnames: list[str] = Field(default_factory=list)
    hot_cves: list[HotCveMatch] = Field(default_factory=list)
    emails: list[EmailRecord] = Field(default_factory=list)
    breaches: list[BreachRecord] = Field(default_factory=list)
    ip_intel: list[IpIntel] = Field(default_factory=list)
    url_scans: list[UrlScanRecord] = Field(default_factory=list)
    leaks: list[LeakRecord] = Field(default_factory=list)
    vt_domain: VtDomain | None = None


class CollectorResult(BaseModel):
    name: str
    status: Literal["ok", "skipped", "error"]
    records: int = 0
    error: str | None = None
    duration_ms: int = 0
    data: Any = None


class Phase2Link(BaseModel):
    label: str
    url: str


class Phase2Task(BaseModel):
    id: str
    kind: str
    title: str
    why: str
    entity_ids: list[str] = Field(default_factory=list)
    next_action: str = ""
    steps: list[str] = Field(default_factory=list)
    links: list[Phase2Link] = Field(default_factory=list)
    status: Literal["open", "done"] = "open"
    priority: int = 0


class Phase2Service(BaseModel):
    rank: int = 0
    category: str = ""
    ip: str
    port: int
    transport: str = ""
    product: str = ""
    version: str = ""
    hostnames: list[str] = Field(default_factory=list)
    title: str = ""
    server: str = ""
    components: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_seen: str = ""
    location: str = ""
    cves: list[str] = Field(default_factory=list)
    kev: list[dict[str, str]] = Field(default_factory=list)
    ssl_expired: bool = False
    ssl_self_signed: bool = False
    tls_versions: list[str] = Field(default_factory=list)
    evidence: str = ""
    entity_ids: list[str] = Field(default_factory=list)
    defender_check: str = ""
    sequence: list[str] = Field(default_factory=list)
    tasks: list[str] = Field(default_factory=list)


class Phase2Person(BaseModel):
    rank: int = 0
    full_name: str = ""
    first_name: str = ""
    last_name: str = ""
    email: str
    phone: str = ""
    linkedin: str = ""
    position: str = ""
    department: str = ""
    seniority: str = ""
    type: str = ""
    source: str = ""
    confidence: int | None = None
    why: str = ""
    breaches: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)


class Phase2MailPosture(BaseModel):
    spf: bool = False
    dmarc_policy: str = "missing"
    spoofable: bool = False
    providers: list[str] = Field(default_factory=list)
    note: str = ""
    mailbox_count: int = 0


class Phase2Dossier(BaseModel):
    domain: str
    generated_at: str
    mail_posture: Phase2MailPosture
    tasks: list[Phase2Task] = Field(default_factory=list)
    services: list[Phase2Service] = Field(default_factory=list)
    people: list[Phase2Person] = Field(default_factory=list)
