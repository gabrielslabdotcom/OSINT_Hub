"""Feed consolidated OSINT + precomputed correlations to an LLM (lab Step 3–4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from osint_hub.config import Settings
from osint_hub.llm import query_llm
from osint_hub.models import Bundle
from osint_hub.util import read_json, write_json

console = Console()

SYSTEM_PROMPT = """You are an offensive security analyst performing reconnaissance analysis.
You receive a consolidated OSINT report about a target organization plus deterministic
cross-source correlations already computed by a rules engine. Prefer those correlations;
extend them only when the raw report clearly supports a new link.

Analyze the data and return a JSON object with this exact structure:
{
  "target_summary": "One paragraph summary of the target organization",
  "technology_stack": ["list of identified technologies"],
  "relationships": [
    {
      "data_points": ["source A", "source B"],
      "relationship": "description of the connection",
      "offensive_relevance": "why this matters for an attacker"
    }
  ],
  "attack_vectors": [
    {
      "vector": "name of the attack vector",
      "target": "specific host, service, or mailbox from ENTITY SUMMARY",
      "confidence": "high/medium/low",
      "impact": "high/medium/low",
      "rationale": "why this vector is promising",
      "prerequisites": "what the attacker needs first"
    }
  ],
  "high_value_targets": [
    {
      "name": "person or system name",
      "type": "person/system/service",
      "value": "why this target matters",
      "access_potential": "what access they likely have"
    }
  ],
  "recommended_next_steps": ["ordered list of next recon or access-attempt actions against cited findings"],
  "exploitation_paths": [
    {
      "finding": "hostname:port product — CVE or mailbox exactly as in ENTITY SUMMARY",
      "entity_ids": ["host:…", "service:…"],
      "attacker_goal": "what access this finding could yield",
      "sequence": [
        "First action against THIS host/port/identity",
        "Second action",
        "Third action"
      ],
      "if_successful": "likely access if those steps work",
      "defender_check": "what the owner should verify (patch, exposure, MFA)"
    }
  ]
}

Rules:
- Cross-reference data across ALL sources. The value is in connections between sources.
- Rate confidence based on how many independent sources support the finding.
- Prioritize attack vectors by the combination of confidence and impact.
- Identify at least 3 cross-source relationships when the data supports them.
- At most 6 items each in relationships, attack_vectors, high_value_targets, and exploitation_paths.
- Keep each string under 400 characters.
- exploitation_paths MUST cite exact ip:port, hostname, product, CVE id+confidence, email, or leak type from ENTITY SUMMARY. Do not invent hosts or CVEs.
- Write at most 6 exploitation_paths for the highest-value attributed findings (confirmed KEV, distinctive suspected fingerprint, in-scope VPN/OWA/Jenkins, Hunter+HIBP mailbox, LeakIX event type).
- Sequences are operator playbooks: order of recon, identity reuse against THIS portal, patch/exposure confirmation. No payloads, PoCs, Nuclei, Metasploit, exploit commands, or curl exploit bodies.
- Stay within authorized reconnaissance: do not invent exploits or payloads.
- Return ONLY valid JSON. No markdown, no explanation outside the JSON.
"""


def _strip_fences(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


def compact_entity_summary(bundle: Bundle) -> dict[str, Any]:
    return {
        "domain": bundle.domain,
        "hostnames": bundle.discovered_hostnames[:80],
        "dns_record_count": len(bundle.dns_records),
        "certificate_count": len(bundle.certificates),
        "github_finding_count": len(bundle.github_findings),
        "shodan_service_count": sum(len(h.services) for h in bundle.hosts if h.in_scope),
        "shared_ip_count": sum(1 for h in bundle.hosts if not h.in_scope or not h.services),
        "hot_cve_count": len(bundle.hot_cves),
        "attributed_services": [
            {
                "ip": svc.ip,
                "port": svc.port,
                "product": svc.product or svc.service,
                "version": svc.version,
                "hostnames": svc.hostnames[:6],
                "title": svc.http_title,
                "cpe": svc.cpe[:6],
                "components": svc.http_components[:8],
                "tags": host.tags[:8],
                "vulns": (svc.vulns or host.vulns)[:8],
                "ssl_expired": svc.ssl_expired,
                "ssl_self_signed": svc.ssl_self_signed,
                "entity_id": svc.entity_id,
            }
            for host in bundle.hosts
            if host.in_scope
            for svc in host.services
            if svc.in_scope
        ][:40],
        "hot_cves": [
            {
                "cve_id": hit.cve_id,
                "vendor": hit.vendor,
                "product": hit.product,
                "date_added": hit.date_added,
                "source": hit.source,
                "confidence": hit.confidence,
                "evidence": hit.evidence,
                "matched_service": hit.matched_service,
                "entity_id": hit.entity_id,
            }
            for hit in bundle.hot_cves[:25]
        ],
        "emails": [
            {
                "email": row.email,
                "name": " ".join(part for part in (row.first_name, row.last_name) if part),
                "type": row.type,
                "position": row.position,
                "department": row.department,
                "seniority": row.seniority,
                "source": row.source,
            }
            for row in bundle.emails[:25]
        ],
        "breaches": [{"email": row.email, "name": row.name, "breach_date": row.breach_date} for row in bundle.breaches[:25]],
        "leaks": [
            {
                "hostname": row.hostname,
                "ip": row.ip,
                "port": row.port,
                "kind": row.kind,
                "plugin": row.plugin,
                "entity_id": row.entity_id,
            }
            for row in bundle.leaks[:20]
        ],
        "ips": sorted({h.ip for h in bundle.hosts} | {r.value for r in bundle.dns_records if r.rtype in {"A", "AAAA"}}),
    }


def analyze_run(
    run_dir: Path,
    bundle: Bundle,
    settings: Settings,
    provider: str,
) -> dict[str, Any] | None:
    report_path = run_dir / "report.md"
    if not report_path.is_file():
        raise FileNotFoundError("report.md missing — run `osint-hub report` first")
    report = report_path.read_text(encoding="utf-8")
    corr_path = run_dir / "correlations.json"
    correlations = read_json(corr_path) if corr_path.is_file() else []

    prompt = (
        f"OSINT REPORT:\n\n{report}\n\n"
        f"---\n\nPRECOMPUTED CORRELATIONS:\n{json.dumps(correlations, indent=2)}\n\n"
        f"---\n\nENTITY SUMMARY:\n{json.dumps(compact_entity_summary(bundle), indent=2)}\n"
    )
    console.print(f"[*] Sending {len(report)} chars to {provider}...")
    raw = query_llm(prompt, provider=provider, settings=settings, system=SYSTEM_PROMPT)
    cleaned = _strip_fences(raw)
    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raw_path = run_dir / "raw_response.txt"
        raw_path.write_text(raw, encoding="utf-8")
        console.print(f"[red]JSON parse failed: {exc}[/red]")
        console.print(f"[red]Raw response saved to {raw_path}[/red]")
        raise RuntimeError(
            f"LLM JSON parse failed for {provider}: {exc}. "
            f"Raw response saved to {raw_path.name}. "
            "If the file ends mid-object, raise ANTHROPIC_MAX_TOKENS and retry Analyze."
        ) from exc

    output_path = run_dir / f"analysis_{provider}.json"
    write_json(output_path, result)
    console.print(f"[green]Analysis saved to {output_path}[/green]")
    from osint_hub.phase2 import write_phase2

    write_phase2(run_dir, bundle)
    print_results(result)
    return result


def print_results(result: dict[str, Any]) -> None:
    console.print("\n" + "=" * 60)
    console.print("TARGET SUMMARY")
    console.print("=" * 60)
    console.print(result.get("target_summary", "N/A"))

    console.print("\n" + "=" * 60)
    console.print("TECHNOLOGY STACK")
    console.print("=" * 60)
    for tech in result.get("technology_stack", []):
        console.print(f"  - {tech}")

    console.print("\n" + "=" * 60)
    console.print("CROSS-SOURCE RELATIONSHIPS")
    console.print("=" * 60)
    for rel in result.get("relationships", []):
        console.print(f"\n  Data points: {', '.join(rel.get('data_points', []))}")
        console.print(f"  Connection:  {rel.get('relationship')}")
        console.print(f"  Relevance:   {rel.get('offensive_relevance')}")

    console.print("\n" + "=" * 60)
    console.print("ATTACK VECTORS (ranked by confidence + impact)")
    console.print("=" * 60)
    rank_map = {"high": 3, "medium": 2, "low": 1}
    vectors = list(result.get("attack_vectors", []))
    vectors.sort(
        key=lambda v: rank_map.get(v.get("confidence", "low"), 0) + rank_map.get(v.get("impact", "low"), 0),
        reverse=True,
    )
    for i, vector in enumerate(vectors, 1):
        console.print(f"\n  [{i}] {vector.get('vector')}")
        console.print(f"      Target:       {vector.get('target')}")
        console.print(f"      Confidence:   {vector.get('confidence')}")
        console.print(f"      Impact:       {vector.get('impact')}")
        console.print(f"      Rationale:    {vector.get('rationale')}")
        console.print(f"      Prereqs:      {vector.get('prerequisites')}")

    console.print("\n" + "=" * 60)
    console.print("HIGH-VALUE TARGETS")
    console.print("=" * 60)
    for target in result.get("high_value_targets", []):
        console.print(f"\n  {target.get('name')} ({target.get('type')})")
        console.print(f"    Value:  {target.get('value')}")
        console.print(f"    Access: {target.get('access_potential')}")

    console.print("\n" + "=" * 60)
    console.print("RECOMMENDED NEXT STEPS")
    console.print("=" * 60)
    for i, step in enumerate(result.get("recommended_next_steps", []), 1):
        console.print(f"  {i}. {step}")

    console.print("\n" + "=" * 60)
    console.print("EXPLOITATION PATHS (finding-specific, no payloads)")
    console.print("=" * 60)
    for i, path in enumerate(result.get("exploitation_paths") or [], 1):
        console.print(f"\n  [{i}] {path.get('finding')}")
        console.print(f"      Goal:     {path.get('attacker_goal')}")
        for step in path.get("sequence") or []:
            console.print(f"      - {step}")
        console.print(f"      Success:  {path.get('if_successful')}")
        console.print(f"      Defender: {path.get('defender_check')}")


def diff_analyses(run_dir: Path) -> dict[str, Any]:
    local_path = run_dir / "analysis_local.json"
    claude_path = run_dir / "analysis_claude.json"
    missing = [str(p) for p in (local_path, claude_path) if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            "Need both analysis_local.json and analysis_claude.json in the run directory. "
            + " ".join(f"missing: {path}" for path in missing)
        )

    local = read_json(local_path)
    claude = read_json(claude_path)
    local_vectors = {v.get("vector") for v in local.get("attack_vectors", []) if v.get("vector")}
    claude_vectors = {v.get("vector") for v in claude.get("attack_vectors", []) if v.get("vector")}
    return {
        "metrics": [
            {
                "name": "Attack vectors found",
                "local": len(local.get("attack_vectors", [])),
                "claude": len(claude.get("attack_vectors", [])),
            },
            {
                "name": "Relationships identified",
                "local": len(local.get("relationships", [])),
                "claude": len(claude.get("relationships", [])),
            },
            {
                "name": "High-value targets",
                "local": len(local.get("high_value_targets", [])),
                "claude": len(claude.get("high_value_targets", [])),
            },
            {
                "name": "Technologies identified",
                "local": len(local.get("technology_stack", [])),
                "claude": len(claude.get("technology_stack", [])),
            },
            {
                "name": "Next steps suggested",
                "local": len(local.get("recommended_next_steps", [])),
                "claude": len(claude.get("recommended_next_steps", [])),
            },
        ],
        "local_only": sorted(local_vectors - claude_vectors),
        "claude_only": sorted(claude_vectors - local_vectors),
        "both": sorted(local_vectors & claude_vectors),
    }


def compare_analyses(run_dir: Path) -> dict[str, Any]:
    diff = diff_analyses(run_dir)
    table = Table(title="Analysis Comparison: Local vs Claude")
    table.add_column("Metric", style="bold")
    table.add_column("Local", justify="center")
    table.add_column("Claude", justify="center")
    for row in diff["metrics"]:
        table.add_row(row["name"], str(row["local"]), str(row["claude"]))
    console.print(table)

    console.print("\n[bold]Attack vectors only the local model found:[/bold]")
    for vector in diff["local_only"]:
        console.print(f"  - {vector}")
    console.print("\n[bold]Attack vectors only Claude found:[/bold]")
    for vector in diff["claude_only"]:
        console.print(f"  - {vector}")
    console.print("\n[bold]Attack vectors both models found:[/bold]")
    for vector in diff["both"]:
        console.print(f"  - {vector}")
    return diff
