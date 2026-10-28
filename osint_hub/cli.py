"""OSINT_Hub command line — collect, report, analyze, targets, compare, all."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from osint_hub import __version__
from osint_hub.analyze import analyze_run, compare_analyses
from osint_hub.config import default_runs_dir, load_settings
from osint_hub.pipeline import collect_domain, load_bundle
from osint_hub.phase2 import write_phase2
from osint_hub.report import write_report
from osint_hub.target_list import build_target_list
from osint_hub.util import resolve_run_dir

console = Console()


def _add_run_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", required=True, help="Path to a runs/<domain>_<timestamp> directory")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-hub",
        description="OSINT_Hub — live OSINT collection, correlation, and optional LLM analysis.",
    )
    parser.add_argument("--version", action="version", version=f"OSINT_Hub {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Run live collectors for a domain")
    collect.add_argument("domain", help="Authorized target domain (example.com)")
    collect.add_argument("--out", type=Path, default=None, help="Runs parent directory (default: ./runs)")

    report = sub.add_parser("report", help="Correlate a run and write report.md")
    _add_run_arg(report)

    phase2 = sub.add_parser("phase2", help="Build the high-value ops dossier from a run")
    _add_run_arg(phase2)

    analyze = sub.add_parser("analyze", help="Send a run's report to an LLM")
    _add_run_arg(analyze)
    analyze.add_argument("--provider", choices=("local", "claude"), default="local")

    targets = sub.add_parser("targets", help="Build a prioritized target list from analysis JSON")
    _add_run_arg(targets)

    compare = sub.add_parser("compare", help="Diff analysis_local.json vs analysis_claude.json")
    _add_run_arg(compare)

    all_cmd = sub.add_parser("all", help="Collect + report, optionally analyze and emit targets")
    all_cmd.add_argument("domain", help="Authorized target domain")
    all_cmd.add_argument("--out", type=Path, default=None, help="Runs parent directory (default: ./runs)")
    all_cmd.add_argument(
        "--analyze",
        dest="analyze_provider",
        choices=("local", "claude", "none"),
        default="none",
        help="LLM provider after reporting (default: none)",
    )

    web = sub.add_parser("web", help="Open the local investigation console")
    web.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8741, help="Bind port (default: 8741)")
    web.add_argument("--open", action="store_true", dest="open_browser", help="Open a browser tab")
    return parser


def _cmd_collect(args: argparse.Namespace) -> int:
    settings = load_settings()
    out = args.out or default_runs_dir()
    asyncio.run(collect_domain(args.domain, settings, out_dir=out))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    run_dir = resolve_run_dir(args.run)
    bundle = load_bundle(run_dir)
    report_path, corr_path, correlations = write_report(run_dir, bundle)
    console.print(f"[green]Wrote {report_path}[/green] ({report_path.stat().st_size} bytes)")
    console.print(f"[green]Wrote {corr_path}[/green] ({len(correlations)} correlations)")
    console.print(f"[green]Wrote {run_dir / 'phase2.json'}[/green]")
    return 0


def _cmd_phase2(args: argparse.Namespace) -> int:
    run_dir = resolve_run_dir(args.run)
    bundle = load_bundle(run_dir)
    path = write_phase2(run_dir, bundle)
    console.print(f"[green]Wrote {path}[/green]")
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    settings = load_settings()
    run_dir = resolve_run_dir(args.run)
    bundle = load_bundle(run_dir)
    if not (run_dir / "report.md").is_file():
        write_report(run_dir, bundle)
    result = analyze_run(run_dir, bundle, settings, args.provider)
    return 0 if result else 2


def _cmd_targets(args: argparse.Namespace) -> int:
    run_dir = resolve_run_dir(args.run)
    build_target_list(run_dir)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    run_dir = resolve_run_dir(args.run)
    compare_analyses(run_dir)
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    try:
        from osint_hub.webapp.serve import run_server
    except ImportError as exc:
        console.print("[red]Web extras are not installed.[/red] Run: pip install -e '.[web]'")
        console.print(f"[dim]{exc}[/dim]")
        return 1
    console.print(f"[green]Investigation console[/green] http://{args.host}:{args.port}")
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("[yellow]Warning: binding beyond localhost exposes this recon console on the network.[/yellow]")
    try:
        run_server(host=args.host, port=args.port, open_browser=args.open_browser)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    return 0


def _cmd_all(args: argparse.Namespace) -> int:
    settings = load_settings()
    out = args.out or default_runs_dir()
    ctx = asyncio.run(collect_domain(args.domain, settings, out_dir=out))
    report_path, corr_path, correlations = write_report(ctx.run_dir, ctx.bundle)
    console.print(f"[green]Wrote {report_path}[/green]")
    console.print(f"[green]Wrote {corr_path}[/green] ({len(correlations)} correlations)")
    if args.analyze_provider == "none":
        return 0
    result = analyze_run(ctx.run_dir, ctx.bundle, settings, args.analyze_provider)
    if not result:
        return 2
    build_target_list(ctx.run_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "collect": _cmd_collect,
        "report": _cmd_report,
        "phase2": _cmd_phase2,
        "analyze": _cmd_analyze,
        "targets": _cmd_targets,
        "compare": _cmd_compare,
        "all": _cmd_all,
        "web": _cmd_web,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted[/yellow]")
        return 130
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
