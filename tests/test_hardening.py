"""Runtime checks for the console hardening pass."""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from osint_hub.models import Bundle, RepoFinding
from osint_hub.report import _plain, build_report
from osint_hub.util import find_env_file, new_run_dir, normalize_domain
from osint_hub.webapp.jobs import MAX_ACTIVE_JOBS, JobBusyError, JobRunner

REPO = Path(__file__).resolve().parents[1]


class DomainValidationTests(unittest.TestCase):
    def test_accepts_org_domain(self) -> None:
        self.assertEqual(normalize_domain("https://Corp.Example/path"), "corp.example")

    def test_rejects_ip_literals(self) -> None:
        for raw in ("127.0.0.1", "169.254.169.254", "8.8.8.8"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    normalize_domain(raw)

    def test_rejects_public_suffixes(self) -> None:
        for raw in ("co.uk", "github.io", "herokuapp.com", "com.au"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    normalize_domain(raw)

    def test_accepts_registrable_under_public_suffix(self) -> None:
        self.assertEqual(normalize_domain("example.co.uk"), "example.co.uk")
        self.assertEqual(normalize_domain("octocat.github.io"), "octocat.github.io")


class EnvAndRunDirTests(unittest.TestCase):
    def test_env_is_repo_root_only(self) -> None:
        found = find_env_file()
        allowed = {REPO / ".env"}
        self.assertTrue(found is None or found.resolve() in {path.resolve() for path in allowed})
        self.assertNotEqual(found, Path.home() / ".env")

    def test_run_dir_collision_allocates_suffix(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = new_run_dir(root, "corp.example")
            second = new_run_dir(root, "corp.example")
            self.assertNotEqual(first, second)
            self.assertTrue((second / "sources").is_dir())


class ReportEscapeTests(unittest.TestCase):
    def test_plain_strips_html_and_markdown(self) -> None:
        escaped = _plain('<script>alert(1)</script> ![x](javascript:alert(1))')
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertNotIn("[x]", escaped)

    def test_build_report_does_not_emit_raw_script(self) -> None:
        bundle = Bundle(
            domain="corp.example",
            collected_at="2026-10-28T00:00:00+00:00",
            github_findings=[
                RepoFinding(
                    repo="evil/repo",
                    file="readme.md",
                    match='<img src=x onerror="fetch(\'/api/runs\')">',
                    url="javascript:alert(1)",
                )
            ],
        )
        markdown = build_report(bundle, [])
        self.assertNotIn("<img", markdown)
        self.assertIn("&lt;img", markdown)


class JobCapTests(unittest.TestCase):
    def test_rejects_over_active_cap(self) -> None:
        async def _run() -> None:
            runner = JobRunner()
            for index in range(MAX_ACTIVE_JOBS):
                await runner.submit_investigate(f"corp{index}.example", "none")
            with self.assertRaises(JobBusyError):
                await runner.submit_investigate("overflow.example", "none")

        asyncio.run(_run())


class ConsoleApiTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            from fastapi.testclient import TestClient
            from osint_hub.webapp.app import create_app
        except ImportError:
            self.skipTest("web extras are not installed")
        self.client = TestClient(create_app())

    def test_loopback_host_allowed(self) -> None:
        response = self.client.get("/api/status", headers={"host": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)

    def test_foreign_host_rejected(self) -> None:
        response = self.client.get("/api/status", headers={"host": "evil.example"})
        self.assertEqual(response.status_code, 400)

    def test_ip_target_rejected_before_queue(self) -> None:
        response = self.client.post(
            "/api/runs",
            headers={"host": "127.0.0.1"},
            json={"domain": "127.0.0.1", "analyze": "none"},
        )
        self.assertEqual(response.status_code, 400)

    def test_public_suffix_rejected_before_queue(self) -> None:
        response = self.client.post(
            "/api/runs",
            headers={"host": "127.0.0.1"},
            json={"domain": "co.uk", "analyze": "none"},
        )
        self.assertEqual(response.status_code, 400)


class CliBindTests(unittest.TestCase):
    def test_refuses_non_loopback_without_flag(self) -> None:
        from osint_hub.cli import main

        code = main(["web", "--host", "0.0.0.0", "--port", "8741"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
