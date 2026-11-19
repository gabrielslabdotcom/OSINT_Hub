"""Unit tests for people investigation requests and User Scanner adapter mapping."""

from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from osint_hub.collectors import user_scanner
from osint_hub.config import Settings
from osint_hub.investigation import (
    merge_people_seeds,
    run_slug_for,
    target_label_for,
    validate_investigation_request,
)
from osint_hub.models import Bundle, EmailRecord, ProfileFinding
from osint_hub.report import build_report
from osint_hub.util import sanitize_run_slug


class InvestigationValidationTests(unittest.TestCase):
    def test_domain_mode_requires_domain(self) -> None:
        with self.assertRaises(ValueError):
            validate_investigation_request(mode="domain")

    def test_people_mode_requires_seed(self) -> None:
        with self.assertRaises(ValueError):
            validate_investigation_request(mode="people")

    def test_people_mode_accepts_username(self) -> None:
        request = validate_investigation_request(mode="people", usernames=["alice"])
        self.assertEqual(request.mode, "people")
        self.assertEqual(request.usernames, ["alice"])
        self.assertEqual(target_label_for(request), "people")
        self.assertEqual(run_slug_for(request), "people")

    def test_both_mode_requires_domain(self) -> None:
        with self.assertRaises(ValueError):
            validate_investigation_request(mode="both", emails=["a@example.com"])

    def test_seed_normalization_and_caps(self) -> None:
        request = validate_investigation_request(
            mode="people",
            emails=["Alice@Example.COM", "alice@example.com", "bob@example.com"],
            usernames=["@Alice", "alice", "bob"],
            max_emails=2,
            max_usernames=2,
        )
        self.assertEqual(request.emails, ["alice@example.com", "bob@example.com"])
        self.assertEqual(request.usernames, ["alice", "bob"])

    def test_people_run_slug_has_no_pii(self) -> None:
        request = validate_investigation_request(mode="people", emails=["secret@corp.example"])
        self.assertEqual(run_slug_for(request), "people")
        self.assertNotIn("@", sanitize_run_slug(run_slug_for(request)))
        self.assertNotIn("secret", sanitize_run_slug(run_slug_for(request)))


class SeedMergeTests(unittest.TestCase):
    def test_derives_usernames_from_mailboxes(self) -> None:
        request = validate_investigation_request(mode="both", domain="corp.example", usernames=["explicit"])
        seeds = merge_people_seeds(
            request,
            mailbox_emails=[EmailRecord(email="alice@corp.example"), EmailRecord(email="bob@corp.example")],
            max_emails=10,
            max_usernames=10,
        )
        self.assertIn("explicit", seeds["usernames"])
        self.assertIn("alice", seeds["usernames"])
        self.assertIn("bob", seeds["usernames"])
        self.assertIn("alice@corp.example", seeds["emails"])


class UserScannerAdapterTests(unittest.TestCase):
    def test_map_result_found_and_unknown(self) -> None:
        found = SimpleNamespace(
            status=SimpleNamespace(name="TAKEN"),
            site_name="GitHub",
            category="Dev",
            url="https://github.com/alice",
            extra={"followers": "10"},
            media={},
            get_reason=lambda: "",
        )
        mapped = user_scanner.map_result(found, seed="alice", seed_type="username")
        assert mapped is not None
        self.assertEqual(mapped.status, "found")
        self.assertEqual(mapped.platform, "GitHub")

        errored = SimpleNamespace(
            status=SimpleNamespace(name="ERROR"),
            site_name="Example",
            category="Social",
            url="",
            extra={},
            media={},
            get_reason=lambda: "rate limited",
        )
        unknown = user_scanner.map_result(errored, seed="alice@example.com", seed_type="email")
        assert unknown is not None
        self.assertEqual(unknown.status, "unknown")

    def test_missing_dependency_skips(self) -> None:
        settings = Settings()
        with patch.object(user_scanner, "available", return_value=False):
            result = asyncio.run(
                user_scanner.collect(emails=["a@example.com"], usernames=[], settings=settings)
            )
        self.assertEqual(result.status, "skipped")
        self.assertIn("not installed", result.error or "")

    def test_loud_requires_both_env_and_request(self) -> None:
        self.assertFalse(bool(Settings(people_scan_allow_loud=False).people_scan_allow_loud and True))
        self.assertFalse(bool(Settings(people_scan_allow_loud=True).people_scan_allow_loud and False))
        self.assertTrue(bool(Settings(people_scan_allow_loud=True).people_scan_allow_loud and True))


class ReportModeTests(unittest.TestCase):
    def test_people_only_report_omits_domain_sections(self) -> None:
        bundle = Bundle(
            domain="",
            collected_at="2026-11-19T00:00:00+00:00",
            mode="people",
            target_label="people",
            profile_findings=[
                ProfileFinding(
                    seed_type="username",
                    seed="alice",
                    platform="GitHub",
                    status="found",
                    url="https://github.com/alice",
                )
            ],
        )
        markdown = build_report(bundle, [])
        self.assertIn("People OSINT", markdown)
        self.assertNotIn("## DNS Records", markdown)
        self.assertNotIn("## Hot / known-exploited CVEs", markdown)
        self.assertNotIn("## Certificate Transparency Logs", markdown)

    def test_legacy_bundle_defaults_to_domain_mode(self) -> None:
        bundle = Bundle.model_validate(
            {
                "domain": "corp.example",
                "collected_at": "2026-11-19T00:00:00+00:00",
            }
        )
        self.assertEqual(bundle.mode, "domain")
        self.assertEqual(bundle.profile_findings, [])


if __name__ == "__main__":
    unittest.main()
