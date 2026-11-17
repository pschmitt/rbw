"""Regression tests for the maintenance-exception gate."""

import datetime
import unittest

from check_advisory_exceptions import check


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.today = datetime.date(2026, 11, 17)
        self.policy = {"advisories": {"ignore": [{"id": "RUSTSEC-2026-0542"}]}}
        self.lock = {
            "package": [
                {"name": "humantime", "version": "2.4.0"},
                {
                    "name": "rbw",
                    "version": "2.46.0",
                    "dependencies": ["humantime"],
                },
            ]
        }
        self.exceptions = {
            "exceptions": [
                {
                    "id": "RUSTSEC-2026-0542",
                    "crate": "humantime",
                    "version": "2.4.0",
                    "expires": datetime.date(2026, 12, 17),
                    "allow": ["rbw 2.46.0"],
                }
            ]
        }

    def errors(self):
        return check(self.policy, self.lock, self.exceptions, self.today)

    def test_current_scope_passes(self):
        self.assertEqual(self.errors(), [])

    def test_expiry_boundary(self):
        self.today = datetime.date(2026, 12, 16)
        self.assertEqual(self.errors(), [])
        for day in (17, 18):
            self.today = datetime.date(2026, 12, day)
            self.assertIn("expired", " ".join(self.errors()))

    def test_new_depender_fails(self):
        self.lock["package"].append(
            {"name": "other", "version": "1.0.0", "dependencies": ["humantime"]}
        )
        self.assertIn("direct dependers changed", " ".join(self.errors()))

    def test_depender_upgrade_fails(self):
        self.lock["package"][1]["version"] = "2.47.0"
        self.assertIn("direct dependers changed", " ".join(self.errors()))

    def test_crate_upgrade_fails(self):
        self.lock["package"][0]["version"] = "2.5.0"
        self.assertIn("versions changed", " ".join(self.errors()))

    def test_additional_version_fails(self):
        self.lock["package"].append({"name": "humantime", "version": "1.0.0"})
        self.assertIn("versions changed", " ".join(self.errors()))

    def test_version_qualified_dependency_passes(self):
        self.lock["package"][1]["dependencies"] = [
            "humantime 2.4.0 (registry+https://github.com/rust-lang/crates.io-index)"
        ]
        self.assertEqual(self.errors(), [])

    def test_removed_dependency_fails(self):
        self.lock["package"] = []
        self.assertTrue(self.errors())

    def test_obsolete_exception_fails(self):
        self.policy["advisories"]["ignore"] = []
        self.assertIn("obsolete", " ".join(self.errors()))

    def test_string_ignore_passes(self):
        self.policy["advisories"]["ignore"] = ["RUSTSEC-2026-0542"]
        self.assertEqual(self.errors(), [])

    def test_duplicate_exception_fails(self):
        self.exceptions["exceptions"] *= 2
        self.assertIn("duplicate exception", " ".join(self.errors()))

    def test_removing_both_entries_passes(self):
        self.policy["advisories"]["ignore"] = []
        self.exceptions["exceptions"] = []
        self.assertEqual(self.errors(), [])


if __name__ == "__main__":
    unittest.main()
