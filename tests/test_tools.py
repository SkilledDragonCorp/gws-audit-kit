"""Stdlib tests against the fake snapshots in tests/fixtures/.

Run: python -I -m unittest discover -s tests
"""
import datetime as dt
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import analyze  # noqa: E402
import diff  # noqa: E402
import drive_inventory  # noqa: E402
import render_html  # noqa: E402

A = os.path.join(HERE, "fixtures", "2026-01-05")
B = os.path.join(HERE, "fixtures", "2026-02-02")


def ids(result):
    return {f["id"]: f for f in result["findings"]}


class AnalyzeTest(unittest.TestCase):
    def test_ranked_by_severity(self):
        result = analyze.analyze(B, "starter")
        order = [analyze.SEVERITIES.index(f["severity"]) for f in result["findings"]]
        self.assertEqual(order, sorted(order))

    def test_2sv_lockout_is_critical_near_enforcement(self):
        found = ids(analyze.analyze(B, "starter"))["2sv-enrollment"]
        self.assertEqual(found["severity"], "critical")
        self.assertIn("casey@example.com", found["evidence"])
        self.assertNotIn("former@example.com", found["evidence"])

    def test_snapshot_date_comes_from_folder_name(self):
        self.assertEqual(analyze.analyze(A)["snapshot_date"], "2026-01-05")

    def test_external_public_file_not_counted(self):
        found = ids(analyze.analyze(B))["drive-public-files"]
        self.assertEqual(found["count"], 3)

    def test_dns_findings(self):
        a = ids(analyze.analyze(A))["mail-dns"]
        self.assertIn("example.com: DMARC p=none (monitoring only)", a["evidence"])
        b = ids(analyze.analyze(B))["mail-dns"]
        self.assertEqual(b["severity"], "low")

    def test_edition_note(self):
        starter = ids(analyze.analyze(B, "starter"))["drive-external-grants"]
        self.assertIn("Business Starter", starter["edition_note"])
        enterprise = ids(analyze.analyze(B, "enterprise"))["drive-external-grants"]
        self.assertIsNone(enterprise["edition_note"])

    def test_missing_inputs_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(os.path.join(B, "users.csv"), tmp)
            result = analyze.analyze(tmp, today=dt.date(2026, 2, 2))
        self.assertIn("policies.csv", result["not_checked"])
        self.assertIn("2sv-enrollment", ids(result))


class DnsParseTest(unittest.TestCase):
    def test_linux_and_windows_layouts(self):
        text = "\n".join(["### a.test TXT", 'a.test\ttext = "v=spf1 " "-all"', 'a.test\ttext = "other"',
                          "### _dmarc.a.test TXT", "_dmarc.a.test\ttext =", "", '\t"v=DMARC1; p=reject"'])
        records = analyze.parse_dns(text)
        self.assertEqual(records["a.test"], ["v=spf1 -all", "other"])
        self.assertEqual(records["_dmarc.a.test"], ["v=DMARC1; p=reject"])


class DiffTest(unittest.TestCase):
    def test_diff_between_fixtures(self):
        prev, cur = analyze.analyze(A, "starter"), analyze.analyze(B, "starter")
        text = diff.diff(prev, cur)
        self.assertIn("gray@example.com", text)
        self.assertIn("Sample PDF Toolkit", text)
        self.assertIn("Draft budget 2026", text)
        self.assertIn("super-admin-recovery", ids(prev))
        self.assertIn("Super admins can recover their own accounts", text)
        self.assertIn("calendar.primary_calendar_max_allowed_external_sharing@ou:/", text)


class RenderHtmlTest(unittest.TestCase):
    def test_page_is_self_contained_and_escaped(self):
        prev, cur = analyze.analyze(A, "starter"), analyze.analyze(B, "starter")
        cur["findings"][0]["detail"] = "<script>alert(1)</script>"
        page = render_html.render(cur, prev)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("src=", page)
        self.assertNotIn("http://", page)
        self.assertIn("Sample PDF Toolkit", page)
        self.assertIn("NEW", page)

    def test_first_run_without_previous(self):
        page = render_html.render(analyze.analyze(A, "starter"))
        self.assertNotIn("Since last time", page)


class InternalDomainTest(unittest.TestCase):
    def test_lookalike_domain_is_external(self):
        domains = {"example.com"}
        self.assertTrue(drive_inventory.is_internal("a@example.com", domains))
        self.assertTrue(drive_inventory.is_internal("a@eu.example.com", domains))
        self.assertTrue(drive_inventory.is_internal("example.com", domains))
        self.assertFalse(drive_inventory.is_internal("a@evil-example.com", domains))


if __name__ == "__main__":
    unittest.main()
