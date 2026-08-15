"""Tests for .rbac-audit-ignore parsing and matching.

stdlib unittest, run with `python3 -m unittest discover tests`: the image has
no test framework in it and this is not worth adding one for.
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_fields_comments_and_blank_lines(self):
        rules = ra.parse_ignore(
            "# a comment\n"
            "\n"
            "role=cluster-admin reason=break glass account  # trailing comment\n"
            "subject=ServiceAccount:kube-system/default reason=cluster bootstrap\n"
        )
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["role"], "cluster-admin")
        self.assertEqual(rules[0]["reason"], "break glass account")
        self.assertEqual(rules[1]["subject"], "ServiceAccount:kube-system/default")

    def test_reason_is_required(self):
        with self.assertRaises(ra.IgnoreError) as cm:
            ra.parse_ignore("role=cluster-admin\n")
        self.assertIn("reason", str(cm.exception))

    def test_at_least_one_matchable_field(self):
        with self.assertRaises(ra.IgnoreError):
            ra.parse_ignore("reason=just because\n")

    def test_unknown_field_is_an_error(self):
        with self.assertRaises(ra.IgnoreError) as cm:
            ra.parse_ignore("namespace=kube-system reason=x\n")
        self.assertIn("namespace", str(cm.exception))

    def test_malformed_line_names_the_line_number(self):
        with self.assertRaises(ra.IgnoreError) as cm:
            ra.parse_ignore("role=ok reason=fine\nnonsense\n")
        self.assertIn(":2:", str(cm.exception))

    def test_values_may_contain_colons_and_spaces(self):
        rules = ra.parse_ignore(
            "role=system:controller:foo verb=* reason=ships with k8s\n"
        )
        self.assertEqual(rules[0]["role"], "system:controller:foo")
        self.assertEqual(rules[0]["verb"], "*")
        self.assertEqual(rules[0]["reason"], "ships with k8s")


class MatchTest(unittest.TestCase):
    def findings(self):
        return [
            ra.finding("wildcard on admin", role="admin", verb="*"),
            ra.finding("wildcard on viewer", role="viewer", verb="*"),
            ra.finding("unused sa", subject="ServiceAccount:kube-system/thing"),
        ]

    def test_all_named_fields_must_match(self):
        rules = ra.parse_ignore("role=admin verb=* reason=accepted\n")
        kept, suppressed = ra.apply_ignores(self.findings(), rules)
        self.assertEqual([f["text"] for f in kept], ["wildcard on viewer", "unused sa"])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(rules[0]["hits"], 1)

    def test_unnamed_fields_are_not_constraints(self):
        rules = ra.parse_ignore("verb=* reason=every wildcard is accepted\n")
        kept, suppressed = ra.apply_ignores(self.findings(), rules)
        self.assertEqual(len(suppressed), 2)
        self.assertEqual([f["text"] for f in kept], ["unused sa"])

    def test_prefix_wildcard(self):
        rules = ra.parse_ignore(
            "subject=ServiceAccount:kube-system/* reason=system ns\n"
        )
        kept, _ = ra.apply_ignores(self.findings(), rules)
        self.assertNotIn("unused sa", [f["text"] for f in kept])

    def test_rule_matching_nothing_is_stale(self):
        rules = ra.parse_ignore("role=nonexistent reason=left over\n")
        kept, suppressed = ra.apply_ignores(self.findings(), rules)
        self.assertEqual(len(kept), 3)
        self.assertEqual(suppressed, [])
        self.assertEqual(rules[0]["hits"], 0)


class ReportTest(unittest.TestCase):
    snap = {
        "taken_at": "2026-08-15T00:00:00Z",
        "roles": [],
        "clusterroles": [
            {
                "metadata": {"name": "admin"},
                "rules": [{"verbs": ["*"], "resources": ["*"]}],
            },
            {
                "metadata": {"name": "viewer"},
                "rules": [{"verbs": ["*"], "resources": ["*"]}],
            },
        ],
        "rolebindings": [],
        "clusterrolebindings": [],
        "serviceaccounts": [],
        "pods": [],
    }

    def run_report(self, ignore_text):
        rules = ra.parse_ignore(ignore_text)
        buf = io.StringIO()
        with redirect_stdout(buf):
            count = ra.report(self.snap, rules)
        return count, buf.getvalue()

    def test_suppressed_findings_are_listed_not_dropped(self):
        count, out = self.run_report("role=admin reason=break glass\n")
        # One finding left to act on, and the suppressed one is still visible.
        self.assertEqual(count, 1)
        self.assertIn("Suppressed (1)", out)
        self.assertIn("break glass", out)
        self.assertIn("**1 findings.** (1 suppressed)", out)

    def test_stale_entries_are_reported(self):
        _, out = self.run_report("role=ghost reason=who knows\n")
        self.assertIn("Stale suppressions (1)", out)
        self.assertIn("matched nothing", out)

    def test_no_ignore_file_is_the_old_behaviour(self):
        count, out = self.run_report("")
        self.assertEqual(count, 2)
        self.assertNotIn("Suppressed", out)
        self.assertNotIn("Stale", out)


if __name__ == "__main__":
    unittest.main()
