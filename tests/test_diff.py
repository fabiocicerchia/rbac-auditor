"""Tests for the snapshot diff.

stdlib unittest, run with `python3 -m unittest discover tests`.

Everything here runs against the fixture snapshots: no cluster, no kubectl,
which is also how the tool is meant to be used in CI.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name):
    return ra.load_snapshot(str(FIXTURES / f"{name}.json"))


def by_object(changes):
    return {change["object"]: change for change in changes}


class DiffTest(unittest.TestCase):
    def setUp(self):
        self.old, self.new = fixture("before"), fixture("after")
        self.changes = ra.diff_snapshots(self.old, self.new)

    def test_a_snapshot_does_not_differ_from_itself(self):
        self.assertEqual(ra.diff_snapshots(self.old, self.old), [])

    def test_order_is_stable(self):
        self.assertEqual(self.changes, ra.diff_snapshots(self.old, self.new))

    def test_added_binding(self):
        change = by_object(self.changes)["ClusterRoleBinding/ci-admin"]
        self.assertEqual(change["change"], "added")
        self.assertEqual(change["roleRef"]["name"], "cluster-admin")
        # An added object is every one of its subjects added, so a policy check
        # never has to ask which kind of change it is looking at.
        self.assertEqual(len(change["subjects"]["added"]), 1)
        self.assertEqual(change["subjects"]["removed"], [])

    def test_changed_role_reports_rules_both_ways(self):
        change = by_object(self.changes)["Role/ci/deploy"]
        self.assertEqual(change["change"], "changed")
        self.assertEqual(len(change["rules"]["added"]), 3)
        self.assertEqual(len(change["rules"]["removed"]), 1)

    def test_changed_binding_reports_the_new_subject_only(self):
        change = by_object(self.changes)["ClusterRoleBinding/view-everyone"]
        self.assertEqual(
            [s["name"] for s in change["subjects"]["added"]], ["system:unauthenticated"]
        )
        self.assertEqual(change["subjects"]["removed"], [])

    def test_removal_is_reported(self):
        changes = ra.diff_snapshots(self.new, self.old)
        change = by_object(changes)["ClusterRoleBinding/ci-admin"]
        self.assertEqual(change["change"], "removed")
        self.assertEqual(len(change["subjects"]["removed"]), 1)

    def test_a_rewritten_role_ref_makes_every_subject_new(self):
        """roleRef is immutable, so a changed one is a delete and recreate: the
        subjects now point at a different role, which is a new grant for all of
        them."""
        old = fixture("before")
        new = fixture("before")
        new["clusterRoleBindings"][0]["roleRef"] = {
            "kind": "ClusterRole",
            "name": "cluster-admin",
        }
        change = by_object(ra.diff_snapshots(old, new))[
            "ClusterRoleBinding/view-everyone"
        ]
        self.assertEqual(change["roleRefBefore"]["name"], "view")
        self.assertEqual(len(change["subjects"]["added"]), 1)


class RenderTest(unittest.TestCase):
    def test_human_output_marks_each_kind_of_change(self):
        changes = ra.diff_snapshots(fixture("before"), fixture("after"))
        text = "\n".join(ra.render_changes(changes))
        self.assertIn("+ ClusterRoleBinding/ci-admin", text)
        self.assertIn("~ Role/ci/deploy", text)
        self.assertIn("+ rule apiGroups=* resources=secrets verbs=get", text)
        self.assertIn("+ Group system:unauthenticated", text)

    def test_the_core_api_group_is_rendered_visibly(self):
        """An empty apiGroup is the core one. Rendering it as nothing would
        make the line read as a missing field."""
        self.assertIn(
            'apiGroups=""', ra.rule_str({"apiGroups": [""], "verbs": ["get"]})
        )

    def test_no_changes_says_so(self):
        old = fixture("before")
        self.assertEqual(ra.render_changes(ra.diff_snapshots(old, old)), [])


if __name__ == "__main__":
    unittest.main()
