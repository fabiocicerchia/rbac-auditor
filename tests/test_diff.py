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

    def test_a_rewritten_role_ref_newly_grants_the_existing_subjects(self):
        """roleRef is immutable, so a changed one is a delete and recreate: the
        subjects now hold a different role. That belongs in `newlyGranted` —
        not in `subjects.added`, which would claim a subject already named by
        the binding was newly bound to it, and print it as both + and -."""
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
        self.assertEqual(change["subjects"], {"added": [], "removed": []})
        self.assertEqual(len(change["newlyGranted"]), 1)

    def test_an_unmoved_role_ref_newly_grants_only_the_added_subjects(self):
        change = by_object(self.changes)["ClusterRoleBinding/view-everyone"]
        self.assertNotIn("roleRefBefore", change)
        self.assertEqual(change["newlyGranted"], change["subjects"]["added"])


class GrantTest(unittest.TestCase):
    """Rules are containers; grants are what a subject can actually do. The
    policy judges grants, so the delta has to be computed over them."""

    def test_a_rule_expands_to_one_grant_per_verb_resource_group(self):
        grants = ra.rule_grants(
            {
                "apiGroups": ["", "apps"],
                "resources": ["pods"],
                "verbs": ["get", "list"],
            }
        )
        self.assertEqual(len(grants), 4)
        self.assertIn({"apiGroup": "apps", "resource": "pods", "verb": "get"}, grants)

    def test_resource_names_narrow_a_grant(self):
        grants = ra.rule_grants(
            {
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": ["db"],
                "verbs": ["get"],
            }
        )
        self.assertEqual(grants[0]["resourceName"], "db")

    def test_non_resource_urls_are_their_own_grants(self):
        grants = ra.rule_grants({"nonResourceURLs": ["/healthz"], "verbs": ["get"]})
        self.assertEqual(grants, [{"nonResourceURL": "/healthz", "verb": "get"}])

    def test_narrowing_a_rule_adds_no_grants(self):
        """The whole reason grants exist. Rewriting a rule to drop two verbs
        replaces one rule with another, so a rule-level diff calls the survivor
        new; a grant-level one says two were lost and none gained."""
        wide = [
            {
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["roles"],
                "verbs": ["bind", "get", "list"],
            }
        ]
        narrow = [
            {
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["roles"],
                "verbs": ["bind"],
            }
        ]
        delta = ra._list_delta(ra.rules_grants(wide), ra.rules_grants(narrow))
        self.assertEqual(delta["added"], [])
        self.assertEqual(len(delta["removed"]), 2)

    def test_splitting_one_rule_into_two_adds_no_grants(self):
        """Refactoring RBAC without changing it must be a no-op to the gate."""
        one = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
        two = [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
        ]
        self.assertEqual(ra.rules_grants(one), ra.rules_grants(two))

    def test_a_broad_grant_implies_a_narrow_one(self):
        """The tightening cases that a plain set difference gets wrong."""
        cases = [
            # replacing `*` resources with a named one
            (
                [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]}],
                [{"apiGroups": ["*"], "resources": ["pods"], "verbs": ["get"]}],
            ),
            # replacing `*` verbs with named ones
            (
                [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}],
                [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
            ),
            # replacing `*` apiGroups with a named one
            (
                [{"apiGroups": ["*"], "resources": ["pods"], "verbs": ["get"]}],
                [{"apiGroups": ["apps"], "resources": ["pods"], "verbs": ["get"]}],
            ),
            # restricting to named objects
            (
                [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}],
                [
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "resourceNames": ["db"],
                        "verbs": ["get"],
                    }
                ],
            ),
            # a non-resource URL prefix glob
            (
                [{"nonResourceURLs": ["/api/*"], "verbs": ["get"]}],
                [{"nonResourceURLs": ["/api/v1"], "verbs": ["get"]}],
            ),
        ]
        for before, after in cases:
            with self.subTest(after=after):
                self.assertEqual(ra.grant_delta(before, after)["added"], [])

    def test_a_narrow_grant_does_not_imply_a_broad_one(self):
        """Subsumption only runs one way, or widening would go unreported."""
        narrow = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]
        broad = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        self.assertEqual(len(ra.grant_delta(narrow, broad)["added"]), 1)

    def test_grant_rendering(self):
        self.assertEqual(
            ra.grant_str(
                {"apiGroup": "apps", "resource": "deployments", "verb": "get"}
            ),
            "get deployments.apps",
        )
        self.assertEqual(
            ra.grant_str({"apiGroup": "", "resource": "pods", "verb": "*"}), "* pods"
        )
        self.assertEqual(
            ra.grant_str({"nonResourceURL": "/healthz", "verb": "get"}),
            "get /healthz",
        )


class AggregationRuleTest(unittest.TestCase):
    def test_an_aggregation_change_is_reported(self):
        """It is captured on purpose, so a change to it cannot render as a bare
        `~ ClusterRole/x` with nothing underneath."""
        old = fixture("before")
        new = fixture("before")
        new["clusterRoles"][0]["aggregationRule"] = {
            "clusterRoleSelectors": [{"matchLabels": {"aggregate-to-admin": "true"}}]
        }
        changes = ra.diff_snapshots(old, new)
        self.assertEqual(len(changes), 1)
        self.assertIsNone(changes[0]["aggregationRule"]["before"])
        text = "\n".join(ra.render_changes(changes))
        self.assertIn("aggregationRule", text)

    def test_every_change_renders_a_detail_line(self):
        """A changed object the diff cannot explain is worse than no line."""
        old, new = fixture("before"), fixture("after")
        for change in ra.diff_snapshots(old, new):
            with self.subTest(object=change["object"]):
                lines = ra.render_changes([change])
                self.assertGreater(len(lines), 1, lines)


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
