"""Tests for `diff --subject`: the scoping, and the resource x verb matrix.

stdlib unittest, run with `python3 -m unittest discover tests`.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DEPLOYER = ("ServiceAccount", "ci", "deployer")


def fixture(name):
    return ra.load_snapshot(str(FIXTURES / f"{name}.json"))


class ParseSubjectTest(unittest.TestCase):
    def test_kind_and_name(self):
        self.assertEqual(
            ra.parse_subject("Group/system:masters"), ("Group", "", "system:masters")
        )

    def test_kind_namespace_name(self):
        self.assertEqual(ra.parse_subject("ServiceAccount/ci/deployer"), DEPLOYER)

    def test_kind_is_case_insensitive(self):
        self.assertEqual(ra.parse_subject("serviceaccount/ci/deployer"), DEPLOYER)

    def test_a_service_account_without_a_namespace_is_a_usage_error(self):
        """`ServiceAccount/deployer` is ambiguous across namespaces, and
        guessing one would answer a question nobody asked."""
        with self.assertRaises(SystemExit) as caught:
            ra.parse_subject("ServiceAccount/deployer")
        self.assertEqual(caught.exception.code, ra.EXIT_USAGE)

    def test_an_unknown_kind_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            ra.parse_subject("Robot/ci/deployer")
        self.assertEqual(caught.exception.code, ra.EXIT_USAGE)


class ScopeTest(unittest.TestCase):
    def setUp(self):
        self.old, self.new = fixture("before"), fixture("after")
        self.changes = ra.diff_snapshots(self.old, self.new)

    def test_only_objects_that_reach_the_subject_survive(self):
        scoped = ra.scope_changes(
            self.changes, ra.subject_scope(self.old, self.new, DEPLOYER)
        )
        objects = {change["object"] for change in scoped}
        self.assertIn("Role/ci/deploy", objects)
        self.assertIn("ClusterRoleBinding/ci-admin", objects)
        # `system:unauthenticated` got a new binding; this ServiceAccount is
        # not in it, so it is not this subject's diff.
        self.assertNotIn("ClusterRoleBinding/view-everyone", objects)

    def test_a_subject_nothing_names_has_an_empty_diff(self):
        want = ra.parse_subject("User/nobody")
        self.assertEqual(
            ra.scope_changes(self.changes, ra.subject_scope(self.old, self.new, want)),
            [],
        )

    def test_the_policy_still_gates_a_scoped_diff(self):
        scoped = ra.scope_changes(
            self.changes, ra.subject_scope(self.old, self.new, DEPLOYER)
        )
        violations, _ = ra.evaluate(scoped, ra.merge_policy(None))
        self.assertIn("cluster-admin-binding", {v["rule"] for v in violations})
        self.assertTrue(ra.gating(violations))


class MatrixTest(unittest.TestCase):
    def setUp(self):
        self.old, self.new = fixture("before"), fixture("after")
        self.rows, self.verbs = ra.matrix_rows(
            ra.effective_cells(self.old, DEPLOYER),
            ra.effective_cells(self.new, DEPLOYER),
        )
        self.by_row = {(r["namespace"], r["resource"]): r for r in self.rows}

    def test_columns_are_the_sorted_union_of_both_sides(self):
        self.assertEqual(self.verbs, sorted(set(self.verbs)))
        self.assertIn("escalate", self.verbs)
        self.assertIn("get", self.verbs)

    def test_a_kept_verb_is_unchanged(self):
        row = self.by_row[("ci", "deployments.apps")]
        self.assertEqual(row["unchanged"], ["get", "list"])
        self.assertEqual(row["added"], ["patch"])
        self.assertEqual(row["removed"], [])

    def test_a_cluster_wide_binding_is_scoped_to_star(self):
        """cluster-admin arrives through a ClusterRoleBinding, so it applies in
        every namespace — which the matrix has to say, not imply."""
        row = self.by_row[("*", "*.*")]
        self.assertEqual(row["added"], ["*"])

    def test_a_lost_verb_is_marked_removed(self):
        rows, _ = ra.matrix_rows(
            ra.effective_cells(self.new, DEPLOYER),
            ra.effective_cells(self.old, DEPLOYER),
        )
        row = {(r["namespace"], r["resource"]): r for r in rows}[
            ("ci", "deployments.apps")
        ]
        self.assertEqual(row["removed"], ["patch"])

    def test_rows_and_columns_are_deterministic(self):
        again = ra.matrix_rows(
            ra.effective_cells(self.old, DEPLOYER),
            ra.effective_cells(self.new, DEPLOYER),
        )
        self.assertEqual((self.rows, self.verbs), again)

    def test_rendering_marks_every_state(self):
        text = "\n".join(ra.render_matrix(self.rows, self.verbs))
        self.assertIn("NAMESPACE", text)
        self.assertIn(ra.MARK_ADDED, text)
        self.assertIn(ra.MARK_SAME, text)
        self.assertIn(ra.MARK_NONE, text)
        self.assertIn("gained", text)
        for line in text.splitlines():
            self.assertEqual(line, line.rstrip())

    def test_an_empty_matrix_says_so_rather_than_printing_a_header(self):
        self.assertIn("no permissions", " ".join(ra.render_matrix([], [])).lower())


class EffectivePermissionsTest(unittest.TestCase):
    def test_a_binding_to_a_missing_role_grants_nothing(self):
        """Kubernetes accepts a binding to a role that does not exist. It
        grants nothing until someone creates that role, and the matrix must not
        invent rows for it."""
        snap = {"apiVersion": ra.SNAPSHOT_VERSION}
        for key in ra.SECTION_KEYS:
            snap[key] = []
        snap["roleBindings"] = [
            {
                "name": "b",
                "namespace": "ci",
                "roleRef": {"kind": "Role", "name": "ghost"},
                "subjects": [
                    {"kind": "ServiceAccount", "namespace": "ci", "name": "deployer"}
                ],
            }
        ]
        self.assertEqual(ra.effective_cells(snap, DEPLOYER), {})

    def test_resource_names_narrow_the_row(self):
        rule = {
            "apiGroups": [""],
            "resources": ["secrets"],
            "resourceNames": ["db", "api"],
            "verbs": ["get"],
        }
        self.assertEqual(
            ra.resource_labels(ra.normalize_rule(rule)), ["secrets[api,db]"]
        )

    def test_non_resource_urls_are_rows_of_their_own(self):
        rule = {"nonResourceURLs": ["/healthz"], "verbs": ["get"]}
        self.assertEqual(ra.resource_labels(rule), ["/healthz"])

    def test_the_core_group_leaves_the_resource_bare(self):
        rule = {"apiGroups": ["", "apps"], "resources": ["pods"], "verbs": ["get"]}
        self.assertEqual(ra.resource_labels(rule), ["pods", "pods.apps"])


if __name__ == "__main__":
    unittest.main()
