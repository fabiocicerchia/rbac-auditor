"""Tests for snapshot normalisation and the committed file format.

stdlib unittest, run with `python3 -m unittest discover tests`: the image has
no test framework in it and this is not worth adding one for.

The point of every assertion here is the same one: a snapshot lives in a
repository and is read as a diff, so two clusters granting the same thing have
to produce the same bytes.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra


class NormalizeRuleTest(unittest.TestCase):
    def test_lists_are_sorted_and_deduplicated(self):
        rule = ra.normalize_rule(
            {
                "verbs": ["list", "get", "get"],
                "resources": ["pods"],
                "apiGroups": [""],
            }
        )
        self.assertEqual(rule["verbs"], ["get", "list"])

    def test_empty_fields_are_dropped(self):
        rule = ra.normalize_rule(
            {"verbs": ["get"], "resources": ["pods"], "resourceNames": []}
        )
        self.assertNotIn("resourceNames", rule)

    def test_identical_rules_collapse(self):
        rules = ra.normalize_rules(
            [
                {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
                {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
            ]
        )
        self.assertEqual(len(rules), 1)

    def test_rule_order_does_not_matter(self):
        first = ra.normalize_rules(
            [
                {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
                {"verbs": ["list"], "resources": ["secrets"], "apiGroups": [""]},
            ]
        )
        second = ra.normalize_rules(
            [
                {"verbs": ["list"], "resources": ["secrets"], "apiGroups": [""]},
                {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
            ]
        )
        self.assertEqual(first, second)


class NormalizeBindingTest(unittest.TestCase):
    def test_service_account_namespace_is_made_explicit(self):
        """The two spellings of the same grant have to normalise to one record."""
        implicit = ra.normalize_binding(
            {
                "metadata": {"name": "b", "namespace": "ci"},
                "roleRef": {"kind": "Role", "name": "deploy"},
                "subjects": [{"kind": "ServiceAccount", "name": "deployer"}],
            }
        )
        explicit = ra.normalize_binding(
            {
                "metadata": {"name": "b", "namespace": "ci"},
                "roleRef": {"kind": "Role", "name": "deploy"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}
                ],
            }
        )
        self.assertEqual(implicit, explicit)
        self.assertEqual(implicit["subjects"][0]["namespace"], "ci")

    def test_a_group_gets_no_namespace(self):
        binding = ra.normalize_binding(
            {
                "metadata": {"name": "b", "namespace": "ci"},
                "roleRef": {"kind": "ClusterRole", "name": "view"},
                "subjects": [{"kind": "Group", "name": "devs"}],
            }
        )
        self.assertNotIn("namespace", binding["subjects"][0])

    def test_role_ref_keeps_only_kind_and_name(self):
        binding = ra.normalize_binding(
            {
                "metadata": {"name": "b"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "view",
                },
                "subjects": [],
            }
        )
        self.assertEqual(binding["roleRef"], {"kind": "ClusterRole", "name": "view"})


class NormalizeRoleTest(unittest.TestCase):
    def test_cluster_scoped_roles_have_no_namespace_key(self):
        role = ra.normalize_role({"metadata": {"name": "view"}, "rules": []})
        self.assertNotIn("namespace", role)
        self.assertEqual(ra.object_id(role), "view")

    def test_namespaced_roles_are_qualified(self):
        role = ra.normalize_role(
            {"metadata": {"name": "deploy", "namespace": "ci"}, "rules": []}
        )
        self.assertEqual(ra.object_id(role), "ci/deploy")

    def test_aggregation_rule_is_kept(self):
        role = ra.normalize_role(
            {
                "metadata": {"name": "view"},
                "aggregationRule": {
                    "clusterRoleSelectors": [{"matchLabels": {"a": "b"}}]
                },
                "rules": [],
            }
        )
        self.assertIn("aggregationRule", role)


class FileFormatTest(unittest.TestCase):
    """The committed artefact: stable bytes, and no timestamp in the payload."""

    def setUp(self):
        self.snap = ra.load_snapshot(
            str(Path(__file__).parent / "fixtures" / "before.json")
        )

    def test_round_trip_is_byte_stable(self):
        once = ra.dump_snapshot(self.snap)
        twice = ra.dump_snapshot(json.loads(once))
        self.assertEqual(once, twice)

    def test_ends_in_a_newline(self):
        self.assertTrue(ra.dump_snapshot(self.snap).endswith("}\n"))

    def test_payload_carries_no_timestamp(self):
        """`git log` already knows when. A timestamp inside would make every
        snapshot differ from every other one."""
        text = ra.dump_snapshot(self.snap).lower()
        for word in ("timestamp", "taken_at", "creationtimestamp", "generated"):
            self.assertNotIn(word, text)

    def test_key_order_does_not_depend_on_input_order(self):
        shuffled = dict(reversed(list(self.snap.items())))
        self.assertEqual(ra.dump_snapshot(shuffled), ra.dump_snapshot(self.snap))


if __name__ == "__main__":
    unittest.main()
