"""Tests for the policy gate — one case per rule, plus the ways to relax it.

stdlib unittest, run with `python3 -m unittest discover tests`.

These are the assertions that decide whether a pipeline goes red, so each rule
is tested for firing *and* for not firing on the change that looks like it.
"""

import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra


def snapshot(**sections):
    """A valid snapshot with only the sections a test cares about filled in."""
    snap = {"apiVersion": ra.SNAPSHOT_VERSION}
    for key in ra.SECTION_KEYS:
        snap[key] = sections.get(key, [])
    return snap


def role(name, rules, namespace=None):
    out = {"name": name, "rules": rules}
    if namespace:
        out["namespace"] = namespace
    return out


def binding(name, role_name, subjects, kind="ClusterRole"):
    return {
        "name": name,
        "roleRef": {"kind": kind, "name": role_name},
        "subjects": subjects,
    }


def verdict(old, new, policy=None):
    policy = policy or ra.merge_policy(None)
    return ra.evaluate(ra.diff_snapshots(old, new), policy)


def rules_fired(violations):
    return sorted({violation["rule"] for violation in violations})


class ClusterAdminBindingTest(unittest.TestCase):
    subject = {"kind": "ServiceAccount", "namespace": "ci", "name": "deployer"}

    def test_a_new_cluster_admin_binding_fails(self):
        violations, _ = verdict(
            snapshot(),
            snapshot(
                clusterRoleBindings=[binding("x", "cluster-admin", [self.subject])]
            ),
        )
        self.assertEqual(rules_fired(violations), ["cluster-admin-binding"])
        self.assertTrue(ra.gating(violations))
        self.assertIn("ServiceAccount ci/deployer", violations[0]["detail"])

    def test_a_new_subject_on_an_existing_binding_fails(self):
        other = {"kind": "Group", "name": "sre"}
        violations, _ = verdict(
            snapshot(clusterRoleBindings=[binding("x", "cluster-admin", [other])]),
            snapshot(
                clusterRoleBindings=[
                    binding("x", "cluster-admin", [other, self.subject])
                ]
            ),
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("ci/deployer", violations[0]["detail"])

    def test_removing_a_cluster_admin_binding_is_not_a_violation(self):
        """A gate that fails a build for *taking away* cluster-admin is a gate
        people route around."""
        violations, _ = verdict(
            snapshot(
                clusterRoleBindings=[binding("x", "cluster-admin", [self.subject])]
            ),
            snapshot(),
        )
        self.assertEqual(violations, [])

    def test_an_unchanged_binding_is_not_a_violation(self):
        before = snapshot(
            clusterRoleBindings=[binding("x", "cluster-admin", [self.subject])]
        )
        violations, _ = verdict(before, before)
        self.assertEqual(violations, [])

    def test_a_binding_to_another_role_is_not_a_violation(self):
        violations, _ = verdict(
            snapshot(),
            snapshot(clusterRoleBindings=[binding("x", "view", [self.subject])]),
        )
        self.assertEqual(violations, [])


class WildcardTest(unittest.TestCase):
    def fire(self, rule):
        violations, _ = verdict(snapshot(), snapshot(clusterRoles=[role("r", [rule])]))
        return violations

    def test_wildcard_verbs(self):
        violations = self.fire(
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}
        )
        self.assertIn("wildcard", rules_fired(violations))
        self.assertIn("verbs", violations[0]["detail"])

    def test_wildcard_resources(self):
        violations = self.fire(
            {"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}
        )
        self.assertIn("resources", violations[0]["detail"])

    def test_wildcard_api_groups(self):
        violations = self.fire(
            {"apiGroups": ["*"], "resources": ["secrets"], "verbs": ["get"]}
        )
        self.assertIn("apiGroups", violations[0]["detail"])

    def test_a_named_grant_is_not_a_violation(self):
        self.assertEqual(
            self.fire({"apiGroups": ["apps"], "resources": ["pods"], "verbs": ["get"]}),
            [],
        )

    def test_narrowing_the_watched_fields(self):
        """Documented relaxation: stop flagging `*` verbs on a named resource."""
        policy = ra.merge_policy(
            {"rules": {"wildcard": {"fields": ["resources", "apiGroups"]}}}
        )
        violations, _ = verdict(
            snapshot(),
            snapshot(
                clusterRoles=[
                    role(
                        "r",
                        [
                            {
                                "apiGroups": ["apps"],
                                "resources": ["pods"],
                                "verbs": ["*"],
                            }
                        ],
                    )
                ]
            ),
            policy,
        )
        self.assertEqual(violations, [])


class EscalatingVerbsTest(unittest.TestCase):
    def fire(self, verbs, policy=None):
        violations, _ = verdict(
            snapshot(),
            snapshot(
                clusterRoles=[
                    role(
                        "r",
                        [
                            {
                                "apiGroups": ["rbac.authorization.k8s.io"],
                                "resources": ["roles"],
                                "verbs": verbs,
                            }
                        ],
                    )
                ]
            ),
            policy,
        )
        return violations

    def test_bind_escalate_impersonate_each_fire(self):
        for verb in ("bind", "escalate", "impersonate"):
            with self.subTest(verb=verb):
                violations = self.fire([verb])
                self.assertIn("escalating-verbs", rules_fired(violations))
                self.assertIn(verb, violations[0]["detail"])

    def test_ordinary_verbs_do_not_fire(self):
        self.assertEqual(self.fire(["get", "list", "watch"]), [])

    def test_a_wildcard_verb_is_left_to_the_wildcard_rule(self):
        """It grants these too, but reporting it twice trains people to skim."""
        self.assertEqual(rules_fired(self.fire(["*"])), ["wildcard"])


class AnonymousSubjectTest(unittest.TestCase):
    def fire(self, subject, policy=None):
        violations, _ = verdict(
            snapshot(),
            snapshot(clusterRoleBindings=[binding("x", "view", [subject])]),
            policy,
        )
        return violations

    def test_system_anonymous_user(self):
        violations = self.fire({"kind": "User", "name": "system:anonymous"})
        self.assertEqual(rules_fired(violations), ["anonymous-subject"])

    def test_system_unauthenticated_group(self):
        violations = self.fire({"kind": "Group", "name": "system:unauthenticated"})
        self.assertEqual(rules_fired(violations), ["anonymous-subject"])

    def test_an_authenticated_group_does_not_fire(self):
        self.assertEqual(
            self.fire({"kind": "Group", "name": "system:authenticated"}), []
        )


class RelaxingTest(unittest.TestCase):
    """The three documented ways to turn a rule down, narrowest first."""

    def wildcard_change(self):
        return snapshot(), snapshot(
            clusterRoles=[
                role(
                    "system:controller:x",
                    [{"apiGroups": ["*"], "verbs": ["*"], "resources": ["*"]}],
                )
            ]
        )

    def test_exemption_keeps_the_rule_working_elsewhere(self):
        policy = ra.merge_policy(
            {
                "exempt": [
                    {
                        "rule": "wildcard",
                        "object": "ClusterRole/system:*",
                        "reason": "ships with Kubernetes",
                    }
                ]
            }
        )
        old, new = self.wildcard_change()
        violations, exempted = ra.evaluate(ra.diff_snapshots(old, new), policy)
        self.assertEqual(violations, [])
        self.assertEqual(rules_fired(exempted), ["wildcard"])
        self.assertEqual(exempted[0]["reason"], "ships with Kubernetes")

        # …and the same rule still fires on an object the exemption does not name.
        other = snapshot(
            clusterRoles=[
                role(
                    "app", [{"apiGroups": ["*"], "resources": ["x"], "verbs": ["get"]}]
                )
            ]
        )
        violations, _ = ra.evaluate(ra.diff_snapshots(snapshot(), other), policy)
        self.assertEqual(rules_fired(violations), ["wildcard"])

    def test_fail_false_reports_without_gating(self):
        policy = ra.merge_policy(
            {"rules": {name: {"fail": False} for name in ra.CHECKS}}
        )
        old, new = self.wildcard_change()
        violations, _ = ra.evaluate(ra.diff_snapshots(old, new), policy)
        self.assertTrue(violations)
        self.assertFalse(ra.gating(violations))

    def test_disabled_rule_stops_looking(self):
        policy = ra.merge_policy({"rules": {"wildcard": {"enabled": False}}})
        old, new = self.wildcard_change()
        violations, _ = ra.evaluate(ra.diff_snapshots(old, new), policy)
        self.assertNotIn("wildcard", rules_fired(violations))

    def test_an_exemption_matches_by_subject(self):
        policy = ra.merge_policy(
            {
                "exempt": [
                    {
                        "rule": "cluster-admin-binding",
                        "subject": "Group system:masters",
                        "reason": "the bootstrap group",
                    }
                ]
            }
        )
        new = snapshot(
            clusterRoleBindings=[
                binding(
                    "x", "cluster-admin", [{"kind": "Group", "name": "system:masters"}]
                )
            ]
        )
        violations, exempted = ra.evaluate(ra.diff_snapshots(snapshot(), new), policy)
        self.assertEqual(violations, [])
        self.assertEqual(len(exempted), 1)


class PolicyFileTest(unittest.TestCase):
    """A gate nobody can read is worse than no gate, so these are all fatal."""

    def test_defaults_are_on_and_blocking(self):
        policy = ra.merge_policy(None)
        for name, settings in policy["rules"].items():
            with self.subTest(rule=name):
                self.assertTrue(settings["enabled"])
                self.assertTrue(settings["fail"])

    def test_every_default_rule_has_a_check(self):
        self.assertEqual(sorted(ra.DEFAULT_POLICY["rules"]), sorted(ra.CHECKS))

    def test_unknown_rule_name_is_fatal(self):
        """A typo would otherwise leave the rule at its default — a check the
        author believes they turned off and did not."""
        with self.assertRaises(ra.PolicyError) as caught:
            ra.merge_policy({"rules": {"wildcards": {"enabled": False}}})
        self.assertIn("wildcards", str(caught.exception))

    def test_unknown_setting_is_fatal(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"rules": {"wildcard": {"enable": False}}})

    def test_unknown_top_level_key_is_fatal(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"ruls": {}})

    def test_unsupported_version_is_fatal(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"version": 2})

    def test_an_exemption_needs_a_reason(self):
        with self.assertRaises(ra.PolicyError) as caught:
            ra.merge_policy({"exempt": [{"object": "ClusterRole/x"}]})
        self.assertIn("reason", str(caught.exception))

    def test_an_exemption_needs_something_to_match_on(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"exempt": [{"reason": "just because"}]})

    def test_the_shipped_example_is_valid(self):
        path = Path(__file__).resolve().parent.parent / ".rbac-policy.example.yaml"
        policy = ra.merge_policy(yaml.safe_load(path.read_text()))
        self.assertEqual(sorted(policy["rules"]), sorted(ra.CHECKS))
        self.assertTrue(policy["exempt"])


if __name__ == "__main__":
    unittest.main()
