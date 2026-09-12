"""Tests for the policy gate — one case per rule, plus the ways to relax it.

stdlib unittest, run with `python3 -m unittest discover tests`.

These are the assertions that decide whether a pipeline goes red, so each rule
is tested for firing *and* for not firing on the change that looks like it.
"""

import sys
import unittest
from pathlib import Path
from typing import ClassVar

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


def verdict(old, new, policy=None, pods=None):
    """(violations, exempted) for a change between two snapshots.

    `pods` is the set of (namespace, ServiceAccount) a pod mounts — only a live
    cluster has it, so it defaults to an empty set here rather than None, which
    would mark the rule that needs it as skipped instead of running it.
    """
    policy = policy or ra.merge_policy(None)
    state = ra.evaluation_state(new, set() if pods is None else pods)
    violations, exempted, _skipped = ra.evaluate(
        ra.diff_snapshots(old, new), policy, state
    )
    return violations, exempted


def rules_fired(violations):
    return sorted({violation["rule"] for violation in violations})


DEPLOYER: dict = {"kind": "ServiceAccount", "namespace": "ci", "name": "deployer"}


def bound(*bindings):
    """A snapshot whose bound ServiceAccount actually exists.

    Without the account these fixtures would also trip `dangling-binding`,
    which is correct of the tool and not what these tests are about.
    """
    return snapshot(
        clusterRoleBindings=list(bindings),
        serviceAccounts=[{"namespace": "ci", "name": "deployer"}],
    )


class ClusterAdminBindingTest(unittest.TestCase):
    subject: ClassVar[dict] = DEPLOYER

    def test_a_new_cluster_admin_binding_fails(self):
        violations, _ = verdict(
            bound(), bound(binding("x", "cluster-admin", [self.subject]))
        )
        self.assertEqual(rules_fired(violations), ["cluster-admin-binding"])
        self.assertTrue(ra.gating(violations))
        self.assertIn("ServiceAccount ci/deployer", violations[0]["detail"])

    def test_a_new_subject_on_an_existing_binding_fails(self):
        other = {"kind": "Group", "name": "sre"}
        violations, _ = verdict(
            bound(binding("x", "cluster-admin", [other])),
            bound(binding("x", "cluster-admin", [other, self.subject])),
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("ci/deployer", violations[0]["detail"])

    def test_removing_a_cluster_admin_binding_is_not_a_violation(self):
        """A gate that fails a build for *taking away* cluster-admin is a gate
        people route around."""
        violations, _ = verdict(
            bound(binding("x", "cluster-admin", [self.subject])), bound()
        )
        self.assertEqual(violations, [])

    def test_an_unchanged_binding_is_not_a_violation(self):
        before = bound(binding("x", "cluster-admin", [self.subject]))
        violations, _ = verdict(before, before)
        self.assertEqual(violations, [])

    def test_a_binding_to_another_role_is_not_a_violation(self):
        violations, _ = verdict(bound(), bound(binding("x", "view", [self.subject])))
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


class DanglingBindingTest(unittest.TestCase):
    """Kubernetes accepts a binding to a ServiceAccount that does not exist and
    never warns when the subject later appears — it just starts granting."""

    ghost: ClassVar[dict] = {
        "kind": "ServiceAccount",
        "namespace": "apps",
        "name": "grafana",
    }

    def test_a_binding_to_a_missing_service_account_fires(self):
        violations, _ = verdict(
            snapshot(),
            snapshot(clusterRoleBindings=[binding("b", "view", [self.ghost])]),
        )
        self.assertEqual(rules_fired(violations), ["dangling-binding"])
        self.assertTrue(ra.gating(violations))
        self.assertIn("does not exist", violations[0]["detail"])
        # It says what creating the account would hand over.
        self.assertIn("ClusterRole/view", violations[0]["detail"])

    def test_a_binding_to_an_existing_service_account_does_not_fire(self):
        violations, _ = verdict(
            snapshot(),
            snapshot(
                clusterRoleBindings=[binding("b", "view", [self.ghost])],
                serviceAccounts=[{"namespace": "apps", "name": "grafana"}],
            ),
            pods={("apps", "grafana")},
        )
        self.assertEqual(violations, [])

    def test_a_user_or_group_subject_is_never_dangling(self):
        """Only ServiceAccounts are objects in the cluster; a User or Group is
        an assertion the authenticator makes, and this tool cannot see it."""
        for subject in (
            {"kind": "User", "name": "alice@example.com"},
            {"kind": "Group", "name": "sre"},
        ):
            with self.subTest(subject=subject):
                violations, _ = verdict(
                    snapshot(),
                    snapshot(clusterRoleBindings=[binding("b", "view", [subject])]),
                )
                self.assertEqual(violations, [])

    def test_deleting_a_dangling_binding_does_not_fire(self):
        dangling = snapshot(clusterRoleBindings=[binding("b", "view", [self.ghost])])
        violations, _ = verdict(dangling, snapshot())
        self.assertEqual(violations, [])

    def test_creating_the_missing_account_clears_it(self):
        """The fix is to create the account deliberately or drop the binding;
        either way *this* finding has to go away.

        The new account is then briefly unused, which the hygiene rule warns
        about until a pod mounts it — correct, and not this rule's business.
        """
        dangling = snapshot(clusterRoleBindings=[binding("b", "view", [self.ghost])])
        fixed = snapshot(
            clusterRoleBindings=[binding("b", "view", [self.ghost])],
            serviceAccounts=[{"namespace": "apps", "name": "grafana"}],
        )
        violations, _ = verdict(dangling, fixed, pods=set())
        self.assertNotIn("dangling-binding", rules_fired(violations))


class UnusedServiceAccountTest(unittest.TestCase):
    """A ServiceAccount no pod mounts is a credential nobody is watching."""

    def accounts(self, *names):
        return snapshot(
            serviceAccounts=[{"namespace": ns, "name": n} for ns, n in names]
        )

    def test_an_unmounted_account_warns(self):
        violations, _ = verdict(
            snapshot(), self.accounts(("staging", "old-migrator")), pods=set()
        )
        self.assertEqual(rules_fired(violations), ["unused-service-account"])
        # Hygiene, not escalation: it reports without failing the build.
        self.assertFalse(ra.gating(violations))

    def test_a_mounted_account_does_not_warn(self):
        violations, _ = verdict(
            snapshot(),
            self.accounts(("ci", "deployer")),
            pods={("ci", "deployer")},
        )
        self.assertEqual(violations, [])

    def test_default_is_never_unused(self):
        """Every namespace has one and a pod naming no account gets it."""
        violations, _ = verdict(
            snapshot(), self.accounts(("ci", "default")), pods=set()
        )
        self.assertEqual(violations, [])

    def test_the_ignore_list_is_configurable(self):
        policy = ra.merge_policy(
            {"rules": {"unused-service-account": {"ignore": ["default", "builder"]}}}
        )
        violations, _ = verdict(
            snapshot(), self.accounts(("ci", "builder")), policy, pods=set()
        )
        self.assertEqual(violations, [])

    def test_deleting_an_unused_account_does_not_warn(self):
        before = self.accounts(("staging", "old-migrator"))
        violations, _ = verdict(before, snapshot(), pods=set())
        self.assertEqual(violations, [])

    def test_it_is_skipped_rather_than_passed_without_pods(self):
        """A security check that silently does not run is worse than one that
        fails: "not checked" and "checked and clean" are different answers."""
        new = self.accounts(("staging", "old-migrator"))
        violations, _, skipped = ra.evaluate(
            ra.diff_snapshots(snapshot(), new),
            ra.merge_policy(None),
            ra.evaluation_state(new, None),
        )
        self.assertEqual(violations, [])
        self.assertEqual([name for name, _why in skipped], ["unused-service-account"])
        self.assertIn("pods", skipped[0][1])

    def test_a_disabled_rule_is_not_reported_as_skipped(self):
        """Off on purpose is not the same as could not run."""
        policy = ra.merge_policy(
            {"rules": {"unused-service-account": {"enabled": False}}}
        )
        new = self.accounts(("staging", "old-migrator"))
        _violations, _exempted, skipped = ra.evaluate(
            ra.diff_snapshots(snapshot(), new),
            policy,
            ra.evaluation_state(new, None),
        )
        self.assertEqual(skipped, [])


class NarrowingTest(unittest.TestCase):
    """CLAUDE.md: every rule needs a case for it *not* firing on the change
    that looks like it. For wildcard and escalating-verbs that change is a
    tightening, which a gate must never block — "only additions are judged"."""

    def narrow(self, before_rule, after_rule):
        violations, _ = verdict(
            snapshot(clusterRoles=[role("r", [before_rule])]),
            snapshot(clusterRoles=[role("r", [after_rule])]),
        )
        return violations

    def test_dropping_verbs_from_an_escalating_rule_does_not_fire(self):
        rule = {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["roles"],
            "verbs": ["bind", "get", "list"],
        }
        narrowed = dict(rule, verbs=["bind"])
        self.assertEqual(self.narrow(rule, narrowed), [])

    def test_dropping_resources_from_a_wildcard_rule_does_not_fire(self):
        rule = {"apiGroups": ["*"], "resources": ["pods", "secrets"], "verbs": ["get"]}
        narrowed = dict(rule, resources=["pods"])
        self.assertEqual(self.narrow(rule, narrowed), [])

    def test_adding_resource_names_to_a_wildcard_rule_does_not_fire(self):
        """Restricting a rule to named objects is strictly a tightening."""
        rule = {"apiGroups": ["*"], "resources": ["secrets"], "verbs": ["get"]}
        narrowed = dict(rule, resourceNames=["db"])
        self.assertEqual(self.narrow(rule, narrowed), [])

    def test_splitting_a_rule_in_two_does_not_fire(self):
        violations, _ = verdict(
            snapshot(
                clusterRoles=[
                    role(
                        "r",
                        [
                            {
                                "apiGroups": ["*"],
                                "resources": ["pods"],
                                "verbs": ["get", "list"],
                            }
                        ],
                    )
                ]
            ),
            snapshot(
                clusterRoles=[
                    role(
                        "r",
                        [
                            {
                                "apiGroups": ["*"],
                                "resources": ["pods"],
                                "verbs": ["get"],
                            },
                            {
                                "apiGroups": ["*"],
                                "resources": ["pods"],
                                "verbs": ["list"],
                            },
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(violations, [])

    def test_widening_the_same_rule_still_fires(self):
        """The other half: the tightening case must not have silenced the
        genuine one."""
        rule = {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["roles"],
            "verbs": ["get"],
        }
        widened = dict(rule, verbs=["bind", "get"])
        self.assertEqual(rules_fired(self.narrow(rule, widened)), ["escalating-verbs"])

    def test_narrowing_a_bindings_role_does_not_fire_anonymous_subject(self):
        """roleRef edit -> view with the same subject is a tightening. The
        subject was already bound here, so it is not newly bound."""
        anon = [{"kind": "Group", "name": "system:unauthenticated"}]
        violations, _ = verdict(
            snapshot(clusterRoleBindings=[binding("b", "edit", anon)]),
            snapshot(clusterRoleBindings=[binding("b", "view", anon)]),
        )
        self.assertEqual(violations, [])

    def test_repointing_a_binding_at_cluster_admin_still_fires(self):
        """…but the role the binding grants is a different question: every
        subject in it now holds cluster-admin."""
        subjects = [{"kind": "ServiceAccount", "namespace": "ci", "name": "deployer"}]
        violations, _ = verdict(
            snapshot(clusterRoleBindings=[binding("b", "view", subjects)]),
            snapshot(clusterRoleBindings=[binding("b", "cluster-admin", subjects)]),
        )
        self.assertEqual(rules_fired(violations), ["cluster-admin-binding"])


class CollapseTest(unittest.TestCase):
    def test_one_rule_yields_one_finding_per_reason_not_per_grant(self):
        """A rule granting `*` over five resources and three verbs is fifteen
        new grants. Fifteen identical findings is a report nobody reads."""
        violations, _ = verdict(
            snapshot(),
            snapshot(
                clusterRoles=[
                    role(
                        "r",
                        [
                            {
                                "apiGroups": ["*"],
                                "resources": ["pods", "secrets", "configmaps"],
                                "verbs": ["get", "list"],
                            }
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["collapsed"], 5)

    def test_distinct_escalating_verbs_stay_distinct(self):
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
                                "verbs": ["bind", "escalate"],
                            }
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(rules_fired(violations), ["escalating-verbs"])
        self.assertEqual(len(violations), 2)


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
        violations, exempted = verdict(old, new, policy)
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
        violations, _ = verdict(snapshot(), other, policy)
        self.assertEqual(rules_fired(violations), ["wildcard"])

    def test_fail_false_reports_without_gating(self):
        policy = ra.merge_policy(
            {"rules": {name: {"fail": False} for name in ra.CHECKS}}
        )
        old, new = self.wildcard_change()
        violations, _ = verdict(old, new, policy)
        self.assertTrue(violations)
        self.assertFalse(ra.gating(violations))

    def test_disabled_rule_stops_looking(self):
        policy = ra.merge_policy({"rules": {"wildcard": {"enabled": False}}})
        old, new = self.wildcard_change()
        violations, _ = verdict(old, new, policy)
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
        violations, exempted = verdict(snapshot(), new, policy)
        self.assertEqual(violations, [])
        self.assertEqual(len(exempted), 1)


class PolicyFileTest(unittest.TestCase):
    """A gate nobody can read is worse than no gate, so these are all fatal."""

    # Hygiene rather than escalation: the one rule that warns instead of
    # blocking, because on a first `baseline` it is usually the longest list
    # and a gate that is red on day one is a gate that gets switched off.
    WARN_BY_DEFAULT: ClassVar[set] = {"unused-service-account"}

    def test_defaults_are_on(self):
        policy = ra.merge_policy(None)
        for name, settings in policy["rules"].items():
            with self.subTest(rule=name):
                self.assertTrue(settings["enabled"])

    def test_escalation_rules_block_and_only_hygiene_warns(self):
        policy = ra.merge_policy(None)
        for name, settings in policy["rules"].items():
            with self.subTest(rule=name):
                self.assertEqual(settings["fail"], name not in self.WARN_BY_DEFAULT)

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

    def test_a_scalar_where_a_list_belongs_is_fatal(self):
        """`verbs: bind` instead of `verbs: [bind]` would turn a membership
        test into a substring one — the check silently stops working."""
        with self.assertRaises(ra.PolicyError) as caught:
            ra.merge_policy({"rules": {"escalating-verbs": {"verbs": "bind"}}})
        self.assertIn("list of strings", str(caught.exception))

    def test_a_scalar_roles_list_cannot_become_a_substring_match(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy(
                {"rules": {"cluster-admin-binding": {"roles": "cluster-admin"}}}
            )

    def test_a_null_list_is_fatal(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"rules": {"wildcard": {"fields": None}}})

    def test_a_non_bool_enabled_is_fatal(self):
        with self.assertRaises(ra.PolicyError) as caught:
            ra.merge_policy({"rules": {"wildcard": {"enabled": "no"}}})
        self.assertIn("true or false", str(caught.exception))

    def test_a_non_string_exempt_value_is_fatal(self):
        """_matches globs with str.endswith; a list here was a traceback."""
        with self.assertRaises(ra.PolicyError) as caught:
            ra.merge_policy({"exempt": [{"object": ["A", "B"], "reason": "x"}]})
        self.assertIn("must be a string", str(caught.exception))

    def test_a_non_string_reason_is_fatal(self):
        with self.assertRaises(ra.PolicyError):
            ra.merge_policy({"exempt": [{"object": "ClusterRole/x", "reason": True}]})

    def test_the_shipped_example_is_valid(self):
        path = Path(__file__).resolve().parent.parent / ".rbac-policy.example.yaml"
        policy = ra.merge_policy(yaml.safe_load(path.read_text()))
        self.assertEqual(sorted(policy["rules"]), sorted(ra.CHECKS))
        self.assertTrue(policy["exempt"])


if __name__ == "__main__":
    unittest.main()
