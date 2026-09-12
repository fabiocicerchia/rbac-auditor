"""Tests for the command line: exit codes, and the files-only path.

stdlib unittest, run with `python3 -m unittest discover tests`.

The codes are this tool's contract with CI. 2 in particular is documented in
docs/architecture.md and is what a pipeline gates on, so it is asserted here
rather than left to a reader of the source. Nothing in this file starts a
cluster or calls kubectl: `diff OLD NEW` is the path CI without cluster access
takes, and it has to be exercised the same way.
"""

import io
import json
import logging
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BEFORE = str(FIXTURES / "before.json")
AFTER = str(FIXTURES / "after.json")

# These tests drive the error paths on purpose. Keep their diagnostics out of
# the suite's own output; assertLogs still sees the records.
ra.log.addHandler(logging.NullHandler())
ra.log.propagate = False


def run(argv):
    """Run the CLI, return (exit code, stdout)."""
    out = io.StringIO()
    parser = ra.build_parser()
    args = parser.parse_args(argv)
    with redirect_stdout(out):
        try:
            args.func(args)
        except SystemExit as exc:
            return exc.code, out.getvalue()
    return None, out.getvalue()


class ExitCodeTest(unittest.TestCase):
    def test_policy_violations_exit_2(self):
        code, _ = run(["diff", BEFORE, AFTER])
        self.assertEqual(code, ra.EXIT_VIOLATIONS)

    def test_no_changes_exits_0(self):
        code, out = run(["diff", BEFORE, BEFORE])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("No changes.", out)
        self.assertIn("No policy violations.", out)

    def test_no_policy_shows_what_would_have_blocked(self):
        """The docs tell people to run this for a week and read what it would
        have blocked, so it has to print the violations — not hide them."""
        code, out = run(["diff", BEFORE, AFTER, "--no-policy"])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("ClusterRoleBinding/ci-admin", out)
        self.assertIn("Policy violations", out)
        self.assertIn("cluster-admin-binding", out)
        self.assertIn("(warn)", out)
        self.assertIn("(none gating)", out)
        self.assertNotIn("No policy violations.", out)

    def test_a_missing_snapshot_exits_66(self):
        code, _ = run(["diff", str(FIXTURES / "nope.json"), AFTER])
        self.assertEqual(code, ra.EXIT_NOINPUT)

    def test_a_missing_policy_file_exits_66(self):
        code, _ = run(["diff", BEFORE, AFTER, "--policy", "/nonexistent/policy.yaml"])
        self.assertEqual(code, ra.EXIT_NOINPUT)

    def test_a_file_that_is_not_a_snapshot_exits_65(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "junk.json"
            path.write_text("{}")
            code, _ = run(["diff", str(path), AFTER])
        self.assertEqual(code, ra.EXIT_DATAERR)

    def test_a_snapshot_that_is_not_json_exits_65(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("not json at all")
            code, _ = run(["diff", str(path), AFTER])
        self.assertEqual(code, ra.EXIT_DATAERR)

    def test_an_unparseable_policy_exits_65(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yaml"
            path.write_text("rules:\n  wildcards:\n    enabled: false\n")
            code, _ = run(["diff", BEFORE, AFTER, "--policy", str(path)])
        self.assertEqual(code, ra.EXIT_DATAERR)

    def test_a_usage_error_exits_64_not_2(self):
        """argparse exits 2 by default, which this tool spends on 'the policy
        failed'. A pipeline must not read a typo as a security finding."""
        parser = ra.build_parser()
        with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()):
            parser.parse_args(["diff"])
        self.assertEqual(caught.exception.code, ra.EXIT_USAGE)


class NoClusterTest(unittest.TestCase):
    def test_a_missing_kubectl_is_a_message_not_a_traceback(self):
        """The image ships kubectl; a `pip install` does not."""
        with (
            mock.patch("rbac_audit.subprocess.run", side_effect=FileNotFoundError),
            self.assertLogs(ra.log, "ERROR") as logs,
            self.assertRaises(SystemExit) as caught,
        ):
            ra.kubectl_json("clusterroles")
        self.assertEqual(caught.exception.code, ra.EXIT_UNAVAILABLE)
        self.assertIn("kubectl is not on PATH", logs.output[0])

    def test_a_two_file_diff_never_calls_kubectl(self):
        """The path CI without cluster access takes."""
        with mock.patch("rbac_audit.subprocess.run") as run_mock:
            code, _ = run(["diff", BEFORE, AFTER])
        run_mock.assert_not_called()
        self.assertEqual(code, ra.EXIT_VIOLATIONS)


class BaselineTest(unittest.TestCase):
    """Drift detection assumes a good baseline; on day one nobody has one. A
    cluster that is already dangerous and never changes is invisible to a diff,
    so `baseline` judges the whole thing against the same policy."""

    def test_it_judges_a_whole_snapshot(self):
        code, out = run(["baseline", AFTER])
        self.assertEqual(code, ra.EXIT_VIOLATIONS)
        self.assertIn("RBAC baseline", out)
        # Everything is an addition, so every standing problem is reported —
        # including the ones a before/after diff of the same fixtures misses.
        self.assertIn("cluster-admin-binding", out)
        self.assertIn("anonymous-subject", out)
        self.assertIn("ClusterRole/cluster-admin", out)

    def test_a_clean_cluster_baselines_clean(self):
        clean = {"apiVersion": ra.SNAPSHOT_VERSION, "kind": ra.SNAPSHOT_KIND}
        for key in ra.SECTION_KEYS:
            clean[key] = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.json"
            path.write_text(json.dumps(clean))
            code, out = run(["baseline", str(path)])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("No changes.", out)

    def test_it_says_which_rules_it_could_not_run(self):
        """Against a file there are no pods, so the unused-ServiceAccount rule
        cannot run. Reporting it as a pass would be a lie about what was
        checked."""
        code, out = run(["baseline", AFTER])
        self.assertIn("Not checked (1)", out)
        self.assertIn("unused-service-account", out)
        self.assertIn("live cluster", out)
        self.assertEqual(code, ra.EXIT_VIOLATIONS)

    def test_the_machine_report_names_them_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            run(["baseline", AFTER, "--json", str(path)])
            data = json.loads(path.read_text())
        self.assertEqual(
            [entry["rule"] for entry in data["notChecked"]], ["unused-service-account"]
        )
        self.assertEqual(data["from"], "an empty cluster")
        self.assertEqual(data["to"], AFTER)

    def test_no_policy_works_the_same_way(self):
        code, out = run(["baseline", AFTER, "--no-policy"])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("(warn)", out)

    def test_it_reads_the_live_cluster_when_given_no_file(self):
        snap = ra.load_snapshot(AFTER)
        with (
            mock.patch("rbac_audit.capture", return_value=snap) as capture_mock,
            mock.patch(
                "rbac_audit.capture_pod_service_accounts", return_value=set()
            ) as pods_mock,
        ):
            code, out = run(["baseline"])
        capture_mock.assert_called_once()
        # The pods it needs are read from the cluster, never from the snapshot.
        pods_mock.assert_called_once()
        self.assertEqual(code, ra.EXIT_VIOLATIONS)
        self.assertIn("live cluster", out)
        self.assertNotIn("Not checked", out)
        self.assertIn("unused-service-account", out)


class InputOrderTest(unittest.TestCase):
    """What the command line alone can reject is rejected before the cluster
    is read: a typo must not exit 69 because kubectl failed, and must not cost
    a full cluster read to find out about."""

    def test_a_malformed_subject_is_64_even_in_live_cluster_mode(self):
        with mock.patch("rbac_audit.capture") as capture_mock:
            code, _ = run(["diff", BEFORE, "--subject", "Robot/ci/x"])
        capture_mock.assert_not_called()
        self.assertEqual(code, ra.EXIT_USAGE)

    def test_an_unreadable_policy_is_65_before_the_cluster_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yaml"
            path.write_text("rules:\n  nope: {}\n")
            with mock.patch("rbac_audit.capture") as capture_mock:
                code, _ = run(["diff", BEFORE, "--policy", str(path)])
        capture_mock.assert_not_called()
        self.assertEqual(code, ra.EXIT_DATAERR)

    def test_a_namespace_on_a_group_is_a_usage_error(self):
        """`Group/ci/system:unauthenticated` can never match anything, so
        reporting "no permissions" would read as an answer, not a typo."""
        with self.assertRaises(SystemExit) as caught:
            ra.parse_subject("Group/ci/system:unauthenticated")
        self.assertEqual(caught.exception.code, ra.EXIT_USAGE)


class DiffReportIsNotASnapshotTest(unittest.TestCase):
    def test_a_json_diff_report_is_refused_as_a_snapshot(self):
        """Both files carry the same apiVersion, so `kind` has to separate
        them. Read as a snapshot, a diff report looks like an empty cluster —
        which reports everything as newly added and fails the build."""
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "diff.json"
            run(["diff", BEFORE, AFTER, "--json", str(report)])
            self.assertEqual(json.loads(report.read_text())["kind"], ra.DIFF_KIND)
            with self.assertLogs(ra.log, "ERROR") as logs:
                code, _ = run(["diff", str(report), AFTER])
        self.assertEqual(code, ra.EXIT_DATAERR)
        self.assertIn("diff report", logs.output[0])

    def test_a_snapshot_declares_its_kind(self):
        self.assertEqual(ra.load_snapshot(BEFORE)["kind"], ra.SNAPSHOT_KIND)


class MalformedSnapshotTest(unittest.TestCase):
    """Structure, not just the version stamp: this is the input to a gate."""

    def check(self, mutate):
        snap = json.loads(Path(BEFORE).read_text())
        mutate(snap)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snap.json"
            path.write_text(json.dumps(snap))
            with self.assertLogs(ra.log, "ERROR"):
                code, _ = run(["diff", str(path), AFTER])
        return code

    def test_a_section_that_is_not_a_list(self):
        self.assertEqual(
            self.check(lambda s: s.update(clusterRoles={"name": "x"})), ra.EXIT_DATAERR
        )

    def test_an_item_that_is_not_an_object(self):
        self.assertEqual(
            self.check(lambda s: s.update(clusterRoles=["view"])), ra.EXIT_DATAERR
        )

    def test_an_item_with_no_name(self):
        self.assertEqual(
            self.check(lambda s: s.update(clusterRoles=[{"rules": []}])),
            ra.EXIT_DATAERR,
        )

    def test_rules_that_are_not_a_list(self):
        self.assertEqual(
            self.check(
                lambda s: s.update(clusterRoles=[{"name": "v", "rules": "all"}])
            ),
            ra.EXIT_DATAERR,
        )

    def test_a_rule_field_that_is_not_a_list_of_strings(self):
        self.assertEqual(
            self.check(
                lambda s: s.update(
                    clusterRoles=[{"name": "v", "rules": [{"verbs": [1, 2]}]}]
                )
            ),
            ra.EXIT_DATAERR,
        )

    def test_a_role_ref_that_is_not_an_object(self):
        self.assertEqual(
            self.check(
                lambda s: s.update(
                    clusterRoleBindings=[{"name": "b", "roleRef": "view"}]
                )
            ),
            ra.EXIT_DATAERR,
        )

    def test_subjects_that_are_not_objects(self):
        self.assertEqual(
            self.check(
                lambda s: s.update(
                    clusterRoleBindings=[
                        {
                            "name": "b",
                            "roleRef": {"kind": "ClusterRole", "name": "v"},
                            "subjects": ["alice"],
                        }
                    ]
                )
            ),
            ra.EXIT_DATAERR,
        )


class PolicyFlagTest(unittest.TestCase):
    def test_an_exempting_policy_clears_the_gate(self):
        policy = """version: 1
exempt:
  - object: "ClusterRoleBinding/ci-admin"
    reason: the CI deployer, reviewed 2026-09
  - object: "Role/ci/deploy"
    reason: reviewed with the deploy change
  - object: "ClusterRoleBinding/view-everyone"
    reason: public read, deliberate
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yaml"
            path.write_text(policy)
            code, out = run(["diff", BEFORE, AFTER, "--policy", str(path)])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("Exempted (", out)
        self.assertIn("No policy violations.", out)

    def test_warn_only_rules_report_but_do_not_gate(self):
        policy = "version: 1\nrules:\n" + "".join(
            f"  {name}:\n    fail: false\n" for name in ra.CHECKS
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yaml"
            path.write_text(policy)
            code, out = run(["diff", BEFORE, AFTER, "--policy", str(path)])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("(warn)", out)


class MachineOutputTest(unittest.TestCase):
    def test_json_and_text_come_from_the_same_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "diff.json"
            code, out = run(["diff", BEFORE, AFTER, "--json", str(path)])
            data = json.loads(path.read_text())
        self.assertEqual(code, ra.EXIT_VIOLATIONS)
        # Whatever the count is, both renderings have to agree on it — they
        # come from one run, so they cannot be allowed to disagree.
        count = data["summary"]["violations"]
        self.assertIn(f"{count} policy violations", out)
        self.assertEqual(count, len(data["violations"]))
        # bind and escalate are separate escalation paths, so separate findings.
        self.assertEqual(
            sorted(v["rule"] for v in data["violations"]),
            [
                "anonymous-subject",
                "cluster-admin-binding",
                "escalating-verbs",
                "escalating-verbs",
                "wildcard",
            ],
        )
        self.assertEqual(data["apiVersion"], ra.SNAPSHOT_VERSION)
        self.assertEqual(data["to"], AFTER)

    def test_json_to_stdout_is_the_only_thing_on_stdout(self):
        """`--json -` has to stay parseable; printing the human report next to
        it would corrupt the pipe it exists for."""
        code, out = run(["diff", BEFORE, AFTER, "--json", "-"])
        self.assertEqual(code, ra.EXIT_VIOLATIONS)
        json.loads(out)

    def test_the_subject_matrix_is_in_the_machine_output(self):
        code, out = run(
            [
                "diff",
                BEFORE,
                AFTER,
                "--subject",
                "ServiceAccount/ci/deployer",
                "--json",
                "-",
            ]
        )
        data = json.loads(out)
        self.assertEqual(code, ra.EXIT_VIOLATIONS)
        self.assertEqual(data["subject"], "ServiceAccount/ci/deployer")
        self.assertIn("patch", data["matrix"]["verbs"])
        self.assertTrue(data["matrix"]["rows"])

    def test_the_report_carries_grant_counts_not_every_grant(self):
        """One rule over many resources and verbs expands to thousands of
        grants. They are how the policy decides, not something to serialise:
        a first-run diff of a real cluster would be tens of megabytes."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "diff.json"
            run(["diff", BEFORE, AFTER, "--json", str(path)])
            data = json.loads(path.read_text())
        role = next(c for c in data["changes"] if c["object"] == "Role/ci/deploy")
        self.assertNotIn("grants", role)
        # patch on deployments, bind and escalate on roles, get on secrets.*
        # — and nothing lost: the deployments rule gained a verb, it did not
        # trade one away.
        self.assertEqual(role["grantCounts"], {"added": 4, "removed": 0})
        # `rules` is still there: it is what somebody has to go and edit.
        self.assertIn("rules", role)

    def test_a_binding_change_has_no_grant_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "diff.json"
            run(["diff", BEFORE, AFTER, "--json", str(path)])
            data = json.loads(path.read_text())
        binding = next(
            c for c in data["changes"] if c["object"] == "ClusterRoleBinding/ci-admin"
        )
        self.assertNotIn("grantCounts", binding)
        self.assertIn("newlyGranted", binding)

    def test_machine_output_is_deterministic(self):
        first = run(["diff", BEFORE, AFTER, "--json", "-"])[1]
        second = run(["diff", BEFORE, AFTER, "--json", "-"])[1]
        self.assertEqual(first, second)


class SubjectCommandTest(unittest.TestCase):
    def test_the_matrix_replaces_the_object_diff(self):
        _, out = run(["diff", BEFORE, AFTER, "--subject", "ServiceAccount/ci/deployer"])
        self.assertIn("Subject: ServiceAccount ci/deployer", out)
        self.assertIn("NAMESPACE", out)
        self.assertIn("deployments.apps", out)

    def test_an_untouched_subject_exits_0(self):
        code, out = run(["diff", BEFORE, AFTER, "--subject", "User/nobody"])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("no permissions", out.lower())


if __name__ == "__main__":
    unittest.main()
