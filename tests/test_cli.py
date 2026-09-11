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

    def test_no_policy_reports_without_gating(self):
        code, out = run(["diff", BEFORE, AFTER, "--no-policy"])
        self.assertEqual(code, ra.EXIT_OK)
        self.assertIn("ClusterRoleBinding/ci-admin", out)

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
        ):
            with self.assertRaises(SystemExit) as caught:
                ra.kubectl_json("clusterroles")
        self.assertEqual(caught.exception.code, ra.EXIT_UNAVAILABLE)
        self.assertIn("kubectl is not on PATH", logs.output[0])

    def test_a_two_file_diff_never_calls_kubectl(self):
        """The path CI without cluster access takes."""
        with mock.patch("rbac_audit.subprocess.run") as run_mock:
            code, _ = run(["diff", BEFORE, AFTER])
        run_mock.assert_not_called()
        self.assertEqual(code, ra.EXIT_VIOLATIONS)


class PolicyFlagTest(unittest.TestCase):
    def test_an_exempting_policy_clears_the_gate(self):
        policy = "\n".join(
            [
                "version: 1",
                "exempt:",
                '  - object: "ClusterRoleBinding/ci-admin"',
                "    reason: the CI deployer, reviewed 2026-09",
                '  - object: "Role/ci/deploy"',
                "    reason: reviewed with the deploy change",
                '  - object: "ClusterRoleBinding/view-everyone"',
                "    reason: public read, deliberate",
                "",
            ]
        )
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
        # The human report says four; so must the machine one.
        self.assertIn("4 policy violations", out)
        self.assertEqual(data["summary"]["violations"], 4)
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
