"""Tests for the exit codes.

stdlib unittest, run with `python3 -m unittest discover tests`: the image has
no test framework in it and this is not worth adding one for.

The codes are the tool's contract with CI. 2 in particular is documented in
docs/architecture.md and is what a pipeline gates on, so it is asserted here
rather than left to a reader of the source.
"""

import io
import json
import logging
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import ClassVar
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

# These tests drive the error paths on purpose. Keep their diagnostics out of
# the suite's own output; assertLogs still sees the records.
ra.log.addHandler(logging.NullHandler())
ra.log.propagate = False


def exit_code(fn, *args, **kwargs):
    """Run `fn`, swallow its stdout, and return the code it exited with."""
    with redirect_stdout(io.StringIO()):
        try:
            fn(*args, **kwargs)
        except SystemExit as exc:
            return exc.code
    return None


class ReportGateTest(unittest.TestCase):
    """`report` exits 2 only when asked to gate. This is the documented one."""

    snap: ClassVar[dict] = {
        "taken_at": "2026-08-15T00:00:00Z",
        "roles": [],
        "clusterroles": [
            {
                "metadata": {"name": "admin"},
                "rules": [{"verbs": ["*"], "resources": ["*"]}],
            }
        ],
        "rolebindings": [],
        "clusterrolebindings": [],
        "serviceaccounts": [],
        "pods": [],
    }

    def run_report(self, *flags):
        argv = ["report", "--ignore-file", "/nonexistent/.rbac-audit-ignore", *flags]
        with mock.patch.object(ra, "snapshot", return_value=self.snap):
            return exit_code(ra.run_report, argv)

    def test_findings_without_the_flag_are_still_a_success(self):
        self.assertEqual(self.run_report(), ra.EXIT_OK)

    def test_findings_with_the_flag_exit_2(self):
        self.assertEqual(self.run_report("--fail-on-findings"), ra.EXIT_FINDINGS)
        self.assertEqual(ra.EXIT_FINDINGS, 2)

    def test_no_findings_never_exits_2(self):
        empty = dict(self.snap, clusterroles=[])
        with mock.patch.object(ra, "snapshot", return_value=empty):
            code = exit_code(
                ra.run_report,
                ["report", "--ignore-file", "/nonexistent", "--fail-on-findings"],
            )
        self.assertEqual(code, ra.EXIT_OK)

    def test_unreadable_ignore_file_is_a_data_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "ignore"
            bad.write_text("role=admin\n")  # no reason=
            code = exit_code(ra.run_report, ["report", "--ignore-file", str(bad)])
        self.assertEqual(code, ra.EXIT_DATAERR)


class ClusterUnreachableTest(unittest.TestCase):
    def test_kubectl_failure_is_unavailable_not_1(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="connection refused")
        with mock.patch("subprocess.run", return_value=failed):
            code = exit_code(ra.kubectl_json, "roles")
        self.assertEqual(code, ra.EXIT_UNAVAILABLE)


class SnapshotFileTest(unittest.TestCase):
    def test_missing_snapshot_is_noinput(self):
        code = exit_code(ra.load_snapshot, "/nonexistent/january.json")
        self.assertEqual(code, ra.EXIT_NOINPUT)

    def test_unparseable_snapshot_is_dataerr(self):
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "january.json"
            junk.write_text("not json at all")
            code = exit_code(ra.load_snapshot, str(junk))
        self.assertEqual(code, ra.EXIT_DATAERR)

    def test_a_real_snapshot_comes_back_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "january.json"
            good.write_text(json.dumps({"roles": [], "taken_at": "x"}))
            self.assertEqual(
                ra.load_snapshot(str(good)), {"roles": [], "taken_at": "x"}
            )


class UsageTest(unittest.TestCase):
    def test_flag_without_a_value_is_a_usage_error(self):
        self.assertEqual(
            exit_code(ra.flag_value, ["report", "--html"], "--html"), ra.EXIT_USAGE
        )

    def test_flag_with_a_value_is_returned(self):
        self.assertEqual(
            ra.flag_value(["report", "--html", "r.html"], "--html"), "r.html"
        )

    def test_absent_flag_gives_the_default(self):
        self.assertEqual(ra.flag_value(["report"], "--html", "fallback"), "fallback")

    def test_unknown_command_is_a_usage_error(self):
        with mock.patch.object(sys, "argv", ["rbac-audit", "frobnicate"]):
            self.assertEqual(exit_code(ra.main), ra.EXIT_USAGE)

    def test_diff_without_a_snapshot_is_a_usage_error(self):
        with mock.patch.object(sys, "argv", ["rbac-audit", "diff"]):
            self.assertEqual(exit_code(ra.main), ra.EXIT_USAGE)

    def test_who_can_without_both_operands_is_a_usage_error(self):
        with mock.patch.object(sys, "argv", ["rbac-audit", "who-can", "delete"]):
            self.assertEqual(exit_code(ra.main), ra.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
