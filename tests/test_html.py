"""Tests for the HTML report and its S3 upload.

stdlib unittest, run with `python3 -m unittest discover tests`: the image has
no test framework in it and this is not worth adding one for.
"""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from html.parser import HTMLParser
from pathlib import Path
from typing import ClassVar
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

SNAP = {
    "taken_at": "2026-08-15T09:00:00+00:00",
    "roles": [],
    "clusterroles": [
        {"metadata": {"name": "admin"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}
    ],
    "rolebindings": [],
    "clusterrolebindings": [
        {
            "metadata": {"name": "grant"},
            "roleRef": {"name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "<script>alert(1)</script>"}],
        }
    ],
    "serviceaccounts": [],
    "pods": [],
}


class WellFormed(HTMLParser):
    """Minimal well-formedness check: every non-void tag is closed, in order."""

    VOID: ClassVar[set] = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack:
            self.errors.append(f"</{tag}> with nothing open")
        elif self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
        else:
            self.stack.pop()


class HTMLReportTest(unittest.TestCase):
    def render(self, identity=None):
        return ra.html_report(SNAP, identity)

    def test_is_well_formed(self):
        p = WellFormed()
        p.feed(self.render())
        self.assertEqual(p.errors, [])
        self.assertEqual(p.stack, [], "unclosed tags")

    def test_is_self_contained(self):
        html = self.render()
        # No external asset can be fetched: no src=, no href=, no @import.
        for needle in ("src=", "href=", "@import", "//cdn", "http://", "https://"):
            self.assertNotIn(needle, html, f"report reaches out for {needle!r}")
        self.assertIn("<style>", html)

    def test_states_cluster_identity_and_time(self):
        html = self.render({"context": "prod-eu", "server": "https://k8s.example:6443"})
        self.assertIn("prod-eu", html)
        self.assertIn("k8s.example:6443", html)
        self.assertIn("2026-08-15T09:00:00+00:00", html)

    def test_findings_are_escaped_not_injected(self):
        html = self.render()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_backticks_become_code_not_literal(self):
        html = self.render()
        self.assertIn("<code>admin</code>", html)
        self.assertNotIn("`", html)

    def test_says_it_is_sensitive(self):
        self.assertIn("sensitive", self.render())

    def test_counts_match_the_findings(self):
        html = self.render()
        self.assertIn("<strong>2 findings.</strong>", html)

    def test_empty_section_says_none(self):
        self.assertIn('<p class="none">None.</p>', self.render())

    def test_suppressions_apply_and_are_listed(self):
        rules = ra.parse_ignore("role=admin reason=ships with Kubernetes")
        html = ra.html_report(SNAP, None, rules)
        self.assertIn("<strong>1 findings.</strong> (1 suppressed)", html)
        self.assertIn("(1 suppressed)</h2>", html)
        self.assertIn("<em>ships with Kubernetes</em>", html)


class UploadTest(unittest.TestCase):
    def test_builds_the_expected_command(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stderr="")
            err = ra.upload_s3("/tmp/report.html", "s3://bucket/audits/", sse="aws:kms")
        self.assertIsNone(err)
        self.assertEqual(
            run.call_args.args[0],
            [
                "aws",
                "s3",
                "cp",
                "/tmp/report.html",
                "s3://bucket/audits/report.html",
                "--sse",
                "aws:kms",
            ],
        )

    def test_default_encryption_is_requested(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stderr="")
            ra.upload_s3("/tmp/r.html", "s3://b/p")
        self.assertIn("--sse", run.call_args.args[0])
        self.assertIn("AES256", run.call_args.args[0])

    def test_failure_is_reported_not_raised(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stderr="AccessDenied")
            err = ra.upload_s3("/tmp/r.html", "s3://b/p")
        self.assertEqual(err, "AccessDenied")

    def test_missing_aws_cli_is_reported_not_raised(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            err = ra.upload_s3("/tmp/r.html", "s3://b/p")
        self.assertIn("aws CLI not found", err)


class IdentityTest(unittest.TestCase):
    def test_degrades_to_unknown_when_kubectl_cannot_say(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="nope")
            ident = ra.cluster_identity()
        self.assertEqual(ident, {"context": "unknown", "server": "unknown"})

    def test_reads_context_and_server(self):
        outputs = [
            mock.Mock(returncode=0, stdout="prod-eu\n"),
            mock.Mock(
                returncode=0,
                stdout='{"clusters":[{"cluster":{"server":"https://k8s:6443"}}]}',
            ),
        ]
        with mock.patch("subprocess.run", side_effect=outputs):
            ident = ra.cluster_identity()
        self.assertEqual(ident, {"context": "prod-eu", "server": "https://k8s:6443"})

    def test_malformed_kubeconfig_json_is_not_fatal(self):
        outputs = [
            mock.Mock(returncode=0, stdout="ctx\n"),
            mock.Mock(returncode=0, stdout="not json"),
        ]
        with mock.patch("subprocess.run", side_effect=outputs):
            ident = ra.cluster_identity()
        self.assertEqual(ident["server"], "unknown")


class DiagnosticsTest(unittest.TestCase):
    """Diagnostics belong on the logger; stdout belongs to the report.

    `rbac-audit report > audit.md` has to produce a markdown file, so anything
    that is not the report itself must not reach stdout.
    """

    def test_html_and_s3_notes_are_logged_and_stay_off_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "r.html")
            argv = ["report", "--html", out, "--s3", "s3://b/p"]
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    ra, "cluster_identity", return_value={"context": "c", "server": "s"}
                ),
                mock.patch.object(ra, "upload_s3", return_value="AccessDenied"),
                redirect_stdout(stdout),
                self.assertLogs(ra.log, level="INFO") as logs,
            ):
                ra.deliver_html(argv, SNAP, ())
        self.assertIn(f"INFO:rbac-audit:HTML report written to {out}", logs.output)
        self.assertIn(
            f"WARNING:rbac-audit:S3 upload failed (AccessDenied); {out} kept",
            logs.output,
        )
        self.assertEqual(stdout.getvalue(), "")

    def test_kubectl_failure_is_logged_at_error_and_exits(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="the server rejected it\n")
        with (
            mock.patch("subprocess.run", return_value=failed),
            self.assertLogs(ra.log, level="ERROR") as logs,
            self.assertRaises(SystemExit),
        ):
            ra.kubectl_json("roles")
        # test.sh greps the image's output for exactly this phrase.
        self.assertIn("kubectl get roles failed", "\n".join(logs.output))
        self.assertIn("the server rejected it", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
