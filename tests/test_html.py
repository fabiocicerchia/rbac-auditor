"""Tests for the HTML report and its S3 upload.

stdlib unittest, run with `python3 -m unittest discover tests`: the image has
no test framework in it and this is not worth adding one for.
"""
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra  # noqa: E402

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

    VOID = {"meta", "br", "hr", "img", "input", "link"}

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


class UploadTest(unittest.TestCase):
    def test_builds_the_expected_command(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stderr="")
            err = ra.upload_s3("/tmp/report.html", "s3://bucket/audits/", sse="aws:kms")
        self.assertIsNone(err)
        self.assertEqual(
            run.call_args.args[0],
            ["aws", "s3", "cp", "/tmp/report.html", "s3://bucket/audits/report.html",
             "--sse", "aws:kms"],
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


if __name__ == "__main__":
    unittest.main()
