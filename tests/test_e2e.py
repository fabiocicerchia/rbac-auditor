"""End to end: the pull-request gate, run as CI runs it.

stdlib unittest, run with `python3 -m unittest discover tests`.

test_cli.py calls each command's function in-process. This file starts
`rbac_audit.py` as its own process instead, so main(), argv parsing, logging
to stderr and the process exit code are all on the path being tested. No
cluster, no kubectl, no image: `snapshot --from-manifests` and `diff OLD NEW`
are what a pull request runs.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = Path(__file__).resolve().parent / "fixtures" / "manifests"


class PullRequestGateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def cli(self, *argv):
        # cwd is the temp dir, so no ./.rbac-policy.yaml is picked up by accident.
        return subprocess.run(
            [sys.executable, str(ROOT / "rbac_audit.py"), *argv],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )

    def snapshot(self, tree, name):
        result = self.cli("snapshot", "--from-manifests", str(tree), "-o", name)
        self.assertEqual(result.returncode, ra.EXIT_OK, result.stderr)
        return name

    def test_an_unchanged_tree_passes_the_gate(self):
        base = self.snapshot(MANIFESTS, "base.json")
        pr = self.snapshot(MANIFESTS, "pr.json")
        self.assertEqual((self.tmp / base).read_bytes(), (self.tmp / pr).read_bytes())
        result = self.cli("diff", base, pr)
        self.assertEqual(result.returncode, ra.EXIT_OK, result.stderr)
        self.assertIn("No changes.", result.stdout)

    def test_a_pr_that_grants_cluster_admin_fails_the_gate(self):
        base = self.snapshot(MANIFESTS, "base.json")
        tree = self.tmp / "pr"
        shutil.copytree(MANIFESTS, tree)
        admins = tree / "rbac" / "admins.yml"
        admins.write_text(
            admins.read_text().replace("name: view", "name: cluster-admin")
        )
        pr = self.snapshot(tree, "pr.json")

        result = self.cli("diff", base, pr, "--json", "report.json")
        self.assertEqual(result.returncode, ra.EXIT_VIOLATIONS, result.stderr)
        self.assertIn("platform-admins", result.stdout)
        self.assertIn("cluster-admin-binding", (self.tmp / "report.json").read_text())
        json.loads((self.tmp / "report.json").read_text())

    def test_no_command_is_a_usage_error(self):
        result = self.cli()
        self.assertEqual(result.returncode, ra.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
