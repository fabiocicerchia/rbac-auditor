"""Integration: the live-cluster path, through a real kubectl process.

stdlib unittest, run with `python3 -m unittest discover tests`.

test_cli.py mocks `subprocess.run` or `capture`, so the argv kubectl is
started with, the JSON it prints and its exit status are never on the path.
Here a stand-in `kubectl` executable sits first on PATH and answers
`get RESOURCE -A -o json` from files, so `rbac_audit.py` runs as its own
process and reads the cluster the way it does in the image. No real cluster
is needed, which keeps this runnable in CI.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rbac_audit as ra

ROOT = Path(__file__).resolve().parent.parent

# Logs its argv, then prints $FAKE_CLUSTER/<resource>.json; a resource with
# no file fails the way kubectl does when the API server refuses the request.
FAKE_KUBECTL = textwrap.dedent(
    f"""\
    #!{sys.executable}
    import os, sys
    cluster = os.environ["FAKE_CLUSTER"]
    with open(os.path.join(cluster, "argv.log"), "a") as log:
        log.write(" ".join(sys.argv[1:]) + "\\n")
    resource = sys.argv[sys.argv.index("get") + 1]
    path = os.path.join(cluster, resource + ".json")
    if not os.path.exists(path):
        sys.stderr.write("error: no resource type " + resource + "\\n")
        sys.exit(1)
    with open(path) as f:
        sys.stdout.write(f.read())
    """
)


def meta(name, namespace=None):
    out = {"name": name, "uid": "ignored", "resourceVersion": "1"}
    if namespace:
        out["namespace"] = namespace
    return out


# What `kubectl get ... -o json` returns, unsorted and with server-side fields
# the snapshot must drop.
CLUSTER = {
    "clusterroles": [
        {
            "metadata": meta("view"),
            "rules": [{"verbs": ["list", "get", "get"], "resources": ["pods"]}],
        },
    ],
    "roles": [],
    "clusterrolebindings": [],
    "rolebindings": [
        {
            "metadata": meta("deployer-view", "ci"),
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "view",
            },
            # No namespace: Kubernetes reads it as the binding's own.
            "subjects": [{"kind": "ServiceAccount", "name": "deployer"}],
        },
    ],
    "serviceaccounts": [
        {"metadata": meta("idle", "ci")},
        {"metadata": meta("deployer", "ci")},
        {"metadata": meta("default", "ci")},
    ],
    "pods": [
        {
            "metadata": meta("runner-7f9c", "ci"),
            "spec": {"serviceAccountName": "deployer"},
        },
        # No serviceAccountName: the pod runs as `default`.
        {"metadata": meta("sidecar-x2k1", "ci"), "spec": {}},
    ],
}


class LiveClusterTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.cluster = self.tmp / "cluster"
        self.cluster.mkdir()
        for resource, items in CLUSTER.items():
            (self.cluster / f"{resource}.json").write_text(
                json.dumps({"apiVersion": "v1", "kind": "List", "items": items})
            )
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        kubectl = bin_dir / "kubectl"
        kubectl.write_text(FAKE_KUBECTL)
        kubectl.chmod(kubectl.stat().st_mode | stat.S_IXUSR)
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_CLUSTER": str(self.cluster),
        }

    def cli(self, *argv):
        # cwd is the temp dir, so no ./.rbac-policy.yaml is picked up by accident.
        return subprocess.run(
            [sys.executable, str(ROOT / "rbac_audit.py"), *argv],
            cwd=self.tmp,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def kubectl_calls(self):
        return (self.cluster / "argv.log").read_text().splitlines()

    def test_snapshot_reads_every_section_from_the_named_context(self):
        result = self.cli("snapshot", "--context", "staging", "-o", "snap.json")
        self.assertEqual(result.returncode, ra.EXIT_OK, result.stderr)
        self.assertEqual(
            self.kubectl_calls(),
            [
                f"--context staging get {resource} -A -o json"
                for _key, _kind, resource, _normalize in ra.SECTIONS
            ],
        )

        snap = json.loads((self.tmp / "snap.json").read_text())
        self.assertEqual(snap["clusterRoles"][0]["rules"][0]["verbs"], ["get", "list"])
        self.assertEqual(
            snap["roleBindings"][0]["subjects"],
            [{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}],
        )
        self.assertEqual(
            [account["name"] for account in snap["serviceAccounts"]],
            ["default", "deployer", "idle"],
        )
        self.assertNotIn("uid", (self.tmp / "snap.json").read_text())

    def test_a_live_snapshot_is_stable_and_diffs_clean_against_itself(self):
        self.assertEqual(self.cli("snapshot", "-o", "a.json").returncode, ra.EXIT_OK)
        self.assertEqual(self.cli("snapshot", "-o", "b.json").returncode, ra.EXIT_OK)
        self.assertEqual(
            (self.tmp / "a.json").read_bytes(), (self.tmp / "b.json").read_bytes()
        )
        result = self.cli("diff", "a.json")
        self.assertEqual(result.returncode, ra.EXIT_OK, result.stderr)
        self.assertIn("No changes.", result.stdout)

    def test_baseline_checks_unused_service_accounts_against_the_pods(self):
        result = self.cli("baseline", "--json", "-")
        self.assertEqual(result.returncode, ra.EXIT_OK, result.stderr)
        self.assertIn("get pods -A -o json", self.kubectl_calls())

        report = json.loads(result.stdout)
        self.assertEqual(report["notChecked"], [])
        unused = [
            violation["object"]
            for violation in report["violations"]
            if violation["rule"] == "unused-service-account"
        ]
        # deployer is mounted by a pod; default is ignored by the default policy.
        self.assertEqual(unused, ["ServiceAccount/ci/idle"])

    def test_a_failing_kubectl_exits_unavailable_with_its_error(self):
        (self.cluster / "roles.json").unlink()
        result = self.cli("snapshot")
        self.assertEqual(result.returncode, ra.EXIT_UNAVAILABLE)
        self.assertIn("kubectl get roles failed", result.stderr)
        self.assertIn("no resource type roles", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
