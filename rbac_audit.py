#!/usr/bin/env python3
"""rbac-audit — readable RBAC reports from a live cluster.

Commands:
  report              full markdown report (findings + inventory)
  dump                raw JSON snapshot (for diffing / archiving)
  diff OLD.json       compare a previous `dump` against the live cluster
  who-can VERB RES    subjects allowed VERB on RES (e.g. who-can delete pods)

Findings covered by `report`:
  * wildcard grants (verbs/resources/apiGroups = "*")
  * cluster-admin bindings
  * ServiceAccounts never referenced by any pod (unused)
  * bindings pointing at subjects that do not exist
"""

import json
import subprocess
import sys
from datetime import datetime, timezone


def kubectl_json(*args):
    p = subprocess.run(
        ["kubectl", "get", *args, "-A", "-o", "json"],
        capture_output=True,
        text=True,
        check=False,  # returncode is inspected below, so a raise would skip the message
    )
    if p.returncode:
        sys.exit(f"kubectl get {' '.join(args)} failed:\n{p.stderr.strip()}")
    return json.loads(p.stdout)["items"]


def snapshot():
    return {
        "taken_at": datetime.now(timezone.utc).isoformat(),
        "roles": kubectl_json("roles"),
        "clusterroles": kubectl_json("clusterroles"),
        "rolebindings": kubectl_json("rolebindings"),
        "clusterrolebindings": kubectl_json("clusterrolebindings"),
        "serviceaccounts": kubectl_json("serviceaccounts"),
        "pods": kubectl_json("pods"),
    }


def name(obj):
    m = obj["metadata"]
    return f"{m.get('namespace', '')}/{m['name']}".lstrip("/")


def wildcard_findings(snap):
    for kind in ("roles", "clusterroles"):
        for role in snap[kind]:
            for rule in role.get("rules") or []:
                if "*" in (rule.get("verbs") or []) and "*" in (
                    rule.get("resources") or []
                ):
                    yield f"`{name(role)}` ({kind[:-1]}) grants `*` verbs on `*` resources"


def cluster_admin_findings(snap):
    for b in snap["clusterrolebindings"]:
        if b.get("roleRef", {}).get("name") == "cluster-admin":
            subjects = (
                ", ".join(
                    f"{s.get('kind')}:{s.get('namespace', '')}/{s.get('name')}".replace(
                        ":/", ":"
                    )
                    for s in b.get("subjects") or []
                )
                or "(no subjects)"
            )
            yield f"clusterrolebinding `{b['metadata']['name']}` grants cluster-admin to {subjects}"


def unused_sa_findings(snap):
    used = {
        (p["metadata"]["namespace"], p["spec"].get("serviceAccountName", "default"))
        for p in snap["pods"]
    }
    for sa in snap["serviceaccounts"]:
        key = (sa["metadata"]["namespace"], sa["metadata"]["name"])
        if sa["metadata"]["name"] != "default" and key not in used:
            yield f"ServiceAccount `{key[0]}/{key[1]}` is not used by any pod"


def dangling_binding_findings(snap):
    sas = {
        (sa["metadata"]["namespace"], sa["metadata"]["name"])
        for sa in snap["serviceaccounts"]
    }
    for kind in ("rolebindings", "clusterrolebindings"):
        for b in snap[kind]:
            for s in b.get("subjects") or []:
                if s.get("kind") == "ServiceAccount":
                    key = (
                        s.get("namespace", b["metadata"].get("namespace", "")),
                        s["name"],
                    )
                    if key not in sas:
                        yield f"{kind[:-1]} `{name(b)}` references missing ServiceAccount `{key[0]}/{key[1]}`"


def report(snap):
    print(f"# RBAC audit — {snap['taken_at']}\n")
    sections = [
        ("Wildcard grants", list(wildcard_findings(snap))),
        ("cluster-admin bindings", list(cluster_admin_findings(snap))),
        ("Unused ServiceAccounts", list(unused_sa_findings(snap))),
        ("Dangling bindings", list(dangling_binding_findings(snap))),
    ]
    total = 0
    for title, findings in sections:
        print(f"## {title} ({len(findings)})\n")
        for f in findings:
            print(f"- {f}")
        print()
        total += len(findings)
    print("## Inventory\n")
    for kind in (
        "roles",
        "clusterroles",
        "rolebindings",
        "clusterrolebindings",
        "serviceaccounts",
    ):
        print(f"- {kind}: {len(snap[kind])}")
    print(f"\n**{total} findings.**")
    return total


def diff(old, new):
    def index(snap):
        out = {}
        for kind in ("roles", "clusterroles", "rolebindings", "clusterrolebindings"):
            for obj in snap[kind]:
                out[(kind, name(obj))] = obj.get("rules") or obj.get("subjects")
        return out

    o, n = index(old), index(new)
    for key in sorted(n.keys() - o.keys()):
        print(f"+ added   {key[0][:-1]} {key[1]}")
    for key in sorted(o.keys() - n.keys()):
        print(f"- removed {key[0][:-1]} {key[1]}")
    for key in sorted(o.keys() & n.keys()):
        if o[key] != n[key]:
            print(f"~ changed {key[0][:-1]} {key[1]}")


def who_can(verb, resource, snap):
    def rule_matches(rule):
        verbs = rule.get("verbs") or []
        resources = rule.get("resources") or []
        return ("*" in verbs or verb in verbs) and (
            "*" in resources or resource in resources
        )

    granting = set()
    for kind in ("roles", "clusterroles"):
        for role in snap[kind]:
            if any(rule_matches(r) for r in role.get("rules") or []):
                granting.add(
                    (
                        kind[:-1]
                        .replace("role", "Role")
                        .replace("clusterRole", "ClusterRole"),
                        name(role),
                    )
                )
    for kind in ("rolebindings", "clusterrolebindings"):
        for b in snap[kind]:
            ref = b.get("roleRef", {})
            ns_name = (
                f"{b['metadata'].get('namespace', '')}/{ref.get('name', '')}".lstrip(
                    "/"
                )
            )
            if any(n_ in (ref.get("name"), ns_name) for _, n_ in granting):
                for s in b.get("subjects") or []:
                    print(
                        f"{s.get('kind')} {s.get('namespace', '')}/{s.get('name')}".replace(
                            " /", " "
                        )
                    )


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    if cmd == "dump":
        json.dump(snapshot(), sys.stdout, indent=2)
    elif cmd == "report":
        sys.exit(2 if report(snapshot()) and "--fail-on-findings" in sys.argv else 0)
    elif cmd == "diff":
        with open(sys.argv[2]) as fh:
            diff(json.load(fh), snapshot())
    elif cmd == "who-can":
        who_can(sys.argv[2], sys.argv[3], snapshot())
    else:
        print(__doc__)
        sys.exit(64)


if __name__ == "__main__":
    main()
