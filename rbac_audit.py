#!/usr/bin/env python3
"""rbac-audit — readable RBAC reports from a live cluster.

Commands:
  report              full markdown report (findings + inventory)
                      --html PATH          also write a self-contained HTML report
                      --s3 s3://BUCKET/PREFIX  upload it (--sse, default AES256)
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
import os
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


# --- HTML report -------------------------------------------------------------


def cluster_identity():
    """Which cluster this is, for the report header.

    A report handed to an auditor has to say what it describes. The context
    name is what a human recognises; the API server URL is what actually
    identifies the cluster, since two kubeconfigs can name the same server
    differently. Best effort — a report is still worth having when kubectl
    cannot say, so this degrades to "unknown" rather than failing the run.
    """

    def kubectl(*args):
        p = subprocess.run(["kubectl", *args], capture_output=True, text=True)
        return p.stdout.strip() if p.returncode == 0 else ""

    context = kubectl("config", "current-context") or "unknown"
    server = ""
    raw = kubectl("config", "view", "--minify", "-o", "json")
    if raw:
        try:
            clusters = json.loads(raw).get("clusters") or []
            server = (
                (clusters[0].get("cluster") or {}).get("server", "") if clusters else ""
            )
        except (json.JSONDecodeError, AttributeError, IndexError):
            server = ""
    return {"context": context, "server": server or "unknown"}


def esc(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# Inline, because a report that fetches a stylesheet is a report that renders
# differently — or not at all — on the air-gapped machine of whoever is reading
# it a year from now.
HTML_CSS = """
:root { color-scheme: light dark; }
body { font: 15px/1.55 system-ui, sans-serif; margin: 0 auto; max-width: 60rem; padding: 2rem 1rem; }
h1 { margin-bottom: .25rem; }
.meta { color: #666; font-size: .9rem; margin-bottom: 2rem; }
.meta code { background: #8881; padding: .1rem .3rem; border-radius: 3px; }
h2 { border-bottom: 1px solid #8884; padding-bottom: .3rem; margin-top: 2.5rem; }
.count { color: #666; font-weight: normal; font-size: .8em; }
ul { padding-left: 1.2rem; }
li { margin: .35rem 0; }
li code { background: #8881; padding: .05rem .3rem; border-radius: 3px; }
.reason { color: #666; font-style: italic; }
.none { color: #666; font-style: italic; }
table { border-collapse: collapse; }
td { padding: .2rem 1.5rem .2rem 0; }
footer { margin-top: 3rem; color: #666; font-size: .85rem; border-top: 1px solid #8884; padding-top: 1rem; }
"""


def _md_code_to_html(text):
    """The finding strings carry markdown backticks; turn them into <code>."""
    parts = esc(text).split("`")
    return "".join(
        p if i % 2 == 0 else f"<code>{p}</code>" for i, p in enumerate(parts)
    )


def html_report(snap, identity=None):
    """Render the same findings as a self-contained HTML document.

    The sections are rebuilt here rather than shared with report(): that one
    prints as it goes, and threading a writer through it to serve two formats
    would complicate the common path for the benefit of the rarer one.
    """
    identity = identity or {"context": "unknown", "server": "unknown"}
    sections = [
        ("Wildcard grants", list(wildcard_findings(snap))),
        ("cluster-admin bindings", list(cluster_admin_findings(snap))),
        ("Unused ServiceAccounts", list(unused_sa_findings(snap))),
        ("Dangling bindings", list(dangling_binding_findings(snap))),
    ]
    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>RBAC audit</title>",
        f"<style>{HTML_CSS}</style>",
        "</head><body>",
        "<h1>RBAC audit</h1>",
        '<table class="meta"><tbody>',
        f"<tr><td>Cluster</td><td><code>{esc(identity['context'])}</code></td></tr>",
        f"<tr><td>API server</td><td><code>{esc(identity['server'])}</code></td></tr>",
        f"<tr><td>Generated</td><td><code>{esc(snap['taken_at'])}</code></td></tr>",
        "</tbody></table>",
    ]

    total = 0
    for title, findings in sections:
        out.append(f'<h2>{esc(title)} <span class="count">{len(findings)}</span></h2>')
        if findings:
            out.append("<ul>")
            out += [f"<li>{_md_code_to_html(f)}</li>" for f in findings]
            out.append("</ul>")
        else:
            out.append('<p class="none">None.</p>')
        total += len(findings)

    out.append("<h2>Inventory</h2><table><tbody>")
    for kind in (
        "roles",
        "clusterroles",
        "rolebindings",
        "clusterrolebindings",
        "serviceaccounts",
    ):
        out.append(f"<tr><td>{kind}</td><td>{len(snap[kind])}</td></tr>")
    out.append("</tbody></table>")

    out.append(f"<footer><strong>{total} findings.</strong><br>")
    out.append(
        "This report enumerates who can do what in the cluster. Treat it as "
        "sensitive: it is a map of the permissions worth attacking."
    )
    out.append("</footer></body></html>")
    return "\n".join(out)


def upload_s3(path, destination, sse="AES256"):
    """Copy the report to S3 with the AWS CLI. Returns an error string or None.

    Shelling out rather than taking a boto3 dependency: the image is a Python
    base plus kubectl, this is optional, and anyone uploading to S3 already has
    credentials configured the CLI can read.

    A failure here never loses the local report and never changes the exit
    code — the audit succeeded; only its delivery did not.
    """
    key = destination.rstrip("/") + "/" + os.path.basename(path)
    cmd = ["aws", "s3", "cp", path, key, "--sse", sse]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return "aws CLI not found on PATH"
    if p.returncode:
        return p.stderr.strip() or f"aws exited {p.returncode}"
    return None


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
        snap = snapshot()
        findings = report(snap)

        # Written from the same snapshot as the markdown above, so the two
        # cannot disagree about what was found.
        if "--html" in sys.argv:
            out = sys.argv[sys.argv.index("--html") + 1]
            with open(out, "w") as fh:
                fh.write(html_report(snap, cluster_identity()))
            print(f"\nHTML report written to {out}", file=sys.stderr)
            if "--s3" in sys.argv:
                sse = "AES256"
                if "--sse" in sys.argv:
                    sse = sys.argv[sys.argv.index("--sse") + 1]
                err = upload_s3(out, sys.argv[sys.argv.index("--s3") + 1], sse)
                if err:
                    # Delivery failed, the audit did not: keep the local file
                    # and the exit code the findings earned.
                    print(
                        f"warning: S3 upload failed ({err}); {out} kept",
                        file=sys.stderr,
                    )

        sys.exit(2 if findings and "--fail-on-findings" in sys.argv else 0)
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
