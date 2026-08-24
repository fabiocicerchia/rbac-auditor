#!/usr/bin/env python3
"""rbac-audit — readable RBAC reports from a live cluster.

Commands:
  report              full markdown report (findings + inventory)
                      --ignore-file PATH   suppressions (default .rbac-audit-ignore)
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


def finding(text, subject="", role="", verb=""):
    """One finding, in the shape the ignore file matches against.

    The text is what a human reads; subject/role/verb are what a suppression
    names. Kept as three separate fields rather than parsed back out of the
    text, so a reworded finding does not silently stop matching its
    suppression."""
    return {"text": text, "subject": subject, "role": role, "verb": verb}


def wildcard_findings(snap):
    for kind in ("roles", "clusterroles"):
        for role in snap[kind]:
            for rule in role.get("rules") or []:
                if "*" in (rule.get("verbs") or []) and "*" in (
                    rule.get("resources") or []
                ):
                    yield finding(
                        f"`{name(role)}` ({kind[:-1]}) grants `*` verbs on `*` resources",
                        role=name(role),
                        verb="*",
                    )


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
            yield finding(
                f"clusterrolebinding `{b['metadata']['name']}` grants cluster-admin to {subjects}",
                subject=subjects,
                role="cluster-admin",
            )


def unused_sa_findings(snap):
    used = {
        (p["metadata"]["namespace"], p["spec"].get("serviceAccountName", "default"))
        for p in snap["pods"]
    }
    for sa in snap["serviceaccounts"]:
        key = (sa["metadata"]["namespace"], sa["metadata"]["name"])
        if sa["metadata"]["name"] != "default" and key not in used:
            yield finding(
                f"ServiceAccount `{key[0]}/{key[1]}` is not used by any pod",
                subject=f"ServiceAccount:{key[0]}/{key[1]}",
            )


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
                        yield finding(
                            f"{kind[:-1]} `{name(b)}` references missing ServiceAccount `{key[0]}/{key[1]}`",
                            subject=f"ServiceAccount:{key[0]}/{key[1]}",
                            role=b.get("roleRef", {}).get("name", ""),
                        )


# --- suppressions ------------------------------------------------------------

IGNORE_FILE = ".rbac-audit-ignore"


class IgnoreError(Exception):
    """A malformed ignore file. Fatal: a suppression nobody can read is worse
    than no suppression, because it hides findings without saying so."""


def parse_ignore(text):
    """Parse .rbac-audit-ignore.

    One rule per line, `field=value` pairs separated by spaces, `#` starts a
    comment. `reason=` is required — an accepted risk with no stated reason is
    indistinguishable from a mistake six months later:

        # noisy but accepted
        role=system:controller:* reason=ships with Kubernetes
        subject=ServiceAccount:kube-system/default reason=cluster bootstrap

    Values may end in `*` to match a prefix. `reason=` swallows the rest of the
    line, so it needs no quoting.
    """
    rules = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        rule = {"line": lineno, "raw": line}
        rest = line
        while rest:
            field, sep, rest = rest.partition("=")
            field = field.strip()
            if not sep:
                raise IgnoreError(
                    f"{IGNORE_FILE}:{lineno}: expected field=value, got {field!r}"
                )
            if field == "reason":
                rule["reason"] = rest.strip()
                rest = ""
                break
            # A value runs to the next " field=" boundary.
            value, rest = _split_value(rest)
            if field not in ("subject", "role", "verb"):
                raise IgnoreError(f"{IGNORE_FILE}:{lineno}: unknown field {field!r}")
            rule[field] = value
        if not rule.get("reason"):
            raise IgnoreError(f"{IGNORE_FILE}:{lineno}: every entry needs reason=…")
        if not any(k in rule for k in ("subject", "role", "verb")):
            raise IgnoreError(
                f"{IGNORE_FILE}:{lineno}: needs at least one of subject/role/verb"
            )
        rules.append(rule)
    return rules


def _split_value(rest):
    """Split `value field=…` into the value and what follows.

    Values can contain almost anything (`system:controller:*`), so the boundary
    is the last space before the next `field=`, not the first space.
    """
    words = rest.split()
    for i, w in enumerate(words):
        if (
            i
            and "=" in w
            and w.split("=", 1)[0] in ("subject", "role", "verb", "reason")
        ):
            return " ".join(words[:i]), " ".join(words[i:])
    return rest.strip(), ""


def _matches(pattern, value):
    # An empty value means the finding has no such attribute — an unused
    # ServiceAccount has no verb — so a rule naming that field cannot match it.
    # Without this, `verb=*` (prefix-glob on the empty string) would suppress
    # every finding in the report rather than every wildcard grant.
    if not value:
        return False
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def apply_ignores(findings, rules):
    """Split findings into (kept, suppressed) and mark which rules fired.

    A rule matches when every field it names matches the finding. Fields it
    does not name are not constraints — `verb=*` alone suppresses every
    wildcard finding, `role=x verb=*` only that role's.
    """
    kept, suppressed = [], []
    for rule in rules:
        # Accumulate across calls: this runs once per section, and a rule that
        # fired in an earlier one is not stale.
        rule.setdefault("hits", 0)
    for f in findings:
        hit = None
        for rule in rules:
            if all(
                _matches(rule[k], f[k])
                for k in ("subject", "role", "verb")
                if k in rule
            ):
                hit = rule
                break
        if hit:
            hit["hits"] += 1
            suppressed.append((f, hit))
        else:
            kept.append(f)
    return kept, suppressed


def load_ignores(path=IGNORE_FILE):
    try:
        with open(path) as fh:
            return parse_ignore(fh.read())
    except FileNotFoundError:
        return []


def sections_for(snap):
    return [
        ("Wildcard grants", list(wildcard_findings(snap))),
        ("cluster-admin bindings", list(cluster_admin_findings(snap))),
        ("Unused ServiceAccounts", list(unused_sa_findings(snap))),
        ("Dangling bindings", list(dangling_binding_findings(snap))),
    ]


def report(snap, rules=()):
    """Print the markdown report; return the number of UNSUPPRESSED findings.

    Suppressed ones are counted and listed, never silently dropped: an ignore
    file you cannot audit is a way to lose findings, not a way to manage them.
    """
    print(f"# RBAC audit — {snap['taken_at']}\n")
    rules = list(rules)
    total, all_suppressed = 0, []
    for title, findings in sections_for(snap):
        kept, suppressed = apply_ignores(findings, rules)
        all_suppressed.extend(suppressed)
        note = f" ({len(suppressed)} suppressed)" if suppressed else ""
        print(f"## {title} ({len(kept)}){note}\n")
        for f in kept:
            print(f"- {f['text']}")
        print()
        total += len(kept)

    if all_suppressed:
        print(f"## Suppressed ({len(all_suppressed)})\n")
        for f, rule in all_suppressed:
            print(f"- {f['text']} — _{rule['reason']}_")
        print()

    stale = [r for r in rules if not r["hits"]]
    if stale:
        print(f"## Stale suppressions ({len(stale)})\n")
        for r in stale:
            print(f"- {IGNORE_FILE}:{r['line']}: `{r['raw']}` matched nothing")
        print()

    print("## Inventory\n")
    for kind in (
        "roles",
        "clusterroles",
        "rolebindings",
        "clusterrolebindings",
        "serviceaccounts",
    ):
        print(f"- {kind}: {len(snap[kind])}")
    suffix = f" ({len(all_suppressed)} suppressed)" if all_suppressed else ""
    print(f"\n**{total} findings.**{suffix}")
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
        p = subprocess.run(
            ["kubectl", *args], capture_output=True, text=True, check=False
        )
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


def html_report(snap, identity=None, rules=()):
    """Render the same findings as a self-contained HTML document.

    Only the rendering is separate from report(): the sections and the
    suppressions come from the same helpers, so the two formats cannot
    disagree about what was found or what was ignored.
    """
    identity = identity or {"context": "unknown", "server": "unknown"}
    sections, all_suppressed = [], []
    for title, findings in sections_for(snap):
        kept, suppressed = apply_ignores(findings, rules)
        all_suppressed.extend(suppressed)
        sections.append((title, kept, suppressed))
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
    for title, kept, suppressed in sections:
        note = f" ({len(suppressed)} suppressed)" if suppressed else ""
        out.append(
            f'<h2>{esc(title)} <span class="count">{len(kept)}</span>{esc(note)}</h2>'
        )
        if kept:
            out.append("<ul>")
            out += [f"<li>{_md_code_to_html(f['text'])}</li>" for f in kept]
            out.append("</ul>")
        else:
            out.append('<p class="none">None.</p>')
        total += len(kept)

    if all_suppressed:
        out.append(
            f'<h2>Suppressed <span class="count">{len(all_suppressed)}</span></h2><ul>'
        )
        out += [
            f"<li>{_md_code_to_html(f['text'])} — <em>{esc(rule['reason'])}</em></li>"
            for f, rule in all_suppressed
        ]
        out.append("</ul>")

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

    suffix = f" ({len(all_suppressed)} suppressed)" if all_suppressed else ""
    out.append(f"<footer><strong>{total} findings.</strong>{esc(suffix)}<br>")
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
        # check=False: the return code is the answer here, not an exception.
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
        path = IGNORE_FILE
        if "--ignore-file" in sys.argv:
            path = sys.argv[sys.argv.index("--ignore-file") + 1]
        try:
            rules = load_ignores(path)
        except IgnoreError as err:
            sys.exit(str(err))
        snap = snapshot()
        # Suppressed findings never reach this count, so the exit code reflects
        # what is left to act on — which is the point of suppressing.
        findings = report(snap, rules)

        # Written from the same snapshot and the same suppressions as the
        # markdown above, so the two cannot disagree about what was found.
        if "--html" in sys.argv:
            out = sys.argv[sys.argv.index("--html") + 1]
            with open(out, "w") as fh:
                fh.write(html_report(snap, cluster_identity(), rules))
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
