#!/usr/bin/env python3
"""rbac-audit — readable RBAC reports from a live cluster.

Commands:
  report              full markdown report (findings + inventory)
                      --ignore-file PATH   suppressions (default .rbac-audit-ignore)
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
        rule["hits"] = 0
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
        # Suppressed findings never reach this count, so the exit code reflects
        # what is left to act on — which is the point of suppressing.
        sys.exit(
            2 if report(snapshot(), rules) and "--fail-on-findings" in sys.argv else 0
        )
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
