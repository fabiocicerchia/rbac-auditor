#!/usr/bin/env python3
"""rbac-audit — commit your cluster's RBAC, then diff it under a policy.

Commands:
  snapshot            deterministic JSON of Roles, ClusterRoles, bindings and
                      ServiceAccounts, meant to be committed to a repository
  diff OLD [NEW]      compare two snapshots, or a snapshot against the live
                      cluster: a readable diff, a machine-readable one, and an
                      exit code decided by a policy file
  diff --subject K/N  the same diff scoped to one subject, as a resource x verb
                      matrix with additions and removals marked

Deliberately absent: `who-can` queries, cluster-wide access matrices and
standalone wildcard listing. rakkess, alcideio/rbac-tool and
FairwindsOps/rbac-lookup already do those, are krew-installable and
vendor-backed. What none of them do is track RBAC *over time*, which is all
this tool is.
"""

import argparse
import copy
import json
import logging
import subprocess
import sys

import yaml

# Diagnostics go here; the diff itself goes to stdout, so the two can be
# redirected apart — `diff old.json > drift.txt` has to stay clean.
log = logging.getLogger("rbac-audit")

# The snapshot format is a committed artefact: its version is part of the
# contract, and a reader that does not know a version refuses rather than
# guesses. Bump it only for a change a v1 reader cannot make sense of.
SNAPSHOT_VERSION = "rbac-audit/v1"

# Policy file looked for in the working directory when --policy is not given.
POLICY_FILE = ".rbac-policy.yaml"

# Exit codes, sysexits(3) names in the comments. 2 is not a sysexits code and
# is not free to move: docs/architecture.md documents it as the policy gate,
# and CI jobs are written against it.
EXIT_OK = 0
EXIT_VIOLATIONS = 2  # the policy failed on at least one change
EXIT_USAGE = 64  # EX_USAGE     — missing operand, flag without a value
EXIT_DATAERR = 65  # EX_DATAERR   — a file that cannot be parsed
EXIT_NOINPUT = 66  # EX_NOINPUT   — a file named on the command line is missing
EXIT_UNAVAILABLE = 69  # EX_UNAVAILABLE — kubectl could not reach the cluster
EXIT_CANTCREAT = 73  # EX_CANTCREAT — an output file could not be written


# --- snapshot ----------------------------------------------------------------


def kubectl_json(resource, context=None):
    cmd = ["kubectl"]
    if context:
        cmd += ["--context", context]
    cmd += ["get", resource, "-A", "-o", "json"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # returncode is inspected below, so a raise would skip the message
        )
    except FileNotFoundError:
        # The image ships kubectl; a `pip install` does not. Saying so beats a
        # traceback, and the files-only workflow needs no kubectl at all.
        log.error(
            "kubectl is not on PATH. It is needed to read a cluster; "
            "`diff OLD NEW` on two snapshot files is not."
        )
        sys.exit(EXIT_UNAVAILABLE)
    if proc.returncode:
        log.error("kubectl get %s failed: %s", resource, proc.stderr.strip())
        sys.exit(EXIT_UNAVAILABLE)
    return json.loads(proc.stdout)["items"]


# The list fields of a PolicyRule, in the order they are rendered. Every one is
# a set as far as Kubernetes is concerned, which is why normalisation may sort
# them without changing meaning.
RULE_FIELDS = ("apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs")


def normalize_rule(rule):
    """One PolicyRule with its lists sorted, deduplicated and empties dropped.

    Sorting is safe because each field is a set; it is also the whole point —
    two clusters that grant the same thing have to produce the same bytes, or
    the diff reports churn nobody caused.
    """
    out = {}
    for field in RULE_FIELDS:
        values = rule.get(field) or []
        if values:
            out[field] = sorted(set(values))
    return out


def canonical(obj):
    """A stable string for an object, for sorting and set membership."""
    return json.dumps(obj, sort_keys=True)


def normalize_rules(rules):
    unique = {}
    for rule in rules or []:
        normalized = normalize_rule(rule)
        if normalized:  # a rule granting nothing is not a grant
            unique[canonical(normalized)] = normalized
    return [unique[key] for key in sorted(unique)]


def normalize_subject(subject, binding_namespace):
    """One binding subject, with a ServiceAccount's namespace made explicit.

    Kubernetes lets a RoleBinding name a ServiceAccount without a namespace and
    reads it as the binding's own. Resolving that here keeps the snapshot
    self-contained: the same grant spelled either way normalises to one record,
    so moving to the explicit spelling is not reported as a change.
    """
    kind = subject.get("kind", "")
    out = {"kind": kind, "name": subject.get("name", "")}
    namespace = subject.get("namespace") or (
        binding_namespace if kind == "ServiceAccount" else ""
    )
    if namespace:
        out["namespace"] = namespace
    return out


def normalize_subjects(subjects, binding_namespace):
    unique = {}
    for subject in subjects or []:
        normalized = normalize_subject(subject, binding_namespace)
        unique[canonical(normalized)] = normalized
    return [unique[key] for key in sorted(unique)]


def _named(obj):
    """The identity fields every snapshot record starts with."""
    meta = obj["metadata"]
    out = {"name": meta["name"]}
    if meta.get("namespace"):
        out["namespace"] = meta["namespace"]
    return out


def normalize_role(obj):
    out = _named(obj)
    # Kept because it is what a change to an aggregated ClusterRole looks like
    # before the controller rewrites the rules.
    if obj.get("aggregationRule"):
        out["aggregationRule"] = obj["aggregationRule"]
    out["rules"] = normalize_rules(obj.get("rules"))
    return out


def normalize_binding(obj):
    out = _named(obj)
    ref = obj.get("roleRef") or {}
    # apiGroup is dropped: it is rbac.authorization.k8s.io for every binding
    # Kubernetes accepts, so carrying it adds bytes and no information.
    out["roleRef"] = {"kind": ref.get("kind", ""), "name": ref.get("name", "")}
    out["subjects"] = normalize_subjects(
        obj.get("subjects"), obj["metadata"].get("namespace", "")
    )
    return out


def normalize_service_account(obj):
    return _named(obj)


# Every kind the snapshot carries: (snapshot key, kind name, kubectl resource,
# normaliser). Named once because the same tuples are walked from the capture,
# the diff and the subject resolver alike — a kind added to one and not the
# others is drift the tool stops seeing.
SECTIONS = (
    ("clusterRoles", "ClusterRole", "clusterroles", normalize_role),
    ("roles", "Role", "roles", normalize_role),
    (
        "clusterRoleBindings",
        "ClusterRoleBinding",
        "clusterrolebindings",
        normalize_binding,
    ),
    ("roleBindings", "RoleBinding", "rolebindings", normalize_binding),
    (
        "serviceAccounts",
        "ServiceAccount",
        "serviceaccounts",
        normalize_service_account,
    ),
)
SECTION_KEYS = tuple(section[0] for section in SECTIONS)
BINDING_KEYS = ("clusterRoleBindings", "roleBindings")


def object_id(obj):
    """`namespace/name`, or just `name` when the object is cluster-scoped."""
    namespace = obj.get("namespace", "")
    return f"{namespace}/{obj['name']}" if namespace else obj["name"]


def capture(context=None):
    """Snapshot the live cluster. The only function that talks to it."""
    snap = {"apiVersion": SNAPSHOT_VERSION}
    for key, _kind, resource, normalize in SECTIONS:
        items = [normalize(obj) for obj in kubectl_json(resource, context)]
        snap[key] = sorted(items, key=object_id)
    return snap


def dump_snapshot(snap):
    """The committed form: sorted keys, two-space indent, trailing newline.

    Deterministic on purpose. This file lives in a repository and is read as a
    diff, so byte-identical input has to produce byte-identical output — which
    is also why nothing in the payload records when it was taken. `git log`
    already knows.
    """
    return json.dumps(snap, indent=2, sort_keys=True) + "\n"


def load_snapshot(path):
    """A snapshot read back from disk.

    Exits rather than raising: a file that is missing, is not JSON, or is not a
    snapshot at all is something the user can fix, and a traceback does not
    tell them what.
    """
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        log.error("no such snapshot: %s", path)
        sys.exit(EXIT_NOINPUT)
    except OSError as err:
        log.error("cannot read %s: %s", path, err)
        sys.exit(EXIT_NOINPUT)
    except json.JSONDecodeError as err:
        log.error("%s is not a JSON snapshot: %s", path, err)
        sys.exit(EXIT_DATAERR)
    if not isinstance(data, dict) or data.get("apiVersion") != SNAPSHOT_VERSION:
        log.error(
            "%s is not a %s snapshot (apiVersion is %r)",
            path,
            SNAPSHOT_VERSION,
            data.get("apiVersion") if isinstance(data, dict) else None,
        )
        sys.exit(EXIT_DATAERR)
    for key in SECTION_KEYS:
        data.setdefault(key, [])
    return data


# --- diff --------------------------------------------------------------------


def index(snap, key):
    return {object_id(obj): obj for obj in snap.get(key) or []}


def _list_delta(before, after):
    """Set difference over rules or subjects, both sides in stable order."""
    was = {canonical(item): item for item in before or []}
    now = {canonical(item): item for item in after or []}
    return {
        "added": [now[k] for k in sorted(now.keys() - was.keys())],
        "removed": [was[k] for k in sorted(was.keys() - now.keys())],
    }


def _change(kind, verb, oid, before, after):
    """One changed object, in the shape the policy and both renderers read.

    Additions and removals are expressed the same way a modification is — an
    added role is every one of its rules added — so a policy check never has to
    ask which of the three it is looking at.
    """
    obj = after or before
    change = {
        "change": verb,
        "kind": kind,
        "id": oid,
        "object": f"{kind}/{oid}",
        "name": obj["name"],
        "namespace": obj.get("namespace", ""),
    }
    if "rules" in obj:
        change["rules"] = _list_delta(
            (before or {}).get("rules"), (after or {}).get("rules")
        )
    if "roleRef" in obj:
        old_ref = (before or {}).get("roleRef")
        new_ref = (after or {}).get("roleRef")
        change["roleRef"] = new_ref or old_ref
        old_subjects = (before or {}).get("subjects")
        new_subjects = (after or {}).get("subjects")
        if before and after and old_ref != new_ref:
            # roleRef is immutable, so this is a delete-and-recreate under the
            # same name. Every subject now points at a different role: that is
            # a new grant for all of them, not an unchanged one.
            change["roleRefBefore"] = old_ref
            change["subjects"] = {
                "added": list(new_subjects or []),
                "removed": list(old_subjects or []),
            }
        else:
            change["subjects"] = _list_delta(old_subjects, new_subjects)
    return change


def diff_snapshots(old, new):
    """Every object that was added, removed or changed, in a stable order."""
    changes = []
    for key, kind, _resource, _normalize in SECTIONS:
        was, now = index(old, key), index(new, key)
        for oid in sorted(now.keys() - was.keys()):
            changes.append(_change(kind, "added", oid, None, now[oid]))
        for oid in sorted(was.keys() - now.keys()):
            changes.append(_change(kind, "removed", oid, was[oid], None))
        for oid in sorted(was.keys() & now.keys()):
            if was[oid] != now[oid]:
                changes.append(_change(kind, "changed", oid, was[oid], now[oid]))
    return changes


# --- policy ------------------------------------------------------------------


class PolicyError(Exception):
    """A malformed policy file. Fatal: a gate nobody can read is worse than no
    gate, because it decides builds without saying how."""


# Defaults. Every rule is on, and every rule fails the build, because a policy
# that ships permissive is a policy nobody ever tightens. Relaxing is a local
# decision and belongs in a file somebody reviewed — see docs/getting-started.md.
DEFAULT_POLICY = {
    "version": 1,
    "rules": {
        "cluster-admin-binding": {
            "enabled": True,
            "fail": True,
            "roles": ["cluster-admin"],
        },
        "wildcard": {
            "enabled": True,
            "fail": True,
            "fields": ["verbs", "resources", "apiGroups"],
        },
        "escalating-verbs": {
            "enabled": True,
            "fail": True,
            "verbs": ["bind", "escalate", "impersonate"],
        },
        "anonymous-subject": {
            "enabled": True,
            "fail": True,
            "subjects": ["system:anonymous", "system:unauthenticated"],
        },
    },
    "exempt": [],
}

EXEMPT_MATCH_FIELDS = ("rule", "object", "subject")


def merge_policy(user):
    """The defaults with the user's file laid over them, or PolicyError.

    Strict about names: a typo in a rule name would otherwise silently leave
    that rule at its default, which for a security gate means a check the
    author believes they turned off and did not.
    """
    policy = copy.deepcopy(DEFAULT_POLICY)
    if user is None:
        return policy
    if not isinstance(user, dict):
        raise PolicyError("policy must be a YAML mapping")
    unknown = set(user) - {"version", "rules", "exempt"}
    if unknown:
        raise PolicyError(f"unknown key(s): {', '.join(sorted(unknown))}")
    version = user.get("version", 1)
    if version != 1:
        raise PolicyError(f"unsupported policy version {version!r}, expected 1")

    rules = user.get("rules") or {}
    if not isinstance(rules, dict):
        raise PolicyError("`rules` must be a mapping of rule name to settings")
    for name, settings in rules.items():
        if name not in policy["rules"]:
            known = ", ".join(sorted(policy["rules"]))
            raise PolicyError(f"unknown policy rule {name!r} (known rules: {known})")
        if not isinstance(settings, dict):
            raise PolicyError(f"rule {name!r} must be a mapping")
        unknown = set(settings) - set(policy["rules"][name])
        if unknown:
            raise PolicyError(
                f"rule {name!r}: unknown setting(s) {', '.join(sorted(unknown))}"
            )
        policy["rules"][name].update(settings)

    exemptions = user.get("exempt") or []
    if not isinstance(exemptions, list):
        raise PolicyError("`exempt` must be a list")
    for position, entry in enumerate(exemptions, 1):
        if not isinstance(entry, dict):
            raise PolicyError(f"exempt[{position}] must be a mapping")
        unknown = set(entry) - set(EXEMPT_MATCH_FIELDS) - {"reason"}
        if unknown:
            raise PolicyError(
                f"exempt[{position}]: unknown key(s) {', '.join(sorted(unknown))}"
            )
        if not any(field in entry for field in EXEMPT_MATCH_FIELDS):
            raise PolicyError(
                f"exempt[{position}]: needs at least one of "
                f"{', '.join(EXEMPT_MATCH_FIELDS)}"
            )
        if not str(entry.get("reason") or "").strip():
            # Same rule the ignore file had: an accepted risk with no stated
            # reason is indistinguishable from a mistake six months later.
            raise PolicyError(f"exempt[{position}]: needs a reason")
    policy["exempt"] = [dict(entry) for entry in exemptions]
    return policy


def load_policy(path=None):
    """The policy in `path`, or in ./.rbac-policy.yaml, or the defaults."""
    explicit = path is not None
    path = path or POLICY_FILE
    try:
        with open(path) as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        if explicit:
            log.error("no such policy file: %s", path)
            sys.exit(EXIT_NOINPUT)
        return merge_policy(None)
    except OSError as err:
        log.error("cannot read %s: %s", path, err)
        sys.exit(EXIT_NOINPUT)
    except yaml.YAMLError as err:
        log.error("%s is not valid YAML: %s", path, err)
        sys.exit(EXIT_DATAERR)
    try:
        return merge_policy(raw)
    except PolicyError as err:
        log.error("%s: %s", path, err)
        sys.exit(EXIT_DATAERR)


def subject_str(subject):
    namespace = subject.get("namespace", "")
    name = subject.get("name", "")
    who = f"{namespace}/{name}" if namespace else name
    return f"{subject.get('kind', '?')} {who}"


def rule_str(rule):
    """A PolicyRule on one line, in the order RULE_FIELDS declares."""
    parts = []
    for field in RULE_FIELDS:
        if field in rule:
            values = ",".join(value or '""' for value in rule[field])
            parts.append(f"{field}={values}")
    return " ".join(parts)


def _violation(rule_name, change, detail, subject=None):
    out = {
        "rule": rule_name,
        "object": change["object"],
        "kind": change["kind"],
        "id": change["id"],
        "detail": detail,
    }
    if subject:
        out["subject"] = subject
    return out


def check_cluster_admin_binding(change, settings):
    """A subject newly bound to cluster-admin (or another named role)."""
    ref = change.get("roleRef")
    if not ref or ref.get("name") not in settings["roles"]:
        return
    for subject in change["subjects"]["added"]:
        yield _violation(
            "cluster-admin-binding",
            change,
            f"binds {subject_str(subject)} to {ref['kind']}/{ref['name']}",
            subject=subject_str(subject),
        )


def check_wildcard(change, settings):
    """A new rule carrying `*` in a field the policy watches."""
    for rule in change.get("rules", {}).get("added", []):
        hit = [field for field in settings["fields"] if "*" in (rule.get(field) or [])]
        if hit:
            yield _violation(
                "wildcard",
                change,
                f"new rule has `*` in {', '.join(hit)}: {rule_str(rule)}",
            )


def check_escalating_verbs(change, settings):
    """A new grant of bind / escalate / impersonate.

    Only literal verbs: a rule with `*` verbs grants these too, and the
    wildcard rule already says so. Reporting it twice would train people to
    skim the list.
    """
    watched = set(settings["verbs"])
    for rule in change.get("rules", {}).get("added", []):
        granted = sorted(set(rule.get("verbs") or []) & watched)
        if granted:
            yield _violation(
                "escalating-verbs",
                change,
                f"new rule grants {', '.join(granted)}: {rule_str(rule)}",
            )


def check_anonymous_subject(change, settings):
    """A new binding to system:anonymous or system:unauthenticated."""
    watched = set(settings["subjects"])
    for subject in change.get("subjects", {}).get("added", []):
        if subject.get("name") in watched:
            ref = change.get("roleRef") or {}
            yield _violation(
                "anonymous-subject",
                change,
                f"binds {subject_str(subject)} to {ref.get('kind')}/{ref.get('name')}",
                subject=subject_str(subject),
            )


CHECKS = {
    "cluster-admin-binding": check_cluster_admin_binding,
    "wildcard": check_wildcard,
    "escalating-verbs": check_escalating_verbs,
    "anonymous-subject": check_anonymous_subject,
}


def _matches(pattern, value):
    """Exact, or a prefix when the pattern ends in `*`."""
    if not value:
        return False
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def exempted_by(violation, policy):
    """The exemption covering this violation, or None.

    An entry constrains only the fields it names, so `object:
    ClusterRole/system:*` covers every rule on those roles while `rule:
    wildcard object: ClusterRole/system:*` covers one.
    """
    for entry in policy["exempt"]:
        if all(
            _matches(entry[field], violation.get(field, ""))
            for field in EXEMPT_MATCH_FIELDS
            if field in entry
        ):
            return entry
    return None


def evaluate(changes, policy):
    """(violations, exempted) for a change list, in a stable order.

    Only additions are judged. Removing a grant cannot be the thing a security
    gate blocks, and a policy that fails a build for taking cluster-admin away
    is a policy people route around.
    """
    violations, exempted = [], []
    for change in changes:
        for name in sorted(policy["rules"]):
            settings = policy["rules"][name]
            if not settings.get("enabled", True):
                continue
            for violation in CHECKS[name](change, settings):
                violation["fail"] = bool(settings.get("fail", True))
                entry = exempted_by(violation, policy)
                if entry:
                    violation["reason"] = entry["reason"]
                    exempted.append(violation)
                else:
                    violations.append(violation)
    return violations, exempted


def gating(violations):
    """Whether anything here should fail the build."""
    return any(violation["fail"] for violation in violations)


# --- subject scope -----------------------------------------------------------

SUBJECT_KINDS = {
    "serviceaccount": "ServiceAccount",
    "user": "User",
    "group": "Group",
}


def parse_subject(spec):
    """`Kind/name`, or `Kind/namespace/name` for a ServiceAccount."""
    parts = spec.split("/")
    if len(parts) == 2:
        kind, namespace, name = parts[0], "", parts[1]
    elif len(parts) == 3:
        kind, namespace, name = parts
    else:
        log.error("--subject wants Kind/name or Kind/namespace/name, got %r", spec)
        sys.exit(EXIT_USAGE)
    canonical_kind = SUBJECT_KINDS.get(kind.lower())
    if not canonical_kind or not name:
        log.error(
            "--subject wants one of %s, e.g. ServiceAccount/ci/deployer",
            "/".join(sorted(SUBJECT_KINDS.values())),
        )
        sys.exit(EXIT_USAGE)
    if canonical_kind == "ServiceAccount" and not namespace:
        log.error(
            "a ServiceAccount needs its namespace: ServiceAccount/<namespace>/%s", name
        )
        sys.exit(EXIT_USAGE)
    return (canonical_kind, namespace, name)


def subject_matches(subject, want):
    return (
        subject.get("kind", ""),
        subject.get("namespace", ""),
        subject.get("name", ""),
    ) == want


def bindings_for(snap, want):
    """Every binding naming the subject, as (binding kind, binding)."""
    for key in BINDING_KEYS:
        kind = "ClusterRoleBinding" if key == "clusterRoleBindings" else "RoleBinding"
        for binding in snap.get(key) or []:
            if any(
                subject_matches(subject, want)
                for subject in binding.get("subjects") or []
            ):
                yield kind, binding


def role_ref_id(binding, ref):
    """(kind, id) of the role a binding points at.

    A roleRef names a ClusterRole bare and a Role within the binding's own
    namespace, which is the one asymmetry in RBAC worth getting right.
    """
    if ref.get("kind") == "ClusterRole":
        return ("ClusterRole", ref.get("name", ""))
    namespace = binding.get("namespace", "")
    return ("Role", f"{namespace}/{ref.get('name', '')}")


def subject_scope(old, new, want):
    """The objects a diff for this subject is allowed to mention.

    The bindings that name it, on either side of the diff, plus the roles those
    bindings reference — and the ServiceAccount itself when it is one.
    """
    ids = set()
    if want[0] == "ServiceAccount":
        ids.add(("ServiceAccount", f"{want[1]}/{want[2]}"))
    for snap in (old, new):
        for kind, binding in bindings_for(snap, want):
            ids.add((kind, object_id(binding)))
            ids.add(role_ref_id(binding, binding.get("roleRef") or {}))
    return ids


def scope_changes(changes, ids):
    return [change for change in changes if (change["kind"], change["id"]) in ids]


# --- subject matrix ----------------------------------------------------------


def resource_labels(rule):
    """The matrix rows one PolicyRule contributes.

    `resource.apiGroup`, the way kubectl spells it, with the core group left
    bare; `resourceNames` become a `[a,b]` suffix, because a rule narrowed to
    named objects is a different grant from the same verbs on all of them.
    Non-resource URLs are rows in their own right.
    """
    labels = list(rule.get("nonResourceURLs") or [])
    groups = rule.get("apiGroups") or []
    names = rule.get("resourceNames") or []
    suffix = "[" + ",".join(names) + "]" if names else ""
    for resource in rule.get("resources") or []:
        for group in groups:
            labels.append((f"{resource}.{group}" if group else resource) + suffix)
    return labels


def effective_cells(snap, want):
    """{(namespace, resource): {verbs}} for one subject.

    `*` as the namespace means cluster-wide. Wildcards in verbs and resources
    are carried through literally rather than expanded: expanding them needs
    API discovery, and inventing rows the cluster never returned would make the
    matrix lie in the direction that matters.
    """
    roles = {("Role", object_id(role)): role for role in snap.get("roles") or []} | {
        ("ClusterRole", role["name"]): role for role in snap.get("clusterRoles") or []
    }
    cells = {}
    for binding_kind, binding in bindings_for(snap, want):
        ref = binding.get("roleRef") or {}
        role = roles.get(role_ref_id(binding, ref))
        if role is None:
            # A binding to a role that does not exist grants nothing today.
            continue
        if binding_kind == "ClusterRoleBinding":
            namespace = "*"
        else:
            namespace = binding.get("namespace", "")
        for rule in role.get("rules") or []:
            for label in resource_labels(rule):
                cells.setdefault((namespace, label), set()).update(
                    rule.get("verbs") or []
                )
    return cells


def matrix_rows(before, after):
    """Rows of (namespace, resource, {verb: marker}) plus the verb columns."""
    keys = sorted(set(before) | set(after))
    verbs = sorted({verb for cells in (before, after) for verb in _all_verbs(cells)})
    rows = []
    for namespace, resource in keys:
        was, now = (
            before.get((namespace, resource), set()),
            after.get((namespace, resource), set()),
        )
        rows.append(
            {
                "namespace": namespace,
                "resource": resource,
                "added": sorted(now - was),
                "removed": sorted(was - now),
                "unchanged": sorted(now & was),
            }
        )
    return rows, verbs


def _all_verbs(cells):
    for verbs in cells.values():
        yield from verbs


# `.` and `=` rather than box-drawing marks: this lands in CI logs, gets piped
# through grep, and has to survive a terminal that is not a UTF-8 one.
MARK_ADDED = "+"
MARK_REMOVED = "-"
MARK_SAME = "="
MARK_NONE = "."
MATRIX_LEGEND = (
    f"  {MARK_ADDED} gained   {MARK_REMOVED} lost   "
    f"{MARK_SAME} unchanged   {MARK_NONE} not granted"
)


def render_matrix(rows, verbs):
    """The resource x verb matrix, additions and removals marked."""
    if not rows:
        return ["The subject has no permissions in either snapshot."]
    namespace_width = max(len("NAMESPACE"), *(len(row["namespace"]) for row in rows))
    resource_width = max(len("RESOURCE"), *(len(row["resource"]) for row in rows))
    widths = [max(len(verb), 3) for verb in verbs]

    def line(namespace, resource, cells):
        columns = " ".join(
            cell.center(width) for cell, width in zip(cells, widths, strict=True)
        )
        # rstrip: the last column is centred, so every row would otherwise end
        # in invisible padding — which a diff view and a test assertion both
        # see and a reader does not.
        return f"{namespace:<{namespace_width}}  {resource:<{resource_width}}  {columns}".rstrip()

    out = [line("NAMESPACE", "RESOURCE", verbs)]
    for row in rows:
        cells = []
        for verb in verbs:
            if verb in row["added"]:
                cells.append(MARK_ADDED)
            elif verb in row["removed"]:
                cells.append(MARK_REMOVED)
            elif verb in row["unchanged"]:
                cells.append(MARK_SAME)
            else:
                cells.append(MARK_NONE)
        out.append(line(row["namespace"], row["resource"], cells))
    out += ["", MATRIX_LEGEND]
    return out


# --- rendering ---------------------------------------------------------------

CHANGE_MARK = {"added": "+", "removed": "-", "changed": "~"}


def render_changes(changes):
    out = []
    for change in changes:
        out.append(f"{CHANGE_MARK[change['change']]} {change['object']}")
        ref = change.get("roleRef")
        if ref:
            before = change.get("roleRefBefore")
            moved = f" (was {before['kind']}/{before['name']})" if before else ""
            out.append(f"    roleRef {ref['kind']}/{ref['name']}{moved}")
        for rule in change.get("rules", {}).get("added", []):
            out.append(f"    + rule {rule_str(rule)}")
        for rule in change.get("rules", {}).get("removed", []):
            out.append(f"    - rule {rule_str(rule)}")
        for subject in change.get("subjects", {}).get("added", []):
            out.append(f"    + {subject_str(subject)}")
        for subject in change.get("subjects", {}).get("removed", []):
            out.append(f"    - {subject_str(subject)}")
    return out


def render_violations(violations, exempted):
    """The verdict, and then what was let through and on whose authority.

    "No policy violations." is printed even when everything was exempted: a
    clean gate and a gate somebody switched off have to read differently.
    """
    out = []
    if violations:
        out.append(f"Policy violations ({len(violations)})")
        for violation in violations:
            mark = "" if violation["fail"] else " (warn)"
            out.append(f"  [{violation['rule']}]{mark} {violation['object']}")
            out.append(f"      {violation['detail']}")
    else:
        out.append("No policy violations.")
    if exempted:
        out.append("")
        out.append(f"Exempted ({len(exempted)})")
        for violation in exempted:
            out.append(
                f"  [{violation['rule']}] {violation['object']} — {violation['reason']}"
            )
    return out


def summarize(changes, violations, exempted):
    counts = {"added": 0, "removed": 0, "changed": 0}
    for change in changes:
        counts[change["change"]] += 1
    counts["violations"] = len(violations)
    counts["exempted"] = len(exempted)
    return counts


def render_report(changes, violations, exempted, header, matrix=None):
    out = list(header)
    out.append("")
    if matrix is None:
        out += render_changes(changes) or ["No changes."]
    else:
        out += render_matrix(*matrix)
    out.append("")
    out += render_violations(violations, exempted)
    counts = summarize(changes, violations, exempted)
    out.append("")
    out.append(
        f"{counts['added']} added, {counts['removed']} removed, "
        f"{counts['changed']} changed; {counts['violations']} policy violations"
        + (f", {counts['exempted']} exempted" if counts["exempted"] else "")
        + "."
    )
    return "\n".join(out)


def machine_report(changes, violations, exempted, source, target, subject, matrix):
    out = {
        "apiVersion": SNAPSHOT_VERSION,
        "from": source,
        "to": target,
        "summary": summarize(changes, violations, exempted),
        "changes": changes,
        "violations": violations,
        "exempted": exempted,
    }
    if subject:
        out["subject"] = "/".join(part for part in subject if part)
        rows, verbs = matrix
        out["matrix"] = {"verbs": verbs, "rows": rows}
    return json.dumps(out, indent=2, sort_keys=True) + "\n"


# --- commands ----------------------------------------------------------------


def write_out(path, text):
    """Write to a file, or to stdout when the path is `-`."""
    if path == "-":
        sys.stdout.write(text)
        return
    try:
        with open(path, "w") as fh:
            fh.write(text)
    except OSError as err:
        log.error("cannot write %s: %s", path, err)
        sys.exit(EXIT_CANTCREAT)


def run_snapshot(args):
    snap = capture(args.context)
    write_out(args.output, dump_snapshot(snap))
    if args.output != "-":
        log.info("snapshot written to %s", args.output)
    sys.exit(EXIT_OK)


def run_diff(args):
    old = load_snapshot(args.old)
    if args.new:
        new, target = load_snapshot(args.new), args.new
    else:
        new, target = capture(args.context), "live cluster"

    changes = diff_snapshots(old, new)
    matrix = None
    subject = None
    if args.subject:
        subject = parse_subject(args.subject)
        changes = scope_changes(changes, subject_scope(old, new, subject))
        matrix = matrix_rows(
            effective_cells(old, subject), effective_cells(new, subject)
        )

    if args.no_policy:
        policy = merge_policy({"rules": {name: {"enabled": False} for name in CHECKS}})
    else:
        policy = load_policy(args.policy)
    violations, exempted = evaluate(changes, policy)

    header = [f"RBAC diff — {args.old} → {target}"]
    if subject:
        header.append(
            f"Subject: {subject_str({'kind': subject[0], 'namespace': subject[1], 'name': subject[2]})}"
        )

    if args.json:
        write_out(
            args.json,
            machine_report(
                changes, violations, exempted, args.old, target, subject, matrix
            ),
        )
    # `--json -` puts the machine report on stdout; printing the human one
    # there too would corrupt it.
    if args.json != "-":
        print(render_report(changes, violations, exempted, header, matrix))

    sys.exit(EXIT_VIOLATIONS if gating(violations) else EXIT_OK)


class Parser(argparse.ArgumentParser):
    """argparse, but usage errors exit 64 like every other usage error here.

    Its default is 2, which this tool spends on "the policy failed" — a CI job
    cannot be allowed to read a typo as a security finding.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        log.error("%s", message)
        sys.exit(EXIT_USAGE)


def build_parser():
    parser = Parser(
        prog="rbac-audit",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    snap = sub.add_parser("snapshot", help="dump RBAC to a deterministic JSON file")
    snap.add_argument(
        "-o",
        "--output",
        default="-",
        metavar="PATH",
        help="write here (default stdout)",
    )
    snap.add_argument("--context", metavar="NAME", help="kubeconfig context to read")
    snap.set_defaults(func=run_snapshot)

    diff = sub.add_parser("diff", help="compare snapshots and apply the policy")
    diff.add_argument("old", metavar="OLD", help="the snapshot to compare from")
    diff.add_argument(
        "new",
        metavar="NEW",
        nargs="?",
        help="the snapshot to compare to (default: the live cluster)",
    )
    diff.add_argument(
        "--policy",
        metavar="PATH",
        help=f"policy file (default: ./{POLICY_FILE} if it exists)",
    )
    diff.add_argument(
        "--no-policy", action="store_true", help="report changes without gating on them"
    )
    diff.add_argument(
        "--subject",
        metavar="KIND/NAME",
        help="scope the diff to one subject, as a resource x verb matrix",
    )
    diff.add_argument(
        "--json",
        metavar="PATH",
        help="also write the machine-readable diff (`-` for stdout)",
    )
    diff.add_argument("--context", metavar="NAME", help="kubeconfig context to read")
    diff.set_defaults(func=run_diff)
    return parser


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr
    )
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(EXIT_USAGE)
    args.func(args)


if __name__ == "__main__":
    main()
