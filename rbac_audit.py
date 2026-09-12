#!/usr/bin/env python3
"""rbac-audit — commit your cluster's RBAC, then diff it under a policy.

Commands:
  snapshot            deterministic JSON of Roles, ClusterRoles, bindings and
                      ServiceAccounts, meant to be committed to a repository
  baseline [SNAP]     apply the policy to a whole cluster rather than to what
                      changed in it — the day-one audit, before there is
                      anything to diff against
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

# Both files this tool writes carry the same apiVersion, so `kind` is what
# tells them apart. Without it a `--json` diff report is accepted as a
# snapshot and read as an empty cluster, which reports the whole cluster as
# newly added and fails the build for nothing.
SNAPSHOT_KIND = "RbacSnapshot"
DIFF_KIND = "RbacDiff"

# Policy file looked for in the working directory when --policy is not given.
POLICY_FILE = ".rbac-policy.yaml"

# Every namespace has one and it is never "unused"; a pod that names no
# ServiceAccount gets it. Both readings have to stay the same string.
DEFAULT_SERVICE_ACCOUNT = "default"

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
    snap = {"apiVersion": SNAPSHOT_VERSION, "kind": SNAPSHOT_KIND}
    for key, _kind, resource, normalize in SECTIONS:
        items = [normalize(obj) for obj in kubectl_json(resource, context)]
        snap[key] = sorted(items, key=object_id)
    return snap


def capture_pod_service_accounts(context=None):
    """{(namespace, serviceAccountName)} for every pod in the cluster.

    Deliberately *not* part of the snapshot. Pod names carry a fresh random
    suffix on every rollout, so committing them would make each snapshot diff
    enormous and meaningless — the opposite of the one property the file has to
    have. This is read at evaluation time instead, which is why the check that
    needs it only runs when a cluster is there to read.
    """
    return {
        (
            pod["metadata"]["namespace"],
            pod["spec"].get("serviceAccountName", DEFAULT_SERVICE_ACCOUNT),
        )
        for pod in kubectl_json("pods", context)
    }


def dump_snapshot(snap):
    """The committed form: sorted keys, two-space indent, trailing newline.

    Deterministic on purpose. This file lives in a repository and is read as a
    diff, so byte-identical input has to produce byte-identical output — which
    is also why nothing in the payload records when it was taken. `git log`
    already knows.
    """
    return json.dumps(snap, indent=2, sort_keys=True) + "\n"


class SnapshotError(Exception):
    """A file that is not a usable snapshot. Fatal, and reported with the field
    that is wrong: this is the input to a security gate, and a gate that reads
    a malformed file as an empty cluster fails builds for nothing."""


def _require(condition, message):
    if not condition:
        raise SnapshotError(message)


def _require_str_list(value, where):
    _require(isinstance(value, list), f"{where}: expected a list")
    for position, item in enumerate(value):
        _require(isinstance(item, str), f"{where}[{position}]: expected a string")


def _validate_rules(rules, where):
    _require(isinstance(rules, list), f"{where}.rules: expected a list")
    for position, rule in enumerate(rules):
        at = f"{where}.rules[{position}]"
        _require(isinstance(rule, dict), f"{at}: expected an object")
        for field in RULE_FIELDS:
            if field in rule:
                _require_str_list(rule[field], f"{at}.{field}")


def _validate_subjects(subjects, where):
    _require(isinstance(subjects, list), f"{where}.subjects: expected a list")
    for position, subject in enumerate(subjects):
        at = f"{where}.subjects[{position}]"
        _require(isinstance(subject, dict), f"{at}: expected an object")
        for field in ("kind", "name", "namespace"):
            if field in subject:
                _require(
                    isinstance(subject[field], str), f"{at}.{field}: expected a string"
                )


def validate_snapshot(data):
    """Raise SnapshotError unless `data` is a snapshot this version can read."""
    _require(isinstance(data, dict), "expected a JSON object at the top level")
    kind = data.get("kind")
    _require(
        kind == SNAPSHOT_KIND,
        f"kind is {kind!r}, expected {SNAPSHOT_KIND!r}"
        + (
            " — this looks like a `--json` diff report, not a snapshot"
            if kind == DIFF_KIND
            else ""
        ),
    )
    _require(
        data.get("apiVersion") == SNAPSHOT_VERSION,
        f"apiVersion is {data.get('apiVersion')!r}, expected {SNAPSHOT_VERSION!r}",
    )
    for key in SECTION_KEYS:
        if key not in data:
            continue
        items = data[key]
        _require(isinstance(items, list), f"{key}: expected a list")
        for position, obj in enumerate(items):
            where = f"{key}[{position}]"
            _require(isinstance(obj, dict), f"{where}: expected an object")
            _require(
                isinstance(obj.get("name"), str) and obj["name"],
                f"{where}: needs a non-empty string name",
            )
            if "namespace" in obj:
                _require(
                    isinstance(obj["namespace"], str),
                    f"{where}.namespace: expected a string",
                )
            if "rules" in obj:
                _validate_rules(obj["rules"], where)
            if "roleRef" in obj:
                ref = obj["roleRef"]
                _require(isinstance(ref, dict), f"{where}.roleRef: expected an object")
                for field in ("kind", "name"):
                    _require(
                        isinstance(ref.get(field), str),
                        f"{where}.roleRef.{field}: expected a string",
                    )
            if "subjects" in obj:
                _validate_subjects(obj["subjects"], where)


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
    try:
        validate_snapshot(data)
    except SnapshotError as err:
        log.error("%s: %s", path, err)
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


def rule_grants(rule):
    """The atomic permissions one PolicyRule expands to.

    A grant is one verb on one resource in one apiGroup (optionally narrowed to
    one resourceName), or one verb on one non-resource URL. Wildcards are kept
    as the literal `*` rather than expanded — see `effective_cells`.

    The policy judges these, not rules, and that distinction is the whole
    reason this function exists. Rules are mutable containers: narrowing
    `verbs: [bind, get, list]` to `verbs: [bind]` replaces one rule with
    another, so comparing rules as wholes reports the surviving `bind` as new
    and fails the build for *removing* two verbs. Comparing grants says what
    actually happened: two lost, none gained.
    """
    grants = []
    for verb in rule.get("verbs") or []:
        for url in rule.get("nonResourceURLs") or []:
            grants.append({"nonResourceURL": url, "verb": verb})
        for group in rule.get("apiGroups") or []:
            for resource in rule.get("resources") or []:
                for name in rule.get("resourceNames") or [""]:
                    grant = {
                        "apiGroup": group,
                        "resource": resource,
                        "verb": verb,
                    }
                    if name:
                        grant["resourceName"] = name
                    grants.append(grant)
    return grants


def rules_grants(rules):
    """Every grant a list of rules expands to, deduplicated and ordered."""
    unique = {}
    for rule in rules or []:
        for grant in rule_grants(rule):
            unique[canonical(grant)] = grant
    return [unique[key] for key in sorted(unique)]


def _grant_subsumers(grant):
    """Keys of every grant that would already have implied this one.

    A grant is implied by a broader one: `*` in place of its apiGroup,
    resource or verb, or the same grant without the resourceName that narrows
    it. Sixteen candidates at most, so this is a set lookup rather than a scan.

    This is what makes a *tightening* invisible to the policy. Adding
    `resourceNames: [db]` to a rule, or replacing `resources: [*]` with
    `resources: [pods]`, produces grant tuples that did not literally exist
    before — but the cluster already allowed every one of them, so none of
    them is new.
    """
    # resourceNames are literal in RBAC, never globs, so that dimension is not
    # wildcarded — only dropped, since a rule without one covers every name.
    names = (grant["resourceName"], None) if "resourceName" in grant else (None,)
    for group in (grant["apiGroup"], "*"):
        for resource in (grant["resource"], "*"):
            for verb in (grant["verb"], "*"):
                for name in names:
                    candidate = {
                        "apiGroup": group,
                        "resource": resource,
                        "verb": verb,
                    }
                    if name is not None:
                        candidate["resourceName"] = name
                    yield canonical(candidate)


def _url_grant_implied(grant, before):
    """Whether a non-resource URL grant was already allowed.

    Non-resource URLs are the one place RBAC does do prefix globs, so `/api/*`
    implies `/api/v1` and this has to be a scan.
    """
    for url, verb in before:
        if verb not in ("*", grant["verb"]):
            continue
        if url == grant["nonResourceURL"] or (
            url.endswith("*") and grant["nonResourceURL"].startswith(url[:-1])
        ):
            return True
    return False


def new_grants(before, after):
    """The grants in `after` that `before` did not already imply."""
    keys = {canonical(grant) for grant in before}
    urls = [
        (grant["nonResourceURL"], grant["verb"])
        for grant in before
        if "nonResourceURL" in grant
    ]
    out = []
    for grant in after:
        if canonical(grant) in keys:
            continue
        if "nonResourceURL" in grant:
            if not _url_grant_implied(grant, urls):
                out.append(grant)
        elif not any(key in keys for key in _grant_subsumers(grant)):
            out.append(grant)
    return out


def grant_delta(before, after):
    """Which permissions were genuinely gained, and which genuinely lost.

    Not a plain set difference: each side is filtered against what the other
    already implied, so rewriting a rule without changing what it allows is
    empty on both sides.
    """
    before, after = rules_grants(before), rules_grants(after)
    return {
        "added": new_grants(before, after),
        "removed": new_grants(after, before),
    }


def _change(kind, verb, oid, before, after):
    """One changed object, in the shape the policy and both renderers read.

    Additions and removals are expressed the same way a modification is — an
    added role is every one of its grants added — so a policy check never has
    to ask which of the three it is looking at.
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
        # `rules` is for a human: it shows the rule text somebody has to edit.
        # `grants` is for the policy: it is what the subject can actually do.
        change["rules"] = _list_delta(
            (before or {}).get("rules"), (after or {}).get("rules")
        )
        change["grants"] = grant_delta(
            (before or {}).get("rules"), (after or {}).get("rules")
        )
        old_aggregation = (before or {}).get("aggregationRule")
        new_aggregation = (after or {}).get("aggregationRule")
        if old_aggregation != new_aggregation:
            # Without this an aggregation-selector change renders as a bare
            # `~ ClusterRole/x` with nothing under it: a changed object the
            # diff cannot say anything about is worse than no line at all.
            change["aggregationRule"] = {
                "before": old_aggregation,
                "after": new_aggregation,
            }
    if "roleRef" in obj:
        old_ref = (before or {}).get("roleRef")
        new_ref = (after or {}).get("roleRef")
        change["roleRef"] = new_ref or old_ref
        change["subjects"] = _list_delta(
            (before or {}).get("subjects"), (after or {}).get("subjects")
        )
        if before and after and old_ref != new_ref:
            change["roleRefBefore"] = old_ref
        # Which subjects newly hold the role this binding points at. Normally
        # the ones added to it — but roleRef is immutable, so a changed one is
        # a delete and recreate under the same name, and every subject now
        # points at a different role. Rules that judge *the role* read this;
        # rules that judge *the subject* read subjects.added, because a subject
        # already bound here is not newly bound.
        if change.get("roleRefBefore"):
            change["newlyGranted"] = list((after or {}).get("subjects") or [])
        else:
            change["newlyGranted"] = list(change["subjects"]["added"])
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
        "dangling-binding": {"enabled": True, "fail": True},
        # Hygiene rather than escalation, so it warns by default where the
        # others block: an unused ServiceAccount is a credential nobody is
        # watching, not a privilege somebody just gained. On a first `baseline`
        # it is also usually the longest list, and a gate that is red on day
        # one is a gate that gets switched off.
        "unused-service-account": {
            "enabled": True,
            "fail": False,
            "ignore": [DEFAULT_SERVICE_ACCOUNT],
        },
    },
    "exempt": [],
}

EXEMPT_MATCH_FIELDS = ("rule", "object", "subject")


def _is_str_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


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
        # Types too, not just names. `verbs: bind` instead of `verbs: [bind]`
        # is a plausible typo, and left unchecked it turns a membership test
        # into a substring one: the rule silently stops matching what it
        # should, or starts matching what it should not.
        for key, value in settings.items():
            expected = policy["rules"][name][key]
            if isinstance(expected, bool):
                if not isinstance(value, bool):
                    raise PolicyError(
                        f"rule {name!r}: {key} must be true or false, got {value!r}"
                    )
            elif not _is_str_list(value):
                raise PolicyError(
                    f"rule {name!r}: {key} must be a list of strings, got {value!r}"
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
        for field in EXEMPT_MATCH_FIELDS:
            # _matches globs with str.endswith, so a non-string here would be
            # a traceback rather than the parse error it is.
            if field in entry and not isinstance(entry[field], str):
                raise PolicyError(
                    f"exempt[{position}]: {field} must be a string, got {entry[field]!r}"
                )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
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


def grant_str(grant):
    """One grant on one line: `get secrets.*`, `bind roles.rbac…`, `* *.*`."""
    if "nonResourceURL" in grant:
        return f"{grant['verb']} {grant['nonResourceURL']}"
    group = grant.get("apiGroup", "")
    resource = grant.get("resource", "")
    what = f"{resource}.{group}" if group else resource
    name = grant.get("resourceName")
    return f"{grant['verb']} {what}" + (f"[{name}]" if name else "")


def _violation(rule_name, change, detail, subject=None, dedupe=None):
    """One violation.

    `dedupe` groups violations that say the same thing about the same object:
    one rule granting `*` on five resources with three verbs is fifteen new
    grants, and fifteen identical findings is a report nobody reads. Violations
    sharing a key collapse into the first, with a count.
    """
    out = {
        "rule": rule_name,
        "object": change["object"],
        "kind": change["kind"],
        "id": change["id"],
        "detail": detail,
    }
    if subject:
        out["subject"] = subject
    out["_dedupe"] = dedupe if dedupe is not None else detail
    return out


def collapse_violations(violations):
    """Fold violations sharing a dedupe key into the first, counting the rest."""
    out, first = [], {}
    for violation in violations:
        key = (violation["rule"], violation["object"], violation.pop("_dedupe"))
        if key in first:
            first[key]["collapsed"] = first[key].get("collapsed", 0) + 1
            continue
        first[key] = violation
        out.append(violation)
    return out


# Which grant field a policy `fields` entry names. The policy speaks the
# language of the YAML somebody writes (`verbs`, `resources`, `apiGroups`);
# a grant is one permission, so its keys are singular.
WILDCARD_FIELDS = {"verbs": "verb", "resources": "resource", "apiGroups": "apiGroup"}


def check_cluster_admin_binding(change, settings, state):
    """A subject newly bound to cluster-admin (or another named role)."""
    ref = change.get("roleRef")
    if not ref or ref.get("name") not in settings["roles"]:
        return
    # newlyGranted, not subjects.added: re-pointing a binding at cluster-admin
    # gives it to every subject already in the binding.
    for subject in change.get("newlyGranted", []):
        yield _violation(
            "cluster-admin-binding",
            change,
            f"binds {subject_str(subject)} to {ref['kind']}/{ref['name']}",
            subject=subject_str(subject),
        )


def check_wildcard(change, settings, state):
    """A newly granted permission carrying `*` in a field the policy watches."""
    for grant in change.get("grants", {}).get("added", []):
        hit = [
            field
            for field in settings["fields"]
            if grant.get(WILDCARD_FIELDS.get(field, field)) == "*"
        ]
        if hit:
            yield _violation(
                "wildcard",
                change,
                f"new grant has `*` in {', '.join(hit)}: {grant_str(grant)}",
                dedupe=("wildcard", *hit),
            )


def check_escalating_verbs(change, settings, state):
    """A new grant of bind / escalate / impersonate.

    Only literal verbs: a `*` verb grants these too, and the wildcard rule
    already says so. Reporting it twice would train people to skim the list.
    """
    watched = set(settings["verbs"])
    for grant in change.get("grants", {}).get("added", []):
        if grant.get("verb") in watched:
            yield _violation(
                "escalating-verbs",
                change,
                f"new grant of {grant['verb']}: {grant_str(grant)}",
                dedupe=grant["verb"],
            )


def check_dangling_binding(change, settings, state):
    """A binding pointing at a ServiceAccount that does not exist.

    Kubernetes accepts this without complaint and never warns when the subject
    later appears — the binding simply starts granting. Harmless today, a live
    privilege grant the moment somebody creates a ServiceAccount with that name
    in that namespace.
    """
    accounts = state["serviceAccounts"]
    for subject in change.get("subjects", {}).get("added", []):
        if subject.get("kind") != "ServiceAccount":
            continue
        key = (subject.get("namespace", ""), subject.get("name", ""))
        if key not in accounts:
            ref = change.get("roleRef") or {}
            yield _violation(
                "dangling-binding",
                change,
                f"names {subject_str(subject)}, which does not exist — "
                f"creating it would grant {ref.get('kind')}/{ref.get('name')}",
                subject=subject_str(subject),
            )


def check_unused_service_account(change, settings, state):
    """A ServiceAccount no pod mounts: a credential nobody is watching.

    Needs the cluster's pods, which the snapshot deliberately does not carry,
    so this is the one rule that cannot run files-only. `evaluate` reports it
    as skipped rather than passing it silently.

    Only newly seen accounts, like every other rule. In `baseline` that is all
    of them, which is the inventory you want on a first audit; in `diff` it is
    the ones just created.
    """
    if change["kind"] != "ServiceAccount" or change["change"] != "added":
        return
    if change["name"] in settings["ignore"]:
        return
    if (change["namespace"], change["name"]) in state["podServiceAccounts"]:
        return
    yield _violation(
        "unused-service-account",
        change,
        f"no pod mounts {change['namespace']}/{change['name']} — "
        "a token nobody is watching",
        subject=f"ServiceAccount {change['namespace']}/{change['name']}",
    )


def check_anonymous_subject(change, settings, state):
    """A new binding to system:anonymous or system:unauthenticated.

    subjects.added, not newlyGranted: this rule watches the subject, and a
    subject already named by this binding is not newly bound to it. Narrowing
    the binding's role is not a new anonymous grant.
    """
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
    "dangling-binding": check_dangling_binding,
    "unused-service-account": check_unused_service_account,
}

# Rules needing something a snapshot does not carry, and the state key that
# supplies it. When it is missing the rule cannot run, and a check that
# silently does not run is the failure this tool exists to prevent — so
# `evaluate` returns it as skipped and the report says so.
CHECK_REQUIRES = {"unused-service-account": "podServiceAccounts"}


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


def evaluation_state(snap, pod_service_accounts=None):
    """What the checks need beyond the change itself.

    `serviceAccounts` comes from the snapshot being judged. `podServiceAccounts`
    can only come from a live cluster, and is None when there was not one —
    which is how `evaluate` knows to report a rule as skipped.
    """
    return {
        "serviceAccounts": {
            (account.get("namespace", ""), account["name"])
            for account in snap.get("serviceAccounts") or []
        },
        "podServiceAccounts": pod_service_accounts,
    }


def runnable_rules(policy, state):
    """(names to run, [(name, why it could not run)]) for an enabled policy."""
    runnable, skipped = [], []
    for name in sorted(policy["rules"]):
        if not policy["rules"][name].get("enabled", True):
            continue
        needs = CHECK_REQUIRES.get(name)
        if needs and state.get(needs) is None:
            why = (
                "needs the cluster's pods, which a snapshot does not carry — "
                "run it against a live cluster"
            )
            skipped.append((name, why))
        else:
            runnable.append(name)
    return runnable, skipped


def evaluate(changes, policy, state=None):
    """(violations, exempted, skipped) for a change list, in a stable order.

    Only additions are judged. Removing a grant cannot be the thing a security
    gate blocks, and a policy that fails a build for taking cluster-admin away
    is a policy people route around.

    `skipped` names the enabled rules that could not run at all. They are not
    failures and they are not passes, and reporting them as either would be a
    lie about what was checked.
    """
    state = state or evaluation_state({})
    violations, exempted = [], []
    names, skipped = runnable_rules(policy, state)
    for change in changes:
        for name in names:
            settings = policy["rules"][name]
            for violation in collapse_violations(CHECKS[name](change, settings, state)):
                violation["fail"] = bool(settings.get("fail", True))
                entry = exempted_by(violation, policy)
                if entry:
                    violation["reason"] = entry["reason"]
                    exempted.append(violation)
                else:
                    violations.append(violation)
    return violations, exempted, skipped


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
    if canonical_kind != "ServiceAccount" and namespace:
        # Only a ServiceAccount subject has a namespace. Accepting one here
        # would build a subject nothing can match and report "no permissions",
        # which reads as an answer rather than as the typo it is.
        log.error(
            "a %s subject has no namespace: %s/%s", canonical_kind, canonical_kind, name
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
    """The object diff. Every changed object gets at least one detail line —
    a bare `~ ClusterRole/x` the diff cannot explain is worse than no line."""
    out = []
    for change in changes:
        out.append(f"{CHANGE_MARK[change['change']]} {change['object']}")
        ref = change.get("roleRef")
        if ref:
            before = change.get("roleRefBefore")
            moved = f" (was {before['kind']}/{before['name']})" if before else ""
            out.append(f"    roleRef {ref['kind']}/{ref['name']}{moved}")
        aggregation = change.get("aggregationRule")
        if aggregation:
            for label, value in (
                ("-", aggregation["before"]),
                ("+", aggregation["after"]),
            ):
                if value is not None:
                    out.append(f"    {label} aggregationRule {canonical(value)}")
        for rule in change.get("rules", {}).get("added", []):
            out.append(f"    + rule {rule_str(rule)}")
        for rule in change.get("rules", {}).get("removed", []):
            out.append(f"    - rule {rule_str(rule)}")
        for subject in change.get("subjects", {}).get("added", []):
            out.append(f"    + {subject_str(subject)}")
        for subject in change.get("subjects", {}).get("removed", []):
            out.append(f"    - {subject_str(subject)}")
    return out


def render_skipped(skipped):
    """Rules that could not run. Never silent: "not checked" and "checked and
    clean" are different answers, and only one of them is reassuring."""
    if not skipped:
        return []
    out = ["", f"Not checked ({len(skipped)})"]
    for name, why in skipped:
        out.append(f"  [{name}] {why}")
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
            more = violation.get("collapsed")
            extra = f" (+{more} more like it)" if more else ""
            out.append(f"      {violation['detail']}{extra}")
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


def render_report(changes, violations, exempted, header, matrix=None, skipped=()):
    out = list(header)
    out.append("")
    if matrix is None:
        out += render_changes(changes) or ["No changes."]
    else:
        out += render_matrix(*matrix)
    out.append("")
    out += render_violations(violations, exempted)
    out += render_skipped(skipped)
    counts = summarize(changes, violations, exempted)
    out.append("")
    # Say when violations were found but none of them gate, so a green build
    # with a page of violations above it is not read as a green build.
    gate = "" if not violations or gating(violations) else " (none gating)"
    out.append(
        f"{counts['added']} added, {counts['removed']} removed, "
        f"{counts['changed']} changed; {counts['violations']} policy violations"
        + gate
        + (f", {counts['exempted']} exempted" if counts["exempted"] else "")
        + "."
    )
    return "\n".join(out)


def public_change(change):
    """One change as the machine report carries it.

    The expanded `grants` stay internal. They are how the policy decides, and
    they are quadratic in the size of a rule — one rule over 40 resources and
    12 verbs is 1440 of them, which would make a first-run diff of a real
    cluster tens of megabytes of JSON. `rules` says what changed and
    `grantCounts` says how much it came to; anyone who needs the expansion can
    get it from the rules.
    """
    out = {key: value for key, value in change.items() if key != "grants"}
    if "grants" in change:
        out["grantCounts"] = {
            "added": len(change["grants"]["added"]),
            "removed": len(change["grants"]["removed"]),
        }
    return out


def machine_report(
    changes, violations, exempted, source, target, subject, matrix, skipped=()
):
    out = {
        "apiVersion": SNAPSHOT_VERSION,
        "kind": DIFF_KIND,
        "from": source,
        "to": target,
        "summary": summarize(changes, violations, exempted),
        "changes": [public_change(change) for change in changes],
        "violations": violations,
        "exempted": exempted,
        "notChecked": [{"rule": name, "why": why} for name, why in skipped],
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


def empty_snapshot():
    """A snapshot of a cluster with no RBAC in it.

    What `baseline` compares against: with nothing on the left, every object is
    an addition and every permission is newly granted, so the same rules that
    judge a week's drift judge the whole cluster.
    """
    snap = {"apiVersion": SNAPSHOT_VERSION, "kind": SNAPSHOT_KIND}
    for key in SECTION_KEYS:
        snap[key] = []
    return snap


def load_policy_for(args):
    """The policy, with --no-policy applied. Read before any cluster is."""
    policy = load_policy(args.policy)
    if args.no_policy:
        # Downgrade, do not disable. The point of this flag is to read what the
        # policy *would* have blocked before switching the gate on, so the
        # violations still have to be printed — just marked (warn), and not
        # deciding the exit code.
        for settings in policy["rules"].values():
            settings["fail"] = False
    return policy


def report_and_exit(args, old, new, source, target, title, policy, subject, pods):
    """The half of `diff` and `baseline` that is the same for both."""
    changes = diff_snapshots(old, new)
    matrix = None
    if subject:
        changes = scope_changes(changes, subject_scope(old, new, subject))
        matrix = matrix_rows(
            effective_cells(old, subject), effective_cells(new, subject)
        )

    violations, exempted, skipped = evaluate(
        changes, policy, evaluation_state(new, pods)
    )

    header = [f"{title} — {source} → {target}" if source else f"{title} — {target}"]
    if subject:
        header.append(
            f"Subject: {subject_str({'kind': subject[0], 'namespace': subject[1], 'name': subject[2]})}"
        )

    if args.json:
        write_out(
            args.json,
            machine_report(
                changes,
                violations,
                exempted,
                source or "an empty cluster",
                target,
                subject,
                matrix,
                skipped,
            ),
        )
    # `--json -` puts the machine report on stdout; printing the human one
    # there too would corrupt it.
    if args.json != "-":
        print(render_report(changes, violations, exempted, header, matrix, skipped))

    sys.exit(EXIT_VIOLATIONS if gating(violations) else EXIT_OK)


def read_target(args, path):
    """The snapshot being judged, and what to call it in the report.

    Also the cluster's pods when there is a cluster: they are what the
    unused-ServiceAccount rule needs, and they are not in any snapshot.
    """
    if path:
        return load_snapshot(path), path, None
    return (
        capture(args.context),
        "live cluster",
        capture_pod_service_accounts(args.context),
    )


def run_diff(args):
    # Everything that can be rejected from the command line alone is rejected
    # first: a malformed --subject or an unreadable policy must not exit 69
    # because reading the cluster failed, and must not cost a cluster read to
    # find out about.
    subject = parse_subject(args.subject) if args.subject else None
    policy = load_policy_for(args)
    old = load_snapshot(args.old)
    new, target, pods = read_target(args, args.new)
    report_and_exit(
        args, old, new, args.old, target, "RBAC diff", policy, subject, pods
    )


def run_baseline(args):
    """Judge a whole cluster, rather than what changed in it.

    Drift detection assumes a good baseline, and on day one nobody has one: a
    cluster that is already dangerous and stays that way never changes, so a
    diff never sees it. This compares against an empty cluster, so the same
    policy reports everything that is true right now.
    """
    subject = parse_subject(args.subject) if args.subject else None
    policy = load_policy_for(args)
    new, target, pods = read_target(args, args.snapshot)
    report_and_exit(
        args, empty_snapshot(), new, "", target, "RBAC baseline", policy, subject, pods
    )


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

    def add_policy_flags(command, what):
        """The flags `diff` and `baseline` share. They run the same engine, so
        a flag on one and not the other would be an accident, not a choice."""
        command.add_argument(
            "--policy",
            metavar="PATH",
            help=f"policy file (default: ./{POLICY_FILE} if it exists)",
        )
        command.add_argument(
            "--no-policy",
            action="store_true",
            help="report what the policy would block, without gating on it",
        )
        command.add_argument(
            "--subject",
            metavar="KIND/NAME",
            help=f"scope the {what} to one subject, as a resource x verb matrix",
        )
        command.add_argument(
            "--json",
            metavar="PATH",
            help=f"also write the machine-readable {what} (`-` for stdout)",
        )
        command.add_argument(
            "--context", metavar="NAME", help="kubeconfig context to read"
        )

    diff = sub.add_parser("diff", help="compare snapshots and apply the policy")
    diff.add_argument("old", metavar="OLD", help="the snapshot to compare from")
    diff.add_argument(
        "new",
        metavar="NEW",
        nargs="?",
        help="the snapshot to compare to (default: the live cluster)",
    )
    add_policy_flags(diff, "diff")
    diff.set_defaults(func=run_diff)

    baseline = sub.add_parser(
        "baseline", help="apply the policy to a whole cluster, not just what changed"
    )
    baseline.add_argument(
        "snapshot",
        metavar="SNAPSHOT",
        nargs="?",
        help="the snapshot to judge (default: the live cluster)",
    )
    add_policy_flags(baseline, "baseline")
    baseline.set_defaults(func=run_baseline)
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
