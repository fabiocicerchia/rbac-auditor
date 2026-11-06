"""The rbac-audit policy: its defaults, the check of a user's file, the rules.

Pure — no files, no cluster, no exit codes. rbac_audit reads the policy file
and the cluster; this module only decides what a list of changes violates.
"""

import copy

# Every namespace has one and it is never "unused"; a pod that names no
# ServiceAccount gets it. Both readings have to stay the same string.
DEFAULT_SERVICE_ACCOUNT = "default"


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
        # The group the API server lets through before RBAC is consulted at
        # all — stronger than cluster-admin, which is at least an RBAC object.
        # Its own rule rather than an entry in anonymous-subject's list, so a
        # break-glass grant can be exempted without exempting anonymous access.
        "masters-subject": {
            "enabled": True,
            "fail": True,
            "subjects": ["system:masters"],
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
        _check_rule_settings(policy["rules"], name, settings)
        policy["rules"][name].update(settings)

    exemptions = user.get("exempt") or []
    if not isinstance(exemptions, list):
        raise PolicyError("`exempt` must be a list")
    for position, entry in enumerate(exemptions, 1):
        _check_exemption(position, entry)
    policy["exempt"] = [dict(entry) for entry in exemptions]
    return policy


def _check_rule_settings(defaults, name, settings):
    """PolicyError unless `settings` is a valid override of rule `name`."""
    if name not in defaults:
        known = ", ".join(sorted(defaults))
        raise PolicyError(f"unknown policy rule {name!r} (known rules: {known})")
    if not isinstance(settings, dict):
        raise PolicyError(f"rule {name!r} must be a mapping")
    unknown = set(settings) - set(defaults[name])
    if unknown:
        raise PolicyError(
            f"rule {name!r}: unknown setting(s) {', '.join(sorted(unknown))}"
        )
    # Types too, not just names. `verbs: bind` instead of `verbs: [bind]`
    # is a plausible typo, and left unchecked it turns a membership test
    # into a substring one: the rule silently stops matching what it
    # should, or starts matching what it should not.
    for key, value in settings.items():
        if isinstance(defaults[name][key], bool):
            if not isinstance(value, bool):
                raise PolicyError(
                    f"rule {name!r}: {key} must be true or false, got {value!r}"
                )
        elif not _is_str_list(value):
            raise PolicyError(
                f"rule {name!r}: {key} must be a list of strings, got {value!r}"
            )


def _check_exemption(position, entry):
    """PolicyError unless `entry` is a well-formed `exempt` list item."""
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


def subject_str(subject):
    namespace = subject.get("namespace", "")
    name = subject.get("name", "")
    who = f"{namespace}/{name}" if namespace else name
    return f"{subject.get('kind', '?')} {who}"


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


def _watched_subjects(rule, change, settings):
    """A new binding to any subject named in the rule's `subjects` list.

    subjects.added, not newlyGranted: these rules watch the subject, and a
    subject already named by this binding is not newly bound to it. Narrowing
    the binding's role is not a new grant to that subject.
    """
    watched = set(settings["subjects"])
    for subject in change.get("subjects", {}).get("added", []):
        if subject.get("name") in watched:
            ref = change.get("roleRef") or {}
            yield _violation(
                rule,
                change,
                f"binds {subject_str(subject)} to {ref.get('kind')}/{ref.get('name')}",
                subject=subject_str(subject),
            )


def check_anonymous_subject(change, settings, state):
    """A new binding to system:anonymous or system:unauthenticated."""
    yield from _watched_subjects("anonymous-subject", change, settings)


def check_masters_subject(change, settings, state):
    """A new binding to system:masters, which bypasses RBAC entirely."""
    yield from _watched_subjects("masters-subject", change, settings)


CHECKS = {
    "cluster-admin-binding": check_cluster_admin_binding,
    "wildcard": check_wildcard,
    "escalating-verbs": check_escalating_verbs,
    "anonymous-subject": check_anonymous_subject,
    "masters-subject": check_masters_subject,
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
