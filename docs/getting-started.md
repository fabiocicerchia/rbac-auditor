# Getting Started

## Prerequisites

A cluster and read access to RBAC — or, for the files-only workflow, nothing at
all. kubectl is in the image and uses whatever credentials you give it.

## Take a snapshot and commit it

```sh
rbac-audit snapshot -o rbac/prod.json
```

Or in a container, with your kubeconfig:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor snapshot > rbac/prod.json
```

A kind cluster publishes its API server on `127.0.0.1`, so add `--network host`
(its kubeconfig embeds the certs, nothing else to mount). If your kubeconfig
uses an exec plugin (EKS, GKE), that binary is not in the image — use a
token-based context, or run it in-cluster with the CronJob below.

`--context NAME` picks a context when your kubeconfig has several.

The file is deterministic: sorted, normalised, and with no timestamp inside it.
Re-running against an unchanged cluster produces byte-identical output, so
`git diff` on it is signal and nothing else. **Commit it.**

It declares `"kind": "RbacSnapshot"`, which is how `diff` tells a snapshot from
the `--json` diff report it also writes. Feeding the wrong one in is an error
rather than a diff against an empty cluster.

```sh
git add rbac/prod.json
git commit -m "chore(rbac): weekly snapshot"
```

## See what drifted

```sh
rbac-audit diff rbac/prod.json
```

That compares the committed snapshot against the live cluster:

```text
RBAC diff — rbac/prod.json → live cluster

~ Role/ci/deploy
    + rule apiGroups=rbac.authorization.k8s.io resources=roles verbs=bind,escalate
    - rule apiGroups=apps resources=deployments verbs=get,list
+ ClusterRoleBinding/ci-admin
    roleRef ClusterRole/cluster-admin
    + ServiceAccount ci/deployer

Policy violations (2)
  [escalating-verbs] Role/ci/deploy
      new rule grants bind, escalate: apiGroups=rbac.authorization.k8s.io resources=roles verbs=bind,escalate
  [cluster-admin-binding] ClusterRoleBinding/ci-admin
      binds ServiceAccount ci/deployer to ClusterRole/cluster-admin

1 added, 0 removed, 1 changed; 2 policy violations.
```

Exit code 2, because the policy failed. That is the CI gate, and it needs no
extra flag — `diff` is a gate by default.

## Diff two files, with no cluster at all

```sh
rbac-audit diff rbac/prod-2026-09-01.json rbac/prod-2026-09-08.json
```

This is the mode for a CI job that has no business holding cluster credentials:
a scheduled job takes the snapshot and opens a pull request with it, and the
pull request's own checks diff the two committed files. Nothing in this path
touches kubectl.

## Machine-readable output

```sh
rbac-audit diff rbac/prod.json --json drift.json     # both: text and the file
rbac-audit diff rbac/prod.json --json - | jq .summary
```

`--json -` writes the JSON to stdout and suppresses the human report, so the
pipe stays parseable. Both come from the same run, so they cannot disagree.

```json
{
  "added": 1,
  "changed": 1,
  "exempted": 0,
  "removed": 0,
  "violations": 2
}
```

## What one subject gained

```sh
rbac-audit diff rbac/prod.json --subject ServiceAccount/ci/deployer
```

```text
NAMESPACE  RESOURCE                          *  bind escalate get list patch
*          *.*                               +   .      .      .   .     .
ci         deployments.apps                  .   .      .      =   =     +
ci         roles.rbac.authorization.k8s.io   .   +      +      .   .     .
ci         secrets.*                         .   .      .      +   .     .

  + gained   - lost   = unchanged   . not granted
```

`+` is what this ServiceAccount can do today and could not last week — the
question you actually have during an incident review.

The subject is `Kind/name`, or `Kind/namespace/name` for a ServiceAccount:

```sh
rbac-audit diff old.json --subject ServiceAccount/ci/deployer
rbac-audit diff old.json --subject Group/system:masters
rbac-audit diff old.json --subject User/alice@example.com
```

Namespace `*` means the grant came from a ClusterRoleBinding and applies
everywhere. Wildcards in the rules are shown as they are written rather than
expanded into the resources they cover: expanding them needs API discovery, and
a matrix that invented rows would be wrong in the direction that matters.

The policy still runs, scoped to that subject, so the exit code means the same
thing it does without `--subject`.

## The policy

With no policy file, these four rules are on and all of them fail the build:

| Rule                    | Fails on                                                        |
| ----------------------- | --------------------------------------------------------------- |
| `cluster-admin-binding` | a subject newly bound to `cluster-admin`                        |
| `wildcard`              | a new rule with `*` in `verbs`, `resources` or `apiGroups`      |
| `escalating-verbs`      | a new grant of `bind`, `escalate` or `impersonate`              |
| `anonymous-subject`     | a new binding to `system:anonymous` or `system:unauthenticated` |

Only additions are judged, and "addition" means a permission the cluster did
not already allow. Removing a grant never fails a build, and neither does
narrowing one: dropping verbs from a rule, replacing `*` with named resources,
restricting a rule to specific `resourceNames`, or splitting one rule into two
that grant the same thing are all silent.

`diff` reads `./.rbac-policy.yaml` if it is there, or `--policy PATH`. Copy
[`.rbac-policy.example.yaml`](https://github.com/fabiocicerchia/rbac-auditor/blob/main/.rbac-policy.example.yaml)
to start from the defaults written out in full.

## Relaxing the policy

Three ways, in the order you should reach for them.

**1. Exempt a specific object.** Narrowest, and the only one that leaves the
rule working everywhere else:

```yaml
version: 1
exempt:
  - rule: wildcard
    object: ClusterRole/system:*
    reason: ships with Kubernetes, upstream-managed
  - rule: cluster-admin-binding
    subject: Group system:masters
    reason: the bootstrap group, reviewed 2026-09
```

An entry constrains only the fields it names — `rule`, `object`, `subject` —
and a value ending in `*` matches a prefix. `reason` is required: an accepted
risk with no stated reason is indistinguishable from a mistake six months
later. Exempted violations are still printed, under **Exempted**, each with its
reason. Nothing disappears quietly.

**2. Downgrade a rule to a warning.** It still reports, marked `(warn)`, but
stops deciding the exit code:

```yaml
version: 1
rules:
  wildcard:
    fail: false
```

**3. Turn a rule off.** It stops looking, and nothing will tell you again:

```yaml
version: 1
rules:
  wildcard:
    enabled: false
```

You can also narrow a rule instead of silencing it. This one stops flagging `*`
verbs on a named resource — often intentional — while still catching `*`
resources and `*` apiGroups:

```yaml
version: 1
rules:
  wildcard:
    fields: [resources, apiGroups]
```

Every rule's list is configurable the same way: `roles` for
`cluster-admin-binding`, `verbs` for `escalating-verbs`, `subjects` for
`anonymous-subject`. They are lists, and the file is rejected if you write a
bare string — `verbs: bind` instead of `verbs: [bind]` would turn a membership
test into a substring one, and a security check that quietly stops matching is
the thing this tool exists to prevent.

A malformed policy is a fatal error rather than a warning, and an unknown rule
name is an error rather than being ignored: a typo would otherwise leave that
rule at its default — a check you believe you turned off and did not.

To see what the policy *would* block without acting on it, pass `--no-policy`.
Every rule still runs and every violation is still printed — marked `(warn)`,
with `(none gating)` on the summary line — but the exit code stays 0. That is
the flag to start with: read a week of them, then take it off.

## Gate it in CI

```yaml
- name: RBAC drift
  run: rbac-audit diff rbac/prod.json rbac/current.json
```

Exit code 2 fails the step. Start with `--no-policy` for a week, read what it
would have blocked, then take the flag off — a check that has been red since
the day it was added is a check that has been switched off.

## Run it weekly, in-cluster

```sh
kubectl apply -f manifests/cronjob.yaml
```

That creates the CronJob, the ServiceAccount, and a read-only ClusterRole
scoped to `get`/`list` on the RBAC kinds plus ServiceAccounts. Read it before
applying — it is short on purpose, so it can be reviewed rather than trusted.

The snapshot goes to the job's stdout, which is where your log pipeline can see
it:

```sh
kubectl -n security logs job/rbac-auditor-<id> > rbac/prod.json
```

> **Treat snapshots as sensitive.** One enumerates who can do what in the
> cluster, which is a map of the permissions worth attacking. A private
> repository, with the same care you would give the kubeconfig itself.

## Development

```sh
make build     # docker build
make lint      # the whole pre-commit gate
make test      # unit tests against fixtures, then the image smoke tests
make release   # multi-arch buildx push
```

The unit tests need neither Docker nor a cluster:

```sh
python3 -m unittest discover -s tests
```
