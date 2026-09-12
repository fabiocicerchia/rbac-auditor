# Architecture

One Python file, `kubectl` for the API calls, and no client library.

```bash
kubectl get {roles,clusterroles,rolebindings,clusterrolebindings,
             serviceaccounts} -A -o json
        │
        └──► capture()  — normalised, sorted, no timestamps
                 │
                 ├── snapshot          the snapshot itself, as committable JSON
                 ├── baseline [SNAP]   the whole cluster, judged by the policy
                 └── diff OLD [NEW]    snapshot vs snapshot, or vs the cluster
                          │
                          ├── changes      added / removed / changed objects
                          ├── policy       which additions fail the build
                          └── --subject    one subject, as a resource × verb matrix
```

## `baseline` is `diff` against nothing

Drift detection assumes a good baseline, and on day one nobody has one. A
cluster that is already dangerous and stays that way never changes, so a diff
never sees it — the tool would be silent about the worst cluster it will ever
meet.

`baseline` compares against an empty cluster. Every object is an addition and
every permission is newly granted, so the same rules that judge a week's drift
judge the whole thing: no second code path, and no second set of findings to
keep in step. It is the same engine with `empty_snapshot()` on the left.

That makes the first run noisy by construction — it is the entire cluster —
but it is noise you work through once to reach a committed snapshot, after
which `diff` is zero and stays zero. That is the difference from the old
`report`, whose findings never went away and therefore never got read.

## The scope, and what was deliberately removed

Versions before 2.0 also shipped `who-can`, a standalone wildcard listing, an
HTML renderer and an S3 upload. Those were removed, not deprecated.

[rakkess][rakkess], [rbac-tool][rbac-tool] and [rbac-lookup][rbac-lookup]
answer point-in-time questions — who can do what, right now — and they answer
them better: they resolve aggregated ClusterRoles, they do API discovery, they
are krew-installable and vendor-backed. This tool's `who-can` did not resolve
aggregation and said so in its own documentation, which is another way of
saying it was a worse version of something that already existed.

What none of them do is track RBAC *over time*. A snapshot in git and a diff
with a policy gate is a different job: it turns drift into a pull request
instead of a query somebody has to remember to run.

Two findings from the old `report` were **not** covered by those tools and came
back as policy rules rather than being dropped: `dangling-binding` and
`unused-service-account`. Both correlate RBAC against cluster inventory —
whether a ServiceAccount exists, whether a pod mounts it — which is not
something an RBAC query tool answers. Removing them on the grounds that rakkess
or rbac-tool would cover them was simply wrong.

[rakkess]: https://github.com/corneliusweig/rakkess
[rbac-tool]: https://github.com/alcideio/rbac-tool
[rbac-lookup]: https://github.com/FairwindsOps/rbac-lookup

## Why `kubectl` and not a Kubernetes client

The tool needs five list calls and no watches, no CRDs and no server-side
apply. `kubernetes-client` would add a dependency tree, a version-skew surface
and its own authentication handling — in exchange for nothing this tool uses.

Shelling out to `kubectl` means authentication is *already solved*: a
kubeconfig, an in-cluster ServiceAccount token, an exec plugin for EKS or GKE,
a proxy — all of it works because kubectl handles it, not because this script
does. `--context` picks which one.

The only dependency outside the standard library is PyYAML, for the policy
file. The image is `python:3.14-alpine3.22`, pinned by digest, with a pinned
kubectl copied in.

## The snapshot is the boundary

`capture()` is the only function that talks to a cluster. Everything else takes
snapshot dicts, which is why `diff OLD NEW` works with no cluster at all — the
mode CI without cluster access uses, and the mode the tests run in.

## Why the snapshot is normalised

A snapshot lives in a repository and is read as a `git diff`, so byte-identical
RBAC has to produce byte-identical bytes. Capture therefore:

| Normalisation                                      | Because                                                                                                     |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| every rule field sorted and deduplicated           | `verbs: [list, get]` and `verbs: [get, list]` are the same grant                                            |
| rules sorted, identical rules collapsed            | the API returns them in whatever order they were applied                                                    |
| objects sorted by namespace and name               | same reason                                                                                                 |
| a ServiceAccount subject's namespace made explicit | Kubernetes defaults it to the binding's; the two spellings are one grant                                    |
| `metadata` reduced to name and namespace           | `resourceVersion`, `uid`, `creationTimestamp` and `managedFields` change on their own and mean nothing here |
| `roleRef.apiGroup` dropped                         | it is `rbac.authorization.k8s.io` for every binding Kubernetes accepts                                      |
| **no timestamp in the payload**                    | `git log` already knows when. A timestamp inside would make every snapshot differ from every other one      |

`aggregationRule` is kept: for an aggregated ClusterRole it is the thing a
human edits, and the rules underneath it are what the controller wrote.

The file carries `"apiVersion": "rbac-audit/v1"` and `"kind": "RbacSnapshot"`.
A reader that does not know a version refuses rather than guesses.

`kind` is not decoration. The `--json` diff report carries the same
`apiVersion`, so without it a report is accepted as a snapshot and read as an
empty cluster — which reports the entire cluster as newly added and fails the
build for nothing. Loading also validates the structure, field by field, and
names the field that is wrong: this is the input to a security gate, and a gate
that reads a malformed file as an empty cluster is worse than one that refuses.

## What the diff compares

Objects, by kind and qualified name. An object is *added*, *removed* or
*changed*; a changed role reports its rules added and removed, a changed
binding its subjects.

Additions and removals are expressed the same way a modification is — an added
role is every one of its rules added — so a policy check never has to ask which
of the three it is looking at.

One case is worth stating: `roleRef` is immutable, so a binding whose `roleRef`
differs between snapshots was deleted and recreated under the same name. Every
subject now holds a different role. The diff records that in `newlyGranted`
rather than in `subjects.added` — a subject the binding already named was not
newly bound to it, and saying otherwise printed the same subject as both an
addition and a removal.

## Rules are containers; grants are permissions

The policy judges **grants**, not rules, and that distinction is load-bearing.

A grant is one verb on one resource in one apiGroup, optionally narrowed to one
`resourceName` — or one verb on one non-resource URL. `rule_grants()` expands a
PolicyRule into them.

Rules are mutable containers, so comparing them as wholes gets tightenings
backwards. Narrowing `verbs: [bind, get, list]` to `verbs: [bind]` replaces one
rule with another: a rule-level diff sees a rule removed and a rule added, and
reports the surviving `bind` as a **new** grant of `bind` — failing the build
for *removing* two verbs. A grant-level diff says two grants were lost and none
gained, which is what happened.

Being literal about grants is not enough on its own, because a narrower grant
is a different tuple. Each side of the delta is therefore filtered against what
the other already **implied**: `_grant_subsumers()` asks whether a broader grant
was already there — `*` in place of the apiGroup, resource or verb, or the same
grant without the `resourceName` that now narrows it. So all of these are
correctly silent:

| Change                                          | Why it is not a new grant                      |
| ----------------------------------------------- | ---------------------------------------------- |
| `resources: [*]` → `resources: [pods]`          | pods was already covered by `*`                |
| `verbs: [*]` → `verbs: [get, list]`             | both were already covered by `*`               |
| adding `resourceNames: [db]` to a rule          | every name was already covered, `db` included  |
| splitting one rule into two that grant the same | the same grants, in different containers       |
| `/api/*` → `/api/v1`                            | non-resource URLs are the one place RBAC globs |

Subsumption runs one way only. Replacing `resources: [pods]` with
`resources: [*]` is a new grant and is reported.

The human diff still prints **rules**, because a rule is what somebody has to
edit. So does the machine report, alongside a `grantCounts` summary: the
expanded grants stay internal, because they are quadratic in the size of a rule
— one rule over 40 resources and 12 verbs is 1440 grants, and serialising them
would make a first-run diff of a real cluster tens of megabytes of JSON.

## One finding per reason, not per grant

A rule granting `*` on five resources with three verbs is fifteen new grants.
Fifteen identical findings is a report nobody reads, so violations that say the
same thing about the same object collapse into the first with a count —
`(+14 more like it)`. The key is per rule: which fields carry the `*` for
`wildcard`, which verb for `escalating-verbs`. Two different escalation verbs
stay two findings, because they are two different things to go and fix.

## The policy

Four rules, all on and all blocking by default, because a gate that ships
permissive is a gate nobody ever tightens:

| Rule                     | Reports                                                         | Default |
| ------------------------ | --------------------------------------------------------------- | ------- |
| `cluster-admin-binding`  | a subject newly bound to `cluster-admin`                        | blocks  |
| `wildcard`               | a new grant with `*` in `verbs`, `resources` or `apiGroups`     | blocks  |
| `escalating-verbs`       | a new grant of `bind`, `escalate` or `impersonate`              | blocks  |
| `anonymous-subject`      | a new binding to `system:anonymous` or `system:unauthenticated` | blocks  |
| `dangling-binding`       | a binding naming a ServiceAccount that does not exist           | blocks  |
| `unused-service-account` | a ServiceAccount no pod mounts                                  | warns   |

Four decisions behind them:

**Only additions are judged.** A gate that fails a build for *removing*
cluster-admin is a gate people route around.

**`escalating-verbs` ignores `*`.** A wildcard verb grants `bind`, `escalate`
and `impersonate` too, but the `wildcard` rule already reports that grant.
Saying it twice trains people to skim the list.

**`unused-service-account` warns where the rest block.** The other five say
something got more dangerous; this one says something is untidy. On a first
`baseline` it is also usually the longest list, and a gate that is red on day
one is a gate somebody switches off — taking the other five with it.

**`dangling-binding` blocks.** It looks like hygiene and is not: Kubernetes
accepts a binding to a subject that does not exist and never warns when the
subject later appears. The binding simply starts granting. It is a privilege
grant with a trigger attached.

`cluster-admin-binding` reads `newlyGranted` and `anonymous-subject` reads
`subjects.added`, which is not an inconsistency. The first watches *the role*:
re-pointing a binding at cluster-admin gives it to every subject already in
the binding. The second watches *the subject*: one already named by the binding
is not newly bound to it, so narrowing that binding's role is not a new
anonymous grant.

A malformed policy file is fatal, and an unknown rule name is an error rather
than a warning: a typo would otherwise leave that rule at its default — a check
the author believes they turned off and did not.

Setting *values* are type-checked for the same reason. `verbs: bind` instead of
`verbs: [bind]` is a plausible mistake in YAML, and left unchecked it turns a
membership test into a substring one: the rule quietly stops matching what it
should, or starts matching what it should not (`roles: cluster-admin` would
flag a binding to a ClusterRole named `admin`).

`--no-policy` downgrades every rule to `fail: false` rather than disabling it.
The flag exists so somebody can read what the gate *would* have blocked before
switching it on, which only works if the violations are still printed — marked
`(warn)`, with `(none gating)` on the summary line.

## What a snapshot cannot answer

`unused-service-account` needs the cluster's pods. They are not in the snapshot
and will not be: a pod name carries a fresh random suffix on every rollout, so
committing them would make each snapshot diff enormous and meaningless —
destroying the one property the file exists to have. They are read at
evaluation time instead, by `capture_pod_service_accounts()`, and only when
there is a cluster to read.

So the rule cannot run files-only. `evaluate` returns such rules as **skipped**
and both reports name them:

```text
Not checked (1)
  [unused-service-account] needs the cluster's pods, which a snapshot does not
  carry — run it against a live cluster
```

Not a pass and not a failure. A security check that silently does not run is
the failure mode this tool is built against, and "not checked" and "checked and
clean" are different answers — only one of them is reassuring. A rule turned
off on purpose is not reported here; only one that could not run.

## The subject matrix

`--subject` scopes the diff to the objects that reach one subject: the bindings
naming it on either side, and the roles those bindings reference. The policy
still runs, over that scoped set, so the exit code means the same thing.

The matrix itself is built from effective permissions rather than from the
object diff: for each snapshot, walk the subject's bindings, resolve each
`roleRef`, and expand the rules into `(namespace, resource) × verb` cells. A
ClusterRoleBinding lands in namespace `*`, because it applies in all of them.

**Wildcards are carried through literally, not expanded.** Expanding `*`
resources needs API discovery, and a matrix that invented rows the cluster
never returned would be wrong in the direction that matters. A `*` row means
exactly what the rule says.

Likewise, a binding to a role that does not exist contributes nothing:
Kubernetes accepts such a binding and it grants nothing until someone creates
that role.

## Exit codes

`diff` exits 2 when the policy fails. Everything else follows sysexits, so a CI
job can tell "the cluster said no" from "you typed it wrong" without reading
the message:

| Code | When                                                         |
| ---- | ------------------------------------------------------------ |
| 0    | success — no violations, or every one exempted               |
| 2    | at least one policy violation with `fail: true`              |
| 64   | missing operand, an unknown flag, or a malformed `--subject` |
| 65   | a snapshot or policy file that could not be parsed           |
| 66   | a file named on the command line does not exist              |
| 69   | `kubectl` could not reach the cluster                        |
| 73   | an output file could not be written                          |

64 rather than argparse's default of 2 is deliberate: this tool spends 2 on
"the policy failed", and a pipeline must not read a typo as a security finding.

The table lives in one place, at the top of `rbac_audit.py`.

## Permissions

`manifests/cronjob.yaml` ships the ClusterRole it needs: `get` and `list` on
the four RBAC kinds plus ServiceAccounts. No `watch`, no writes, and no Pods —
those were only there for the unused-ServiceAccount finding, which is gone.

An auditor with write access to what it audits is its own finding. The
read-only grant is also small enough to be reviewed in the pull request that
adds it, which is the point of shipping it rather than describing it.

## Adding a policy rule

1. A check function taking `(change, settings)` and yielding `_violation(...)`
   records, next to the other four.
1. An entry in `DEFAULT_POLICY["rules"]` and one in `CHECKS`, keyed the same. A
   test asserts those two agree, so a rule with no check cannot ship.
1. A case in `tests/test_policy.py` for the rule firing *and* for it not firing
   on the change that looks like it. The second one is what stops a noisy rule.
1. A row in the table above, and in `.rbac-policy.example.yaml`.

Before adding one, ask what a reader does when it goes red. A gate that has
been failing since the day it was added is a gate somebody has already learned
to `--no-policy` past.
