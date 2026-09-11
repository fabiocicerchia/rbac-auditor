# Architecture

One Python file, `kubectl` for the API calls, and no client library.

```bash
kubectl get {roles,clusterroles,rolebindings,clusterrolebindings,
             serviceaccounts} -A -o json
        │
        └──► capture()  — normalised, sorted, no timestamps
                 │
                 ├── snapshot          the snapshot itself, as committable JSON
                 └── diff OLD [NEW]    snapshot vs snapshot, or vs the cluster
                          │
                          ├── changes      added / removed / changed objects
                          ├── policy       which additions fail the build
                          └── --subject    one subject, as a resource × verb matrix
```

## The scope, and what was deliberately removed

Versions before 2.0 also shipped `who-can`, a findings `report` (wildcard
grants, cluster-admin bindings, unused ServiceAccounts, dangling bindings), an
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

The file carries `"apiVersion": "rbac-audit/v1"`. A reader that does not know a
version refuses rather than guesses.

## What the diff compares

Objects, by kind and qualified name. An object is *added*, *removed* or
*changed*; a changed role reports its rules added and removed, a changed
binding its subjects.

Additions and removals are expressed the same way a modification is — an added
role is every one of its rules added — so a policy check never has to ask which
of the three it is looking at.

One case is worth stating: `roleRef` is immutable, so a binding whose `roleRef`
differs between snapshots was deleted and recreated under the same name. Every
subject now points at a different role, which is a new grant for all of them,
and the diff reports it that way.

## The policy

Four rules, all on and all blocking by default, because a gate that ships
permissive is a gate nobody ever tightens:

| Rule                    | Fails on                                                        |
| ----------------------- | --------------------------------------------------------------- |
| `cluster-admin-binding` | a subject newly bound to `cluster-admin`                        |
| `wildcard`              | a new rule with `*` in `verbs`, `resources` or `apiGroups`      |
| `escalating-verbs`      | a new grant of `bind`, `escalate` or `impersonate`              |
| `anonymous-subject`     | a new binding to `system:anonymous` or `system:unauthenticated` |

Two decisions behind them:

**Only additions are judged.** A gate that fails a build for *removing*
cluster-admin is a gate people route around.

**`escalating-verbs` ignores `*`.** A wildcard verb grants `bind`, `escalate`
and `impersonate` too, but the `wildcard` rule already reports that rule.
Saying it twice trains people to skim the list.

A malformed policy file is fatal, and an unknown rule name is an error rather
than a warning: a typo would otherwise leave that rule at its default — a check
the author believes they turned off and did not.

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
