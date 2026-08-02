# Architecture

One Python file, `kubectl` for the API calls, and no client library.

```
kubectl get {roles,clusterroles,rolebindings,clusterrolebindings,
             serviceaccounts,pods} -A -o json
        │
        └──► snapshot()  — one dict, timestamped, the input to everything
                 │
                 ├── report()    findings + inventory, as markdown
                 ├── dump        the snapshot itself, as JSON
                 ├── diff OLD    snapshot vs snapshot
                 └── who-can     subjects granted a verb on a resource
```

## Why `kubectl` and not a Kubernetes client

The tool needs six list calls and no watches, no CRDs and no server-side apply.
`kubernetes-client` would add a dependency tree, a version-skew surface, and
its own authentication handling — in exchange for nothing this tool uses.

Shelling out to `kubectl` means authentication is *already solved*: a
kubeconfig, an in-cluster ServiceAccount token, an exec plugin for EKS or GKE,
a proxy — all of it works because kubectl handles it, not because this script
does.

The single dependency is PyYAML, and the image is `python:3.13-alpine` with a
pinned kubectl copied in.

## The snapshot is the boundary

Every command takes the same `snapshot()` dict. Nothing else calls the cluster.

That is what makes `dump` and `diff` work at all: a dump written in January and
a live snapshot in February are the same shape, so the diff is a set operation
rather than a special code path. It is also what makes the findings testable —
they are pure functions of a dict.

`pods` are in the snapshot for one reason: an "unused ServiceAccount" is one no
pod references, and that cannot be answered from RBAC objects alone.

## The four findings, and what each is really detecting

| Finding | Detects |
|---|---|
| **Wildcard grants** | A rule with `*` in **both** verbs and resources. Deliberately narrow: `*` verbs on one named resource is often intentional, and flagging it trains people to ignore the report. |
| **cluster-admin bindings** | Any ClusterRoleBinding whose `roleRef.name` is `cluster-admin`, with its subjects named. Rarely wrong to have one; usually wrong to have eleven and not know it. |
| **Unused ServiceAccounts** | A SA no pod mounts. Each one is a credential nobody is watching. `default` is excluded, because every namespace has one and it is never "unused". |
| **Dangling bindings** | A binding referencing a ServiceAccount that does not exist. Harmless today; a privilege grant that activates the moment someone creates a SA with that name in that namespace. |

The dangling-binding case is the one worth understanding: Kubernetes does not
reject a binding to a nonexistent subject, and it does not warn when the
subject later appears. The binding just starts working.

## What `who-can` does not do

It walks roles whose rules match the verb and resource, then walks bindings
that reference them. **It does not resolve `aggregationRule`**, so a subject
that gets the verb through an aggregated ClusterRole — which includes several
built-in roles — will not appear.

That is a known gap, on the roadmap, and stated here because a security query
that silently under-reports is worse than one that refuses to answer. Treat the
output as a lower bound. `kubectl auth can-i --list --as=<subject>` is the
authoritative check for any single subject.

## Exit codes

`report` exits 2 when there are findings **and** `--fail-on-findings` was
passed; 0 otherwise. So the same command is a report by default and a gate when
you ask for one — which matters because the first thing you do with a new
findings tool is read it, and the second is decide which findings you are
willing to block on.

## Permissions

`manifests/cronjob.yaml` ships the ClusterRole it needs: `get` and `list` on
the four RBAC kinds plus ServiceAccounts and Pods. No `watch`, no writes.

An auditor with write access to what it audits is its own finding. The
read-only grant is also small enough to be reviewed in the PR that adds it,
which is the point of shipping it rather than describing it.

## Adding a finding

1. A generator function taking `snap` and yielding strings, next to the other
   four.
2. A row in the `sections` list in `report()`.
3. It has to be a pure function of the snapshot — anything that needs its own
   API call breaks `diff` and the archived-dump workflow.

Before adding one, ask what a reader does with it. The report is only useful
while people still read it, and the fastest way to kill it is a section that is
always non-empty and never actionable.
