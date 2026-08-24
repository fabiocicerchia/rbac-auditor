# Getting Started

## Prerequisites

A cluster and read access to RBAC. Nothing to install — kubectl is in the
image, and it uses whatever credentials you give it.

## First report, from your laptop

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor report
```

A kind cluster publishes its API server on `127.0.0.1`, so add `--network host`
(its kubeconfig embeds the certs, nothing else to mount):

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor report
```

```markdown
# RBAC audit — 2026-08-02T09:14:22+00:00

## Wildcard grants (1)

- `kube-system/legacy-operator` (role) grants `*` verbs on `*` resources

## cluster-admin bindings (3)

- clusterrolebinding `cluster-admin` grants cluster-admin to Group:/system:masters
- clusterrolebinding `ci-deployer` grants cluster-admin to ServiceAccount:ci/deployer

## Unused ServiceAccounts (7)

- ServiceAccount `staging/old-migrator` is not used by any pod

## Dangling bindings (1)

- rolebinding `apps/grafana-reader` references missing ServiceAccount `apps/grafana`

## Inventory

- roles: 42
- clusterroles: 71
...

**12 findings.**
```

If your kubeconfig uses an exec plugin (EKS, GKE), that binary is not in the
image. Either use a token-based context, or run it in-cluster with the CronJob
below — which is where it belongs anyway.

## Read it before you gate on it

Start with the two findings that are almost always actionable:

**Dangling bindings.** A binding to a ServiceAccount that does not exist is not
inert — Kubernetes does not reject it, and it starts granting the moment
someone creates a SA with that name in that namespace. Delete the binding or
create the account deliberately.

**cluster-admin bindings.** The count is the finding. One or two is normal;
discovering there are eleven is the point of running this.

**Unused ServiceAccounts** are usually a long list on a first run. Each is a
token nobody watches, but working through them is a project, not a fix.

**Wildcard grants** are only flagged when a rule has `*` in both verbs and
resources — the case that is nearly always accidental.

## Run it weekly, in-cluster

```sh
kubectl apply -f manifests/cronjob.yaml
```

That creates the CronJob, the ServiceAccount, and a read-only ClusterRole
scoped to `get`/`list` on the RBAC kinds plus ServiceAccounts and Pods. Read it
before applying — it is short on purpose, so it can be reviewed rather than
trusted.

The report goes to the job's stdout, which is where your log pipeline can see
it:

```sh
kubectl -n security logs job/rbac-auditor-<id>
```

## Track drift instead of re-reading the whole thing

The report tells you what is true. The diff tells you what changed, which is
usually the question:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor dump > snapshots/2026-01.json

# a month later
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  -v "$PWD/snapshots:/snapshots:ro" \
  fabiocicerchia/rbac-auditor diff /snapshots/2026-01.json
```

```text
+ added   clusterrolebinding ci-deployer-v2
~ changed role apps/backend-reader
- removed rolebinding staging/old-migrator
```

Keep the dumps in git. RBAC drift is invisible until an incident, and a
month-over-month diff is small enough that someone will actually read it.

## Ask who can do something

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor who-can delete pods
```

**This is a lower bound, not an answer.** It does not resolve aggregated
ClusterRoles, so subjects that get the verb through aggregation are missing
from the output. For a definitive check on one subject, use the API server's
own evaluation:

```sh
kubectl auth can-i delete pods --as=system:serviceaccount:ci:deployer
```

Use `who-can` to find candidates; use `auth can-i` to confirm them.

## Gate on it in CI

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor report --fail-on-findings
```

Exit code 2 when there are findings. Do this only after you have driven the
count to something you are prepared to keep at zero — a check that has been red
since the day it was added is a check that has been switched off.

## Development

```sh
make build     # docker build
make lint      # hadolint + py_compile
make test      # help text renders, kubectl present, script compiles
make release   # multi-arch buildx push
```

## Suppressing accepted findings

Accepted risks otherwise reappear on every run until the real findings are lost
in them. A `.rbac-audit-ignore` next to the report (or `--ignore-file PATH`)
suppresses findings by `subject`, `role` or `verb`:

```
# The kube-system bootstrap accounts are not ours to fix.
subject=ServiceAccount:kube-system/* reason=cluster bootstrap, upstream-managed

# Break-glass access, reviewed 2026-08.
role=cluster-admin reason=break-glass account, reviewed 2026-08
```

`reason=` is required — an accepted risk with no stated reason is
indistinguishable from a mistake six months later. A value ending in `*`
matches a prefix, and a rule only constrains the fields it names.

Nothing disappears quietly:

- suppressed findings are counted per section and listed under **Suppressed**,
  each with its reason
- a rule that matches nothing is reported under **Stale suppressions**, so the
  file can be pruned as the cluster changes
- the exit code reflects the findings that are *left* — `--fail-on-findings`
  still fails the build for anything unsuppressed

A malformed entry is a fatal error rather than a warning: a suppression nobody
can read hides findings without saying so.

See [`.rbac-audit-ignore.example`](../.rbac-audit-ignore.example).

## HTML reports

Terminal output is fine for a person at a keyboard and no use as a
point-in-time record. `--html` writes the same findings as a self-contained
document — no external stylesheet, font or script, so it renders the same on an
air-gapped laptop a year from now:

```sh
rbac-audit report --html rbac-$(date +%F).html
```

The header states which cluster it describes (context name *and* API server
URL, since two kubeconfigs can name the same server differently) and when it
was generated. Suppressions apply exactly as they do to the markdown report —
same snapshot, same ignore file, same **Suppressed** section.

Add `--s3` to upload it, with server-side encryption on by default:

```sh
rbac-audit report --html rbac.html --s3 s3://my-audit-bucket/rbac/ --sse AES256
```

Upload uses the AWS CLI, so it picks up whatever credentials are already
configured. **A failed upload never loses the local report and never changes
the exit code** — the audit succeeded, only its delivery did not.

> **Treat these reports as sensitive.** A report enumerates who can do what in
> the cluster, which is a map of the permissions worth attacking. Use a private
> bucket, never a public ACL, and keep the same care you would for the
> kubeconfig itself.
