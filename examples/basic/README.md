# Basic Example

What it shows: a dangerous RBAC change, caught by a diff against a committed
snapshot rather than by someone reading a report.

Needs `kind` (or any cluster you do not mind writing to) and Docker.

## Set up a cluster and commit its RBAC

```sh
kind create cluster --name rbac-demo

docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor snapshot > before.json
```

`--network host` is for kind specifically: the kubeconfig points at
`127.0.0.1`, which inside a container is the container. Against a real cluster
you do not need it.

Look at `before.json`. It is sorted, normalised and carries no timestamp, which
is the whole reason it is worth committing: re-running against an unchanged
cluster produces the same bytes, so any `git diff` on it is real.

## Make the change nobody reviewed

```sh
kubectl create clusterrolebinding oops \
  --clusterrole=cluster-admin --serviceaccount=default:default
```

## Catch it

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  -v "$PWD:/snapshots:ro" \
  fabiocicerchia/rbac-auditor diff /snapshots/before.json
echo "exit: $?"
```

```text
RBAC diff — /snapshots/before.json → live cluster

+ ClusterRoleBinding/oops
    roleRef ClusterRole/cluster-admin
    + ServiceAccount default/default

Policy violations (1)
  [cluster-admin-binding] ClusterRoleBinding/oops
      binds ServiceAccount default/default to ClusterRole/cluster-admin

1 added, 0 removed, 0 changed; 1 policy violations.
exit: 2
```

One line of diff, and a non-zero exit. That is the argument for keeping
snapshots in git: the full RBAC of a real cluster is thousands of lines, and
the week's diff is a handful — small enough that someone will actually read it,
and mechanical enough that CI can decide without them.

## Ask what that ServiceAccount gained

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  -v "$PWD:/snapshots:ro" \
  fabiocicerchia/rbac-auditor diff /snapshots/before.json \
    --subject ServiceAccount/default/default
```

```text
NAMESPACE  RESOURCE   *
*          *.*        +

  + gained   - lost   = unchanged   . not granted
```

It went from nothing to everything, everywhere.

## Accept it, deliberately

If that binding is intentional, say so in the policy rather than silencing the
rule. Write `.rbac-policy.yaml`:

```yaml
version: 1
exempt:
  - rule: cluster-admin-binding
    object: ClusterRoleBinding/oops
    reason: demo binding, deliberately created by examples/basic
```

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  -v "$PWD:/snapshots:ro" \
  fabiocicerchia/rbac-auditor diff /snapshots/before.json \
    --policy /snapshots/.rbac-policy.yaml
echo "exit: $?"
```

Exit 0 — and the violation is still printed, under **Exempted**, with the
reason next to it. An accepted risk stays visible; it just stops blocking.

## No cluster? The same thing with two files

Every command above works on two snapshot files, which is how CI runs it
without holding cluster credentials:

```sh
rbac-audit diff before.json after.json
```

The fixtures in [`tests/fixtures/`](../../tests/fixtures) are a pair you can
try it on immediately.

## Clean up

```sh
kind delete cluster --name rbac-demo
rm -f before.json .rbac-policy.yaml
```
