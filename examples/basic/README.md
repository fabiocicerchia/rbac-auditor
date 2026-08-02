# Basic Example

What it shows: a finding this tool exists to catch, created deliberately in a
throwaway cluster, then found.

Needs `kind` (or any cluster you do not mind writing to) and Docker.

## Set up a cluster with something wrong in it

```sh
kind create cluster --name rbac-demo
```

Create a RoleBinding pointing at a ServiceAccount that does not exist. This is
accepted without complaint — that is the whole problem:

```sh
kubectl create namespace apps
kubectl create rolebinding grafana-reader \
  --clusterrole=view \
  --serviceaccount=apps:grafana \
  --namespace=apps
```

`apps/grafana` does not exist. Kubernetes does not care, and never will —
including on the day someone creates it.

## Find it

```sh
docker run --rm --network host -v ~/.kube:/home/auditor/.kube:ro \
  fabiocicerchia/rbac-auditor report
```

```markdown
## Dangling bindings (1)

- rolebinding `apps/grafana-reader` references missing ServiceAccount `apps/grafana`
```

`--network host` is for kind specifically: the kubeconfig points at
`127.0.0.1`, which inside a container is the container. Against a real cluster
you do not need it.

## Watch the drift show up

Take a snapshot, change something, diff:

```sh
docker run --rm --network host -v ~/.kube:/home/auditor/.kube:ro \
  fabiocicerchia/rbac-auditor dump > before.json

kubectl create clusterrolebinding oops \
  --clusterrole=cluster-admin --serviceaccount=default:default

docker run --rm --network host -v ~/.kube:/home/auditor/.kube:ro \
  -v "$PWD:/snapshots:ro" \
  fabiocicerchia/rbac-auditor diff /snapshots/before.json
```

```text
+ added   clusterrolebinding oops
```

One line, and it is the line that matters. That is the argument for keeping
dumps in git: the full report on a real cluster is hundreds of lines, and a
month-over-month diff is a handful.

The report now also flags it directly:

```sh
docker run --rm --network host -v ~/.kube:/home/auditor/.kube:ro \
  fabiocicerchia/rbac-auditor report | grep -A3 'cluster-admin'
```

## Check `who-can` against the authoritative answer

```sh
docker run --rm --network host -v ~/.kube:/home/auditor/.kube:ro \
  fabiocicerchia/rbac-auditor who-can delete pods

kubectl auth can-i delete pods --as=system:serviceaccount:default:default
```

The second is the API server evaluating its own rules and is definitive.
`who-can` does not resolve aggregated ClusterRoles, so it can list fewer
subjects than really have the verb — use it to find candidates, then confirm
each with `auth can-i`.

## Clean up

```sh
kind delete cluster --name rbac-demo
rm -f before.json
```
