# rbac-auditor

[![CI](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/ci.yml)
[![Code Quality](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/rbac-auditor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/rbac-auditor)

Dumps and diffs Kubernetes **RBAC into readable reports**: wildcard grants,
cluster-admin bindings, unused ServiceAccounts, dangling bindings, plus
`who-can` queries and snapshot diffing for change tracking.

RBAC drift is invisible until an incident. This makes it a weekly markdown
report a human actually reads.

## Commands

| Command | Output |
|---|---|
| `report` | markdown findings report (add `--fail-on-findings` for CI gates) |
| `dump` | raw JSON snapshot for archiving |
| `diff old.json` | added/removed/changed roles & bindings vs. a snapshot |
| `who-can VERB RESOURCE` | subjects that can e.g. `delete pods` |

## Install

```sh
make build                       # builds fabiocicerchia/rbac-auditor:0.1.0 locally
docker pull fabiocicerchia/rbac-auditor:0.1.0
```

## Usage

```sh
# local, using your kubeconfig
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig fabiocicerchia/rbac-auditor report

# weekly in-cluster report (read-only ClusterRole included)
kubectl apply -f manifests/cronjob.yaml

# month-over-month drift
docker run ... dump > january.json
docker run ... diff january.json
```

## Development

`make build` / `make lint` / `make test` / `make release`.

## Documentation

Full docs live in [`docs/`](docs/). Runnable examples live in [`examples/`](examples/).

## License

Apache-2.0 — see [LICENSE](LICENSE).
