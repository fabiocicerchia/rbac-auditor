# rbac-auditor

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

## Usage

```sh
# local, using your kubeconfig
docker run --rm -v ~/.kube:/home/auditor/.kube:ro fabiocicerchia/rbac-auditor report

# weekly in-cluster report (read-only ClusterRole included)
kubectl apply -f manifests/cronjob.yaml

# month-over-month drift
docker run ... dump > january.json
docker run ... diff january.json
```

## Status & roadmap

- [x] Findings report, dump/diff, who-can
- [ ] Aggregated ClusterRole resolution in `who-can`
- [ ] HTML report output + S3 upload (mirroring kube-bench-runner)
- [ ] Findings suppression file (`.rbac-audit-ignore`)

## Development

`make build` / `make lint` / `make test` / `make release`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
