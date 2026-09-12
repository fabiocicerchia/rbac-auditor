# rbac-auditor

[![CI](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/ci.yml)
[![Code Quality](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/rbac-auditor/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/rbac-auditor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/rbac-auditor)
[![CI carbon](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fabiocicerchia/rbac-auditor/gh-pages/badge.json)](.github/workflows/carbon-badge.yml)

Commit your cluster's RBAC, then **fail the build when it changes for the
worse**.

`snapshot` writes Roles, ClusterRoles, bindings and ServiceAccounts to a
deterministic JSON file you keep in git. `diff` compares two of those — or a
committed one against the live cluster — prints what changed, and applies a
policy that decides the exit code.

RBAC drift is invisible until an incident. This makes it a pull request.

## What this tool does not do, and what to use instead

Point-in-time questions about a cluster are solved. These tools do them well,
are krew-installable and have vendors behind them:

| You want                                  | Use                                                          |
| ----------------------------------------- | ------------------------------------------------------------ |
| "who can delete pods?"                    | [rbac-tool][rbac-tool] `who-can`, [rbac-lookup][rbac-lookup] |
| an access matrix for a subject, right now | [rakkess][rakkess], [rbac-tool][rbac-tool] `policy-rules`    |
| list every wildcard grant in the cluster  | [rbac-tool][rbac-tool] `analysis`                            |
| visualise who reaches what                | [rbac-tool][rbac-tool] `viz`                                 |

Earlier releases of rbac-auditor shipped a `who-can` query, a findings
`report` (wildcard grants, cluster-admin bindings, unused ServiceAccounts,
dangling bindings), an HTML renderer and an S3 upload. **They are gone as of
2.0.** They duplicated the tools above and did it worse — no aggregated
ClusterRole resolution, no API discovery.

What none of those tools do is answer *what changed since last week, and is any
of it dangerous*. That is the whole of this one.

[rakkess]: https://github.com/corneliusweig/rakkess
[rbac-tool]: https://github.com/alcideio/rbac-tool
[rbac-lookup]: https://github.com/FairwindsOps/rbac-lookup

## Commands

| Command                              | Output                                                    |
| ------------------------------------ | --------------------------------------------------------- |
| `snapshot`                           | deterministic JSON of the cluster's RBAC, for committing  |
| `diff OLD`                           | that snapshot against the live cluster                    |
| `diff OLD NEW`                       | two snapshots, no cluster needed                          |
| `diff OLD [NEW] --subject KIND/NAME` | the same diff as a resource × verb matrix for one subject |

Add `--json PATH` to any `diff` for the machine-readable version (`-` for
stdout), and `--policy PATH` to point at a policy other than
`./.rbac-policy.yaml`.

## Install

```sh
make install                     # pip install .
make build                       # …or build the image locally
```

## Usage

```sh
# take a snapshot and commit it
rbac-audit snapshot -o rbac/prod.json
git add rbac/prod.json && git commit -m "chore(rbac): weekly snapshot"

# a week later: what drifted, and does it fail the policy?
rbac-audit diff rbac/prod.json          # exits 2 on a policy violation

# two committed snapshots — no cluster access, for CI
rbac-audit diff rbac/prod-2026-09-01.json rbac/prod-2026-09-08.json

# what can this ServiceAccount do today that it could not last week?
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

In a container, with your kubeconfig:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  fabiocicerchia/rbac-auditor snapshot > rbac/prod.json
```

## The policy

`diff` fails the build (exit 2) on any of these, out of the box:

- a new binding to `cluster-admin`
- a new rule with `*` in `verbs`, `resources` or `apiGroups`
- a new grant of `bind`, `escalate` or `impersonate`
- a new binding to `system:anonymous` or `system:unauthenticated`

Only *additions* are judged: taking a grant away never fails a build. Every
rule can be exempted per object, downgraded to a warning, or turned off — see
[`.rbac-policy.example.yaml`](.rbac-policy.example.yaml) and
[Getting Started](docs/getting-started.md#relaxing-the-policy).

## Verifying the image

Every published image is signed with [cosign][cosign], keyless: the identity in
the signature is the workflow that published it, not a key anybody holds.

```sh
cosign verify ghcr.io/fabiocicerchia/rbac-auditor:latest \
  --certificate-identity-regexp \
    'https://github.com/fabiocicerchia/rbac-auditor/.github/workflows/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`no signatures found` means the tag predates signing, not that verification was
set up wrongly — a wrong identity or issuer says so explicitly. Re-run the
publish workflow for that tag to sign it.

[cosign]: https://docs.sigstore.dev/

## Development

`make help` lists every target. Every repository in this estate exposes the
same eight verbs, so you do not have to read a Makefile to find out how to
build or run it (FC-GEN-057).

| Verb      | What it does here                                         |
| --------- | --------------------------------------------------------- |
| `setup`   | Install the pre-commit hook                               |
| `install` | `pip install .` — the CLI and its man page                |
| `build`   | Build the image locally                                   |
| `run`     | Snapshot the cluster in your kubeconfig — `ARGS=snapshot` |
| `test`    | Unit tests against fixtures, then the image smoke tests   |
| `lint`    | `pre-commit run --all-files` — the whole gate             |
| `format`  | `ruff format .`                                           |
| `analyze` | `trivy fs` — vulnerabilities, misconfig, secrets          |

Beyond the eight: `push` and `release`. All eight are wired, so there is
nothing under "Not applicable".

The unit tests need no cluster and no Docker:

```sh
python3 -m unittest discover -s tests
```

## Documentation

Full docs live in [`docs/`](docs/). Runnable examples live in [`examples/`](examples/).

## License

Apache-2.0 — see [LICENSE](LICENSE).
