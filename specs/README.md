# Specifications of rbac-auditor

What this code does, one atomic Gherkin scenario per behaviour, read from the code by code-atlas.
Tags: `@verified` a test asserts it · `@inferred` read from the code only · `@gap` an entry point no test covers · `@human` written or amended by a person, never rewritten.

## Command Line
The rbac-audit CLI surface: commands, flags, inputs and errors.

- **Cluster access**: [Reading RBAC from the live cluster](command-line/cluster-access/reading-the-live-cluster.feature) (5)
- **Usage and input errors**: [Rejecting bad input with distinct exit codes](command-line/usage-errors/input-errors.feature) (4)

## Drift Detection
Comparing RBAC between two points in time to surface what access changed.

- **Baseline audit**: [Auditing a whole cluster on day one](drift-detection/baseline-audit/day-one-baseline.feature) (4)
- **Effective grant analysis**: [Judging only genuinely new access](drift-detection/grant-analysis/judging-new-access.feature) (2)
- **Snapshot comparison**: [Comparing RBAC snapshots](drift-detection/snapshot-diff/comparing-snapshots.feature) (4)
- **Subject scoping**: [Scoping an audit to one subject](drift-detection/subject-scope/scoping-to-a-subject.feature) (4)

## Operations and Developer Tooling
Building, packaging, deploying and developing the auditor.

- **Build, test and release tasks**: [Snapshotting a cluster through the packaged image](operations/build-release/containerised-snapshot-run.feature) (1)
- **Container image**: [Running the auditor from its container image](operations/container-image/container-image.feature) (3)

## Policy and Gating
Deciding which RBAC changes are risky and whether the run should fail.

- **Exemptions**: [Exempting accepted findings](policy/exemptions/exemptions.feature) (3)
- **Gating and exit codes**: [Gating a build on the policy](policy/gating/gating-the-build.feature) (2), [Deciding whether findings fail the build](policy/gating/gating.feature) (2)
- **Inventory hygiene rules**: [Catching bindings and ServiceAccounts that do not line up with the cluster](policy/inventory-hygiene/inventory-hygiene-rules.feature) (4)
- **Policy configuration**: [Configuring the audit policy](policy/policy-config/policy-configuration.feature) (4)
- **Dangerous privilege rules**: [Flagging dangerous privilege grants](policy/privilege-rules/dangerous-privilege-rules.feature) (6)
- **Privileged subject rules**: [Flagging bindings to privileged or unauthenticated subjects](policy/privileged-subjects/privileged-subject-rules.feature) (3)

## Reporting
Presenting changes and findings to humans and machines.

- **Access matrix**: [Subject access matrix](reporting/access-matrix/subject-access-matrix.feature) (4)
- **Machine-readable report**: [Machine-readable diff report](reporting/json-report/machine-readable-report.feature) (4)
- **Human-readable report**: [Human-readable audit report](reporting/text-report/readable-report.feature) (3)

## RBAC Snapshots
Capturing a cluster's RBAC into a committable, deterministic JSON file and reading it back safely.

- **Capture from manifests**: [Snapshotting RBAC from manifests](snapshots/manifest-capture/snapshot-from-manifests.feature) (6)
- **Normalization and deterministic output**: [Committable, deterministic snapshots](snapshots/normalization/deterministic-snapshots.feature) (3)
- **Snapshot loading and validation**: [Loading snapshot files](snapshots/snapshot-validation/loading-snapshots.feature) (3)
