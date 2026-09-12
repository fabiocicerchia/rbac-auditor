# Examples

- [`basic/`](basic) — commit a snapshot of a throwaway `kind` cluster, make a
  cluster-admin binding nobody reviewed, and watch the diff fail the gate; then
  the same thing on two files, with no cluster at all.

For the in-cluster weekly snapshot, the manifests are the example:
[`manifests/cronjob.yaml`](../manifests/cronjob.yaml) — CronJob, ServiceAccount
and a read-only ClusterRole, short enough to review before applying.
