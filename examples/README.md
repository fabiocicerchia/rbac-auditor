# Examples

- [`basic/`](basic) — create a dangling binding in a throwaway `kind` cluster,
  then find it; plus a snapshot diff and the limits of `who-can`.

For the in-cluster weekly report, the manifests are the example:
[`manifests/cronjob.yaml`](../manifests/cronjob.yaml) — CronJob, ServiceAccount
and a read-only ClusterRole, short enough to review before applying.
