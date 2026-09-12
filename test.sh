#!/usr/bin/env sh
# Smoke test: the image runs, kubectl is in it, and the files-only path — the
# one CI without cluster access uses — produces a diff and the documented exit
# code. Anything needing a cluster belongs in the unit tests, which run against
# fixture snapshots.
set -eu
IMAGE="${1:?usage: test.sh <image:tag>}"
FIXTURES="$(CDPATH='' cd -- "$(dirname -- "$0")/tests/fixtures" && pwd)"

# WORK is mounted writable at /out, so a file the container produces can be
# fed back to the container. A host path passed as an argument would not exist
# inside it.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# --user: the image declares USER 10001, which cannot write to a directory
# mktemp created for whoever is running this. Running as the caller is also how
# the docs tell people to invoke it.
run() {
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$FIXTURES:/fixtures:ro" -v "$WORK:/out" "$IMAGE" "$@"
}

# Help text names every command there is.
for command in snapshot baseline diff; do
  docker run --rm "$IMAGE" --help 2>&1 | grep -qE "^usage:.*\{.*$command.*\}" || {
    echo "FAIL: '$command' is missing from the usage line" >&2
    exit 1
  }
done

# The removed commands are refused as usage errors, not run. Grepping the help
# text would not prove it: the help text names who-can, to say it is gone.
for gone in who-can report dump; do
  docker run --rm "$IMAGE" "$gone" >/dev/null 2>&1 && rc=0 || rc=$?
  if [ "$rc" -ne 64 ]; then
    echo "FAIL: '$gone' was removed on purpose; expected exit 64, got $rc" >&2
    exit 1
  fi
done

docker run --rm --entrypoint kubectl "$IMAGE" version --client >/dev/null

# No kubeconfig: a readable kubectl error, not a Python traceback.
docker run --rm "$IMAGE" snapshot 2>&1 | grep -q "kubectl get clusterroles failed"
# `! cmd` would skip errexit (SC2251), so assert the absence explicitly.
if docker run --rm "$IMAGE" snapshot 2>&1 | grep -q "Traceback"; then
  echo "FAIL: snapshot leaked a Python traceback instead of a readable error" >&2
  exit 1
fi

# Files only, no cluster: the diff renders and the policy gate exits 2.
run diff /fixtures/before.json /fixtures/after.json >/tmp/diff.txt 2>&1 && rc=0 || rc=$?
if [ "$rc" -ne 2 ]; then
  echo "FAIL: a policy violation should exit 2, got $rc" >&2
  cat /tmp/diff.txt >&2
  exit 1
fi
grep -q "cluster-admin-binding" /tmp/diff.txt
grep -q "anonymous-subject" /tmp/diff.txt

# The same diff scoped to one subject, as a matrix.
run diff /fixtures/before.json /fixtures/after.json \
  --subject ServiceAccount/ci/deployer --no-policy | grep -q "NAMESPACE"

# A snapshot compared with itself is clean, and says so with exit 0.
run diff /fixtures/before.json /fixtures/before.json | grep -q "No changes."

# Tightening RBAC must never fail the gate: narrowed.json drops a verb, drops
# an escalation verb and restricts a rule to one resourceName. The rules all
# change, so a rule-level diff would call the survivors new grants.
run diff /fixtures/after.json /fixtures/narrowed.json >/tmp/narrow.txt 2>&1 && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: narrowing RBAC should exit 0, got $rc" >&2
  cat /tmp/narrow.txt >&2
  exit 1
fi
grep -q "No policy violations." /tmp/narrow.txt

# --no-policy prints what it would have blocked rather than hiding it.
run diff /fixtures/before.json /fixtures/after.json --no-policy | grep -q "(warn)"

# baseline judges the whole cluster, not just what changed: everything counts
# as an addition, so the standing cluster-admin binding is reported.
run baseline /fixtures/after.json >/tmp/base.txt 2>&1 && rc=0 || rc=$?
if [ "$rc" -ne 2 ]; then
  echo "FAIL: baseline on a cluster with a cluster-admin binding should exit 2, got $rc" >&2
  cat /tmp/base.txt >&2
  exit 1
fi
grep -q "RBAC baseline" /tmp/base.txt
grep -q "cluster-admin-binding" /tmp/base.txt
# A rule that cannot run says so rather than passing silently.
grep -q "Not checked" /tmp/base.txt
grep -q "unused-service-account" /tmp/base.txt

# A binding to a ServiceAccount that does not exist is a latent privilege grant.
run diff /fixtures/after.json /fixtures/dangling.json >/tmp/dangle.txt 2>&1 && rc=0 || rc=$?
if [ "$rc" -ne 2 ]; then
  echo "FAIL: a new dangling binding should exit 2, got $rc" >&2
  cat /tmp/dangle.txt >&2
  exit 1
fi
grep -q "dangling-binding" /tmp/dangle.txt

# A --json diff report is not a snapshot, even though it shares the apiVersion.
run diff /fixtures/before.json /fixtures/after.json --json /out/report.json \
  >/dev/null 2>&1 || true
if [ ! -s "$WORK/report.json" ]; then
  echo "FAIL: --json wrote no report" >&2
  exit 1
fi
run diff /out/report.json /fixtures/after.json >/dev/null 2>&1 && rc=0 || rc=$?
if [ "$rc" -ne 65 ]; then
  echo "FAIL: a diff report read as a snapshot should exit 65, got $rc" >&2
  exit 1
fi

rm -f /tmp/diff.txt /tmp/narrow.txt /tmp/base.txt /tmp/dangle.txt
echo PASS
