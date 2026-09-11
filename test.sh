#!/usr/bin/env sh
# Smoke test: the image runs, kubectl is in it, and the files-only path — the
# one CI without cluster access uses — produces a diff and the documented exit
# code. Anything needing a cluster belongs in the unit tests, which run against
# fixture snapshots.
set -eu
IMAGE="${1:?usage: test.sh <image:tag>}"
FIXTURES="$(CDPATH='' cd -- "$(dirname -- "$0")/tests/fixtures" && pwd)"

run() { docker run --rm -v "$FIXTURES:/fixtures:ro" "$IMAGE" "$@"; }

# Help text names the two commands there are.
docker run --rm "$IMAGE" --help 2>&1 | grep -q "{snapshot,diff}"

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

rm -f /tmp/diff.txt
echo PASS
