#!/usr/bin/env sh
# Smoke test: help text renders, kubectl present, script compiles.
set -eu
IMAGE="${1:?usage: test.sh <image:tag>}"
docker run --rm "$IMAGE" help 2>&1 | grep -q "who-can"
docker run --rm --entrypoint kubectl "$IMAGE" version --client >/dev/null
# no kubeconfig: readable kubectl error, not a Python traceback
docker run --rm "$IMAGE" report 2>&1 | grep -q "kubectl get roles failed"
# `! cmd` would skip errexit (SC2251), so assert the absence explicitly.
if docker run --rm "$IMAGE" report 2>&1 | grep -q "Traceback"; then
  echo "FAIL: report leaked a Python traceback instead of a readable error" >&2
  exit 1
fi
echo PASS
