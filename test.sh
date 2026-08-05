#!/usr/bin/env sh
# Smoke test: help text renders, kubectl present, script compiles.
set -eu
IMAGE="${1:?usage: test.sh <image:tag>}"
docker run --rm "$IMAGE" help 2>&1 | grep -q "who-can"
docker run --rm --entrypoint kubectl "$IMAGE" version --client >/dev/null
# no kubeconfig: readable kubectl error, not a Python traceback
docker run --rm "$IMAGE" report 2>&1 | grep -q "kubectl get roles failed"
! docker run --rm "$IMAGE" report 2>&1 | grep -q "Traceback"
echo PASS
