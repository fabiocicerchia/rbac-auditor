#!/usr/bin/env bash
# Local test cluster: kind + kubernetes-goat (deliberately awful RBAC).
# Not committed — throwaway dev helper. `./dev-cluster.sh down` to tear it down.
set -euo pipefail

CLUSTER=${CLUSTER:-rbac-auditor}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.31.0}   # VERSION-BUMP
GOAT_REF=${GOAT_REF:-master}                     # VERSION-BUMP
GOAT_DIR=${GOAT_DIR:-/tmp/kubernetes-goat}

if [ "${1:-up}" = "down" ]; then
  kind delete cluster --name "$CLUSTER"
  exit 0
fi

for bin in kind kubectl helm git; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }
done

kind get clusters | grep -qx "$CLUSTER" ||
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
kubectl config use-context "kind-$CLUSTER"

[ -d "$GOAT_DIR" ] || git clone --depth 1 -b "$GOAT_REF" \
  https://github.com/madhuakula/kubernetes-goat.git "$GOAT_DIR"

cd "$GOAT_DIR"
bash setup-kubernetes-goat.sh

echo
echo "Cluster up. Audit it with:"
echo "  python3 rbac_audit.py            # uses current kubeconfig context"
echo "  ./dev-cluster.sh down            # tear down"
