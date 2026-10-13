#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Fixed names keep every operation scoped to this disposable cluster.
CLUSTER=sts-operator-dev
CONTEXT=k3d-sts-operator-dev
NAMESPACE=sts-operator-dev
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

kube() {
  kubectl --kubeconfig="$work/kubeconfig" --context="$CONTEXT" "$@"
}

load_kubeconfig() {
  k3d kubeconfig get "$CLUSTER" > "$work/kubeconfig"
}

up() {
  if ! docker info > /dev/null 2>&1; then
    echo 'Docker is unavailable. Start Docker Desktop (or your Docker runtime) first.' >&2
    exit 1
  fi
  if ! k3d cluster list -o json | jq -e --arg name "$CLUSTER" 'any(.[]; .name == $name)' > /dev/null; then
    k3d cluster create "$CLUSTER" --servers 1 --agents 0 \
      --image rancher/k3s:v1.35.2-k3s1 --api-port "127.0.0.1:${K3D_API_PORT:-6553}" \
      --kubeconfig-update-default=false --kubeconfig-switch-context=false --wait --timeout=120s
  fi
  load_kubeconfig
  kube wait --for=condition=Ready nodes --all --timeout=120s
}

deploy() {
  load_kubeconfig
  docker build -t sts-operator:dev .
  docker build -f config/local/Dockerfile.mock -t sts-operator-mock:dev .
  k3d image import sts-operator:dev sts-operator-mock:dev --cluster "$CLUSTER"

  kube apply -f config/crd/bases/nais.io_stsclients.yaml
  kube wait --for=condition=Established crd/stsclients.nais.io --timeout=60s
  kube apply -f config/local/rbac.yaml

  # Generate a development-only signing credential once per cluster.
  # Never print the private key or put it in command-line arguments.
  if [[ -z $(kube -n "$NAMESPACE" get secret sts-operator-credentials --ignore-not-found -o name) ]]; then
    step crypto jwk create "$work/public.json" "$work/private.json" \
      --kty RSA --size 2048 --alg RS256 --use sig --no-password --insecure
    kube -n "$NAMESPACE" create secret generic sts-operator-credentials \
      --from-file=STS_OPERATOR_PRIVATE_JWK="$work/private.json"
  fi

  mock_exists=$(kube -n "$NAMESPACE" get deployment mock-sts --ignore-not-found -o name)
  operator_exists=$(kube -n "$NAMESPACE" get deployment sts-operator --ignore-not-found -o name)
  kube apply -f config/local/mock.yaml
  if [[ -n "$mock_exists" ]]; then
    kube -n "$NAMESPACE" rollout restart deployment/mock-sts
  fi
  kube -n "$NAMESPACE" rollout status deployment/mock-sts --timeout=120s
  kube apply -f config/local/operator.yaml
  # The dev image tag is reused; force existing pods to pick up the imported image.
  if [[ -n "$operator_exists" ]]; then
    kube -n "$NAMESPACE" rollout restart deployment/sts-operator
  fi
  kube -n "$NAMESPACE" rollout status deployment/sts-operator --timeout=120s
}

smoke() {
  load_kubeconfig
  kube create namespace sts-demo --dry-run=client -o yaml | kube apply -f -
  # Recreate only this sample so a redeployed mock receives a fresh registration.
  kube -n sts-demo delete stsclient smoke-client --ignore-not-found --wait=true --timeout=60s
  if [[ -n $(kube -n sts-demo get configmap sts-smoke-client --ignore-not-found -o name) ]]; then
    kube -n sts-demo wait --for=delete configmap/sts-smoke-client --timeout=60s
  fi
  kube apply -f config/local/sample.yaml
  kube -n sts-demo wait --for=jsonpath='{.status.observedGeneration}'=1 \
    stsclient/smoke-client --timeout=60s
  kube -n sts-demo get configmap sts-smoke-client -o json > "$work/configmap.json"
  jq -e '.data.STS_CLIENT_ID == "sts-operator-dev:sts-demo:smoke-client" and
    any(.metadata.ownerReferences[]; .kind == "STSClient" and .name == "smoke-client" and .controller == true)' \
    "$work/configmap.json" > /dev/null
  kube get --raw '/api/v1/namespaces/sts-operator-dev/services/mock-sts:8080/proxy/registrations' \
    > "$work/registrations.json"
  jq -e 'has("sts-operator-dev:sts-demo:smoke-client")' "$work/registrations.json" > /dev/null
  kube -n sts-demo get stsclient smoke-client
  kube -n sts-demo get configmap sts-smoke-client
  echo 'Smoke test passed. Sample left in namespace sts-demo for inspection.'
}

case "${1:-}" in
  start) up; deploy; smoke ;;
  up) up ;;
  deploy) deploy ;;
  smoke) smoke ;;
  logs) load_kubeconfig; kube -n "$NAMESPACE" logs -f deployment/sts-operator --all-containers=true ;;
  down)
    echo "Deleting development cluster $CLUSTER and all resources/data inside it."
    k3d cluster delete "$CLUSTER"
    ;;
  *) echo "Usage: ${0##*/} {start|up|deploy|smoke|logs|down}" >&2; exit 2 ;;
esac
