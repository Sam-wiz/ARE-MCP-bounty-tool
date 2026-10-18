#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$PWD/artifacts/kubeconfig}"
mkdir -p artifacts
kubectl --context kind-are-mcp -n are-mcp port-forward --address=127.0.0.1 service/are-mcp 18080:8080 >artifacts/demo-forward.log 2>&1 &
forward_pid=$!
trap 'kill "$forward_pid" 2>/dev/null || true' EXIT
export APP_URL=http://127.0.0.1:18080
for attempt in {1..30}; do
 if curl --silent --fail "$APP_URL/readyz" >/dev/null; then break; fi
 sleep 1
done
python3 scripts/smoke.py
kubectl --context kind-are-mcp -n are-mcp get pods -o wide > artifacts/pods.txt
kubectl --context kind-are-mcp -n are-mcp get deployments,statefulsets,services,pvc -o wide > artifacts/runtime.txt
kubectl --context kind-are-mcp -n are-mcp get pods -o json > artifacts/pod-identities.json
kubectl --context kind-are-mcp -n are-mcp logs deployment/are-mcp --tail=100 > artifacts/application.log
curl --silent --fail "$APP_URL/metrics" > artifacts/metrics.txt
