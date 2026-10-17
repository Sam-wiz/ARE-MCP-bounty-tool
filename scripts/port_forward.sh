#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$PWD/artifacts/kubeconfig}"
mkdir -p artifacts
pids=()
cleanup(){ for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for mapping in 'are-mcp 8080:8080' 'prometheus 9090:9090' 'grafana 3000:3000' 'jaeger 16686:16686'; do
 read -r service ports <<< "$mapping"
 kubectl --context kind-are-mcp -n are-mcp port-forward --address=127.0.0.1 "service/$service" "$ports" >"artifacts/forward-$service.log" 2>&1 &
 pids+=("$!")
done
printf '%s\n' 'API: http://localhost:8080/version' 'Grafana: http://localhost:3000 (admin; password in .env.local)' 'Prometheus: http://localhost:9090' 'Jaeger: http://localhost:16686' 'Keep this terminal open; Ctrl-C stops forwarding.'
while true; do
 for pid in "${pids[@]}"; do
  if ! kill -0 "$pid" 2>/dev/null; then
   echo "A port-forward stopped; inspect artifacts/forward-*.log and restart make dashboards." >&2
   exit 1
  fi
 done
 sleep 2
done
