#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools:$PATH"
export KUBECONFIG="${KUBECONFIG:-$PWD/artifacts/kubeconfig}"
export KUBE_CONTEXT=kind-are-mcp
mkdir -p artifacts
for tool in docker kind kubectl python3; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }; done
docker info >/dev/null
python3 scripts/init_local_env.py
python3 scripts/source_identity.py > artifacts/source-identity.json
image_tag=$(python3 -c 'import json; print(json.load(open("artifacts/source-identity.json"))["image_tag"])')
source_hash=$(python3 -c 'import json; print(json.load(open("artifacts/source-identity.json"))["source_sha256"])')
docker build --build-arg "VERSION=$image_tag" --build-arg "REVISION=$source_hash" -t "are-mcp:$image_tag" .
if ! kind get clusters | grep -qx are-mcp; then
  kind create cluster --name are-mcp --config deploy/kind.yaml --kubeconfig "$KUBECONFIG" --wait 120s
else
  kind export kubeconfig --name are-mcp --kubeconfig "$KUBECONFIG"
fi
kind load docker-image "are-mcp:$image_tag" --name are-mcp
kubectl --context "$KUBE_CONTEXT" apply -f deploy/local/namespace.yaml
python3 scripts/local_secrets.py
kubectl kustomize deploy/local > artifacts/rendered.yaml
python3 - "$image_tag" <<'PY'
import sys
from pathlib import Path
p=Path('artifacts/rendered.yaml')
p.write_text(p.read_text().replace('image: are-mcp:local','image: are-mcp:'+sys.argv[1]))
PY
kubectl --context "$KUBE_CONTEXT" apply -f artifacts/rendered.yaml
kubectl --context "$KUBE_CONTEXT" -n are-mcp rollout status statefulset/mongodb --timeout=600s
kubectl --context "$KUBE_CONTEXT" -n are-mcp rollout status statefulset/redis --timeout=300s
for app in are-mcp prometheus grafana jaeger; do
 kubectl --context "$KUBE_CONTEXT" -n are-mcp rollout status "deployment/$app" --timeout=600s
done
printf '%s\n' "Deployed are-mcp:$image_tag. Run make local-demo."
