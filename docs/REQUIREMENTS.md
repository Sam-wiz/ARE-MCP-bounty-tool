# Project requirements and review map

Student: Samrudh, 23bcs10123. Project: ARE MCP Bounty Tool.
The supplied guide accepts local kind/Minikube and makes cloud hosting and Terraform
optional. The technical additions below use local Kubernetes.

| Required area | Implementation | Verification |
| --- | --- | --- |
| Architecture and operation | Existing Go engine; authenticated single-operator gateway; MongoDB storage; Redis dependency | `docs/ARCHITECTURE.md`, synthetic workflow and dependency fault test |
| Kubernetes | Deployment, StatefulSets, ClusterIP Services, three probe types, resource requests/limits, PVCs, restricted security contexts | `deploy/`, `make local-up`, workload status and pod identities |
| Deployment configuration | Shared Kustomize base and local overlay; generated ConfigMaps; separately injected Secrets | `kubectl kustomize deploy/local`, repeat deployment |
| CI and CD | Vet, race tests, build, vulnerability check, ephemeral kind deployment and smoke/recovery checks; manual image publication | `.github/workflows/ci.yaml`, `.github/workflows/release.yaml` |
| Release control | Source-hash local image; commit-tagged published image; one replica/Recreate; explicit rollback | `/version`, `are_build_info`, bad-image recovery drill |
| Observability and reliability | Prometheus, Grafana dashboard, alerts, JSON logs, OpenTelemetry/Jaeger | Metrics, trace IDs, recovery timings, `scripts/verify_observability.py` |
| Security | Random ignored credentials, scoped Mongo user, API authentication, restricted tool allowlist, non-root pods, no service account tokens, vulnerability scan | Gateway tests, runtime security configuration, unauthorized smoke request |
| Evidence | Version-bound workflow result, deployed image IDs, pod/PVC state, metrics, logs, failure/recovery result | Generated `artifacts/` files; do not include cluster credentials |
| Submission reviewability | Preserved baseline and runbook, one PR requested by course | Baseline recorded; focused local commits; PR publication awaits owner approval |

## Submission details still requiring owner action

- Repository: https://github.com/Sam-wiz/ARE-MCP-bounty-tool
- Baseline: `8f65f098932831c4bf8429e5385446164f57d1be`
- One PR: publication pending owner approval.
- Final commit: obtain with `git rev-parse HEAD` after the local commits. Local builds include the commit and a source snapshot hash.
- GitHub pipeline run: verify the PR checks; local evidence is separately recorded.
- Reviewer access: confirm access to the existing repository when submitting.
- Academic rule: the guide prohibits AI assistance; these changes are AI-assisted.

Use actual generated evidence, not this implementation map, as proof of execution.
A missing or failing evidence file is not a pass. The source snapshot and `/version`
must agree with the version you demonstrate. Do not describe an unpushed local check
as a successful hosted GitHub Actions run.
