# Viva rehearsal

Run commands from the repository root. Use synthetic records only. Read
[ARCHITECTURE.md](ARCHITECTURE.md) for the decisions and
[OPERATIONS.md](OPERATIONS.md) for setup and troubleshooting.

1. **Explain the workload.** The existing Go application organizes programs,
   findings and reports. The cloud gateway exposes a small authenticated workflow.
   It is a single-operator application, so one replica is deliberate.
2. **Show the release.** Run `make local-up`, then `make source-identity`.
   Explain: source checks → container image → kind image load → Kustomize apply →
   rollout. The image tag includes HEAD and a source hash; `/version` reports the
   running build. GitHub CI runs the same deployment checks on a disposable runner.
3. **Show Kubernetes.** Run
   `kubectl --kubeconfig artifacts/kubeconfig --context kind-are-mcp -n are-mcp get pods,svc,pvc`.
   Explain the app Deployment, database StatefulSets, persistent data and internal
   Services. Recreate avoids two active in-memory operator sessions but causes downtime.
4. **Trace a request.** Run `make local-demo`. It checks authentication, selects
   `cloud-demo`, sets a synthetic target, ingests a finding, reads it from MongoDB
   and generates a report. No target scanning occurs. Open `artifacts/smoke.json`.
   Explain that Redis is checked for readiness but this workflow does not enqueue scans.
5. **Show observability.** Run `make verify-observability`, then `make dashboards`
   in a separate terminal. Open Grafana at localhost:3000, Prometheus at :9090 and
   Jaeger at :16686. Use the locally generated Grafana credentials; do not display
   secrets during screen sharing. Find the ingestion trace ID from the smoke evidence.
   Metrics show aggregate behavior; logs describe events; traces connect request steps.
6. **Explain and demonstrate recovery.** Run `make verify-recovery`. Redis outage
   produces readiness 503 while liveness stays 200. Restoring Redis restores readiness.
   App replacement preserves a stored finding. A nonexistent image prevents startup;
   restoring the exact prior image recovers the release. Read `artifacts/recovery.json`.
   These are observed timings, not an availability guarantee. Run `make local-demo`
   again after the drill to select the active program for your demonstration.
7. **Explain changes under new requirements.** Multiple users need explicit session
   ownership, per-user authorization and isolated workspaces before adding replicas.
   Production needs TLS, backup/restore tests, persistent telemetry, stronger network
   isolation and database availability. PVCs survive pod replacement, not deletion
   of the local cluster. Rollback changes code, not database history.

Navigate implementation: `cmd/server/main.go` → `internal/mcp/http.go` →
`internal/core/` → `internal/storage/mongo.go`. Then show `deploy/base/`,
`deploy/monitoring/`, `.github/workflows/ci.yaml` and `release.yaml`.
Publication is manual; environment approval rules require repository configuration.
Do not claim a hosted pipeline passed until its GitHub run has actually passed.

This walkthrough supports understanding, not memorization. Explain the observed
behavior in your own words. The assistance disclosure is in [BASELINE.md](BASELINE.md).
