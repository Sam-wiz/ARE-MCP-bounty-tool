# Local Kubernetes operation

Run the existing ARE finding workflow on a local kind cluster backed by Docker
Desktop. No cloud account, paid infrastructure, Terraform, LLM key, or live security
target is needed for this demonstration. Docker Compose is an optional development
path; the required Kubernetes runtime is provided by kind.

## Prerequisites

Use Docker Desktop with its engine running, `kubectl`, Python 3, Bash, and kind
v0.31.0. Go 1.26.9 is used for local validation and the image build. Allocate roughly
4 CPUs and 6 GiB RAM to Docker, and keep at least 12 GiB of host disk free
for image layers, Go toolchains and compilation caches. These are starting estimates,
not a measured minimum. The first build downloads container images and Go dependencies.

This workspace has kind at `.tools/kind`. On another machine, install the pinned
version using `go install sigs.k8s.io/kind@v0.31.0` and put Go's binary directory on
PATH. `.tools`, local credentials, cluster credentials and generated evidence are
ignored by Git. Do not check in `.env.local` or `artifacts/kubeconfig`.

## Start and demonstrate

From the repository root:

```sh
make local-up
make local-demo
make dashboards
```

`local-up` generates random credentials once, hashes source files, builds a tagged
image, creates the `are-mcp` kind cluster, loads the image, applies Kustomize
configuration and waits for workloads. It reuses the cluster and credentials on
subsequent runs. It uses `artifacts/kubeconfig`, leaving your default Kubernetes
context alone. The cluster context is explicitly `kind-are-mcp`; the namespace is
`are-mcp`.

`local-demo` performs an unauthenticated rejection, initialization, program setup,
scope validation, synthetic finding ingestion, readback, and report generation.
The example domain is never contacted. Results include the running build revision,
finding ID, trace IDs and timings in `artifacts/smoke.json`. All calls are serialized
for a single operator.

Keep `make dashboards` running in a terminal to forward these loopback ports:

| Address | Purpose |
| --- | --- |
| http://localhost:8080/version | Running version and source revision |
| http://localhost:8080/healthz | Process liveness |
| http://localhost:8080/readyz | Live MongoDB and Redis checks |
| http://localhost:3000 | Grafana; username `admin`, `GRAFANA_PASSWORD` from `.env.local` |
| http://localhost:9090 | Prometheus query and alert pages |
| http://localhost:16686 | Jaeger; select service `are-mcp` |

Grafana provisions the **ARE MCP Operations** dashboard and Prometheus/Jaeger data
sources. Use a trace ID from `artifacts/smoke.json` in Jaeger to connect a request to
its dependency checks. Structured application logs contain the same trace ID.
Credentials remain in `.env.local`; the scripts do not print them.

## Application interfaces

The existing stdio MCP server remains the default for a native binary. Cloud mode
sets `SERVER_TRANSPORT=http` and exposes `POST /rpc`, an authenticated JSON-RPC
workflow gateway. It is **not** an implementation of MCP Streamable HTTP; use the
original stdio interface for a normal MCP client.

The gateway allows `set_program`, `list_programs`, `program_stats`, `set_target`,
`validate_scope`, `ingest_result`, `get_findings`, and `generate_report`. It does not
install or expose external scanners or arbitrary script execution. The original
stdio tool interface remains available for the original application use case.
LLM review is outside this deterministic infrastructure demo.

The API requires `Authorization: Bearer <API_TOKEN>`. Token length is checked at
startup. Browser-origin requests are rejected. The gateway limits JSON bodies to
1 MiB, refuses concurrent operations with HTTP 429, and checks dependencies before
executing requests. The HTTP listener defaults to loopback for native execution;
container configuration binds inside the private pod network.

## Inspect runtime

```sh
export KUBECONFIG="$PWD/artifacts/kubeconfig"
kubectl --context kind-are-mcp -n are-mcp get pods,svc,pvc
kubectl --context kind-are-mcp -n are-mcp logs deployment/are-mcp --tail=100
kubectl --context kind-are-mcp -n are-mcp describe pod -l app=are-mcp
kubectl --context kind-are-mcp -n are-mcp get events --sort-by=.lastTimestamp
```

When the app is unready, inspect database readiness, secret references and logs.
Do not restart a healthy app just because a dependency is down. Liveness only
checks the application process; readiness checks dependencies with a deadline.
Startup failures exit instead of silently dropping persistence in HTTP mode.

## Recovery and release verification

```sh
make verify-recovery
```

This test scales Redis to zero, checks readiness becomes 503 while liveness remains
200, restores Redis, replaces the application pod, verifies a finding survives, then
introduces a nonexistent image and restores the exact previous image. A `finally`
block restores Redis and the image even when a check fails. Run this only in the
project's disposable local cluster. It intentionally causes brief downtime.

A release uses a single replica with `Recreate`: the application keeps an active
program/session in memory and does not support independent concurrent operators.
Replacement prevents old and new processes writing the same workspace at once.
This trades availability during releases for predictable state ownership. Re-select
the program after restart; findings and reports are read from MongoDB. Workspaces,
MongoDB and Redis use PVCs. These survive pod replacement, not cluster deletion.

For manual image rollback, select a recorded known-good image from
`artifacts/pod-identities.json` or `kubectl rollout history`, then:

```sh
kubectl --context kind-are-mcp -n are-mcp set image deployment/are-mcp app=are-mcp:KNOWN_GOOD_TAG
kubectl --context kind-are-mcp -n are-mcp rollout status deployment/are-mcp --timeout=180s
make local-demo
```

Change the desired source and rerun `make local-up` after an emergency rollback so
configuration and runtime agree. Image rollback does not undo database changes.
This release introduces no destructive schema migration.

## Reliability targets and signals

For a local demo session, target at least 99% successful authenticated workflow
requests, p95 latency under two seconds after initial workspace creation, and
recovery within two minutes after a dependency is restored. These are proposed
operating targets, not claims of long-term measured availability. Single-node
Kubernetes cannot provide high availability.

- `are_rpc_requests_total`: outcomes distinguish successful calls, tool errors,
  dependency failures, authentication rejections and busy responses.
- `are_rpc_duration_seconds`: request latency histogram. Initial workspace creation
  is a separate warm-up event; the container skips unnecessary Python venv setup.
- `are_build_info`: running version and revision.
- Go/process collectors: memory and runtime behavior.
- Prometheus alerts: unavailable application, sustained error rate above 5%, and
  p95 latency above two seconds. Rules appear in Prometheus; no external notification
  receiver is configured.
- OpenTelemetry traces: incoming request, tool dispatch and MongoDB/Redis checks.
  No credentials, target URLs, finding bodies or tool arguments are put in spans.
- JSON logs: method, result, duration and trace ID. Use `kubectl logs` for the
  operational log store; no centralized log retention service is included.

Prometheus and Grafana storage is ephemeral and Jaeger stores at most 10,000 traces
in memory. Export evidence before replacing these pods. Persistent telemetry and a
backup policy would be needed for a long-running service.

## Delivery and security

The CI workflow checks source with `go vet`, race tests, builds and `govulncheck`,
then builds/deploys an ephemeral kind cluster and executes the workflow and recovery
tests. Selected evidence files are uploaded; cluster credentials and secret files
are not. PR jobs have read-only repository permissions and receive no deployment
credentials. CI creates disposable infrastructure on the runner.

The separate manual release workflow rechecks source and publishes an image to
GHCR tagged with the exact Git commit, with provenance and an SBOM. Publishing
requires an explicit workflow dispatch. The `release` environment can have required
reviewers configured in GitHub; the YAML alone does not enable approval rules.
Local deployment is an explicit `make local-up` operation. No repository push or
workflow run is implied by having these files locally.

Application pods run as UID 10001 with a read-only root filesystem, dropped Linux
capabilities, no privilege escalation, RuntimeDefault seccomp, and no service
account token. The namespace enforces restricted Pod Security. Dependency and
monitoring pods also run without root or Kubernetes API credentials. Services are
ClusterIP; access uses localhost port forwarding. MongoDB has an application user
with access only to `hack_ai_v2`; Redis and the API have separate random credentials.

The local setup has no TLS ingress, tenant isolation, egress firewall, external
secret manager, database replica set, HPA or automatic backup. kind's default
networking is not claimed to enforce NetworkPolicy. Do not expose this operator
service publicly without adding TLS, identity/authorization, network isolation,
stronger execution isolation, and a durable data protection plan.

## Optional Compose development

```sh
make compose-up
python3 scripts/smoke.py
```

This starts the app, MongoDB, Redis and Jaeger with persistent Docker volumes and
loopback access. It is useful for development but does not satisfy the Kubernetes
requirement. It uses the same synthetic workflow and credentials. Do not run Compose
and `make dashboards` on the same host ports simultaneously.

## Stop and data lifecycle

Stop port forwarding with Ctrl-C; this leaves the cluster running. To remove the
disposable cluster deliberately, use `kind delete cluster --name are-mcp`. That
removes its PVC data. Docker Compose uses `docker compose --env-file .env.local
down`; adding `--volumes` also deletes its databases. Retain the local credential
file while reusing volumes; generating new passwords does not rotate existing
MongoDB users automatically.

## References

The implementation follows the official [kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/),
[Kubernetes probe guidance](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/),
and [OpenTelemetry Go exporter guidance](https://opentelemetry.io/docs/languages/go/exporters/).
