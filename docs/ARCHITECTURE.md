# Architecture and engineering decisions

ARE MCP retains its Go application and exposes a narrow remote workflow for a local
DevOps demonstration. The infrastructure supports the existing application's data
flow rather than splitting it into artificial microservices.

```text
Operator / smoke script
  -> localhost kubectl port-forward -> ClusterIP service -> Go workflow gateway
       authentication -> serialized request -> active program -> finding/report
                                                   |              |
                                            Redis readiness    MongoDB records
                                                   |              |
                                              Redis PVC       MongoDB PVC

Go process -> /metrics <- Prometheus <- Grafana
Go process -> OTLP HTTP -> Jaeger    <- Grafana / trace search
Go process -> JSON stderr -> kubectl logs
Go workspaces -> workspace PVC
```

The gateway's readiness checks contact both dependency services. Tool dispatch runs
the existing engine; program/finding operations use MongoDB, while Redis remains
available for the original queue integration. The synthetic cloud workflow does not
claim to enqueue a distributed scan. This distinction matters when explaining the
request path.

## Workload and storage choices

The application is a Deployment because pod identity is not meaningful. One replica
and Recreate suit its active in-memory program/session and shared filesystem.
StatefulSets give MongoDB and Redis stable identities and PVC ownership. This is a
single-node local demonstration, not a database high-availability topology. There
is no affinity or multi-zone placement because one node is intentional.

Adding replicas without moving session ownership out of process would be incorrect.
A future service would pass explicit program/session IDs on each request, make writes
idempotent, isolate workspaces, and use a durable worker queue before introducing
horizontal scaling. CPU-based autoscaling alone cannot solve state ownership.

PVCs survive application/database pod recreation. They do not provide backups or
survive deleting the kind cluster. Memory in the application is a cache of the
active workflow; persisted findings are queried from MongoDB for list and report
operations. On restart the operator selects a program again.

## Configuration and release boundaries

Kustomize keeps a common base and a local overlay without extra templating tooling.
Generated ConfigMap names change when configuration changes, updating pod templates.
Credentials are created separately and never rendered into evidence manifests.
Secret changes require a workload restart; initial Mongo user provisioning is not
a password-rotation implementation.

CI automatically checks and deploys disposable local infrastructure on a runner.
Publication is a separate manual workflow. Local image tags combine Git HEAD with
a hash of source contents, so uncommitted changes are not misrepresented as the
baseline commit. Published images use the selected exact commit. A human chooses
when to deploy. Recreate implies brief planned downtime and an error release can
extend it; rollback explicitly restores the known-good image.

## Failure boundaries

| Failure | Expected observation | Response |
| --- | --- | --- |
| Bad token | HTTP 401, unauthorized metric; engine not called | Supply the local operator token |
| Second simultaneous operator request | HTTP 429 | Retry after current operation completes |
| MongoDB/Redis outage | Readiness 503, liveness 200; service has no ready app endpoint | Restore dependency; avoid restart loops |
| Application process crash | Kubernetes restarts container | Inspect logs, reselect program, verify persisted findings |
| Incorrect image tag | ErrImagePull/ImagePullBackOff; no available app | Restore exact previous image and run smoke test |
| Lost kind node/cluster | Application and local volumes unavailable | Recreate from configuration; restore data from an independent backup if one exists |
| Jaeger/Prometheus restart | Telemetry history lost | Preserve evidence; use persistent telemetry storage for longer operation |

Readiness reflects dependency availability, not a promise that every subsequent
write succeeds. Database writes still need error checking. The gateway is
single-operator; tokens are not identities for separate tenants. The process-level
sandbox in the original application is not upgraded into a secure multi-tenant
execution environment by putting the gateway in Kubernetes.

## Viva walkthrough

Trace a change through source checks, image creation, source identity, kind image
loading, Kustomize application, rollout and `/version`. Then trace one synthetic
finding through authentication, scope setup, ingestion, MongoDB readback and report
generation. Show its trace and corresponding log line.

Explain why liveness excludes dependency checks, why HTTP startup fails when data
stores are absent, why the app has one replica, what survives pod restart, what
Recreate costs, and why rollback does not restore database history. The recovery
script provides concrete observations for these tradeoffs.
