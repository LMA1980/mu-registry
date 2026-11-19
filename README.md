# mu-registry

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-registry/card.svg" alt="mu-registry Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-registry/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-registry/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-registry/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-registry/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Pluggable artifact and package registry with Content-Addressed Storage (CAS), DuckDB metadata catalog, Cargo Sparse HTTP registry front-end, and Canary Release & Integration Test Bundle APIs.

______________________________________________________________________

## Core Capabilities

- **Pluggable Ecosystem Frontends (`src/frontend/`)**:
  - **Cargo Sparse HTTP Index (`src/frontend/cargo.rs`)**: Serves `GET /config.json`, `GET /index/{*path}` (with `sha256:` ETag and `If-None-Match` validation), `PUT /api/v1/crates/new`, `GET /api/v1/crates/{crate}/{version}/download`, `DELETE /api/v1/crates/{crate}/{version}/yank`, and `PUT /api/v1/crates/{crate}/{version}/unyank`.
  - **`dotnet` NuGet v3 & `mvn` Maven 2 (`src/frontend/mod.rs`)**: Currently implemented as read-only index stubs (`GET /v3/index.json` service index metadata and `GET /maven2/{*path}` placeholder).
- **Content-Addressed Store (CAS)**:
  - Immutable blob storage organized strictly by SHA-256 digest (`blobs/sha256/<prefix>/<digest>`).
  - Constant-time deduplication and integrity verification.
- **DuckDB Metadata Catalog**:
  - Embedded columnar DuckDB store (`catalog.duckdb`) providing indexed metadata queries, dependency graph traversal, API token storage, and canary/taint state via parameterized SQL.
- **Canary Release & Integration Test Bundle API (`src/api/canary.rs`)**:
  - Stages integration test bundles (`POST /api/v1/bundles/it`, `GET /api/v1/bundles/it/{id}`) consumed by [`mu-cd`](https://github.com/LMA1980/mu-cd) ([`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) and [`mu-cd-agent`](https://github.com/LMA1980/mu-cd-agent)).
  - Promotes validated digests (`POST /api/v1/canary/{digest}/promote`) or quarantines failing digests (`POST /api/v1/canary/{digest}/taint`), and exposes `GET /api/v1/canary/status` (polled by [`mu-ci-web`](https://github.com/LMA1980/mu-ci-web)).
- **Read-Only Registry & Console API (`src/api/mod.rs`)**:
  - Exposes `/api/v1/registry/*` (`/api/v1/registry/crates`, `/api/v1/registry/crates/{name}`, `/api/v1/registry/bundles`, `/api/v1/registry/taints`, `/api/v1/registry/overview`, `/api/v1/registry/events` SSE) and `/api/v1/console/*` (`/api/v1/console/packages`, `/api/v1/console/canaries`, `/api/v1/console/cas`, plus `/api/v1/packages`, `/api/v1/canaries`, `/api/v1/cas/status`) consumed by [`mu-console`](https://github.com/LMA1980/mu-console).
- **Security & Observability Fabric**:
  - Mutual TLS (`rustls`) backed by `step-ca` PKI SAN extraction (`X-Client-Cert-SAN`), alongside SHA-256 and Argon2id scoped bearer tokens (`publish`, `yank`, `read`, `canary:manage`).
  - W3C `traceparent` middleware emitting `MUOB`-framed OpenTelemetry spans and audit log batches via [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc).

______________________________________________________________________

## Storage & Catalog Layout

Default storage root `/var/lib/mu-registry` (override via `MU_REGISTRY_ROOT_DIR`, with legacy fallback to `/var/lib/muregist` and `MUREGIST_ROOT_DIR` when upgrading existing deployments):

```text
/var/lib/mu-registry/
├── blobs/
│   └── sha256/
│       ├── 0a/
│       │   └── 0a1b2c3d4e... (immutable payload)
│       └── ...
├── index/
│   └── cargo/
│       └── 3/c/crate_name (Cargo sparse JSON index)
├── tmp/
│   └── ... (atomic index staging files)
└── catalog.duckdb (DuckDB metadata, releases, tokens, canary state)
```

Systemd deployment templates (`deploy/mu-registry.service` and `deploy/mu-registry.env.example`) configure the `mu-registry` service user, `/etc/mu-registry/registry.env`, and `/var/lib/mu-registry`.

______________________________________________________________________

## Canary & Integration Test Bundle Lifecycle

```text
[ mu-ci Pipeline ] ──> PUT /api/v1/crates/new ──> [ mu-registry (CAS + Index) ]
                                                         │
                                                         ▼ POST /api/v1/bundles/it
                                             [ mu-cd Canary Verification ]
                                              ├── Success ──> [ Promoted (healthy) ]
                                              └── Failure ──> [ Tainted (Quarantined) ]
```

1. **Ingest**: CI stages publish crates via `CargoDeployAdapter` in [`mu-ci-tools`](https://github.com/LMA1980/mu-ci-tools) (orchestrated by [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller)) and stage canary integration test bundles (`status: testing`) via `POST /api/v1/bundles/it`.
1. **Bundle Dispatch**: [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) and [`mu-cd-agent`](https://github.com/LMA1980/mu-cd-agent) query `GET /api/v1/bundles/it/{id}` (`?download=binary` / `?download=archive`) to fetch binary artifacts and test suites.
1. **Verdict & Status**: On passing validation, `POST /api/v1/canary/{digest}/promote` marks the bundle `healthy`; on failure or timeout, `POST /api/v1/canary/{digest}/taint` permanently taints the digest (`cannot_promote_tainted` on future promotion attempts). Overall canary health is exposed on `GET /api/v1/canary/status` for [`mu-ci-web`](https://github.com/LMA1980/mu-ci-web) and [`mu-console`](https://github.com/LMA1980/mu-console).

______________________________________________________________________

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
