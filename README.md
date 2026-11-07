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

---

Pluggable artifact and package registry with Content-Addressed Storage (CAS), DuckDB metadata catalog, Cargo Sparse HTTP registry front-end, and Canary Release & Integration Test Bundle APIs.

---

## Core Capabilities

- **Pluggable Ecosystem Frontends**:
  - **Cargo Sparse HTTP Index (RFC 2785)**: Fast HTTP index queries (`GET /{prefix}/{crate_name}`) and native `cargo publish` endpoints (`POST /api/v1/crates/new`).
  - **`dotnet` NuGet v3 Feed**: Service index (`/v3/index.json`), package publication, and flat-container layout.
  - **`mvn` Maven Repository**: Maven 2 standard layout (`/{groupId}/{artifactId}/{version}/...`).
- **Content-Addressed Store (CAS)**:
  - Immutable blob storage organized strictly by SHA-256 digest (`blobs/sha256/<prefix>/<digest>`).
  - Constant-time deduplication and integrity verification.
- **DuckDB Metadata Catalog**:
  - Embedded columnar DuckDB store (`catalog.duckdb`) providing indexed metadata queries, dependency graph traversal, and audit logging via parameterized SQL.
- **Canary Release & Integration Test Bundle API**:
  - Ephemeral staging of newly built release candidates (`status: canary`).
  - Staged integration test bundles consumed by `mu-conductor` for canary validation.
  - Automatic promotion to `status: stable` or instant marking as `status: tainted` upon verification failure.
- **Security Fabric**:
  - Mutual TLS (mTLS) backed by two-tier PKI with HA `step-ca`.
  - Scoped bearer tokens (`publish`, `yank`, `read`, `canary:manage`).

---

## Storage & Catalog Layout

```text
/var/lib/mu-registry/
├── blobs/
│   └── sha256/
│       ├── 0a/
│       │   └── 0a1b2c3d4e... (immutable payload)
│       └── ...
├── index/
│   └── cargo/
│       └── 3/c/crate_name (RFC 2785 sparse JSON index)
└── catalog.duckdb (DuckDB metadata, releases, tokens, canary state)
```

---

## Canary & Integration Test Bundle Lifecycle

```text
[ CI Pipeline ] ──> cargo publish ──> [ mu-registry (Status: Canary) ]
                                                │
                                                ▼ Bundle API
                                    [ mu-conductor Verification ]
                                     ├── Success ──> [ Promoted (Status: Stable) ]
                                     └── Failure ──> [ Tainted (Status: Quarantined) ]
```

1. **Ingest**: Release candidate published with `is_canary = true`.
2. **Bundle Dispatch**: `mu-conductor-controller` queries `/api/v1/bundles/it/{id}` to fetch binary artifacts and test suites.
3. **Verdict**: If node canary validation succeeds, `mu-registry` promotes the artifact. If validation fails or times out, the artifact digest is permanently tainted, preventing broader distribution.

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
