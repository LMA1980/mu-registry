---
name: mu-registry
description: "Develop and interact with the mu-registry Content-Addressed Storage (CAS) artifact registry, DuckDB catalog, Cargo Sparse HTTP registry, and canary release APIs."
---

# `mu-registry` Artifact & Package Registry Invariants

## 1. Content-Addressed Storage (CAS) & SHA-256 Verification

- All published artifacts, crate tarballs, and integration-test bundles are indexed in DuckDB and stored by verified SHA-256 digest in CAS.
- Before promoting a release from canary to production, verify that its digest is untainted and its pre-release license gate (`LGPL-3.0-only WITH LGPL-3.0-linking-exception` for libraries/IPC/traits vs. `AGPL-3.0-only` for daemons/controllers/web) is satisfied.
