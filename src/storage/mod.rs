pub mod cas;
pub mod catalog;

pub use cas::{
    CasScrubSnapshot, CasStorage, CasStorageHealthSummary, CasStorageSummary, CasStore,
    Sha256Digest, StorageError,
};
pub use catalog::{
    sanitize_node_alias, sanitize_public_text, validate_w3c_trace_id, ApiTokenRecord,
    CanaryBundleRecord, CanaryStatusSummary, Catalog, CatalogError, CatalogOverviewCounts,
    CrateDepRecord, CrateRecord, CrateVersionRecord, DuckDbCatalog, PublicCrateDetail,
    PublicCrateVersionDetail, PublicPackageSummary, RegistrySseEvent, TaintRecord,
    TaintedDigestRecord, TokenScope,
};

/// Convenience helper delegating to [`DuckDbCatalog::list_public_packages`].
pub fn list_public_packages(
    catalog: &DuckDbCatalog,
    ecosystem_filter: Option<&str>,
) -> Result<Vec<PublicPackageSummary>, CatalogError> {
    catalog.list_public_packages(ecosystem_filter)
}
