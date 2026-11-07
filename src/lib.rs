//! mu-registry - Pluggable Artifact & Package Registry

pub mod api;
pub mod auth;
pub mod config;
pub mod frontend;
pub mod storage;
pub mod telemetry;

pub use api::build_app_router;
pub use api::canary::AppState;
pub use auth::{
    authenticate_request, build_tls_server_config, extract_cert_sans, hash_token_argon2,
    hash_token_sha256, AuthContext, AuthError, ClientIdentity,
};
pub use config::AppConfig;
pub use frontend::cargo::{cargo_index_relative_path, encode_publish_frame, CargoSparseFrontend};
pub use frontend::{Maven2Frontend, NuGetV3Frontend, RegistryFrontend};
pub use storage::{
    list_public_packages, sanitize_node_alias, sanitize_public_text, validate_w3c_trace_id,
    ApiTokenRecord, CanaryBundleRecord, CanaryStatusSummary, CasStorage, CasStorageHealthSummary,
    CasStorageSummary, CasStore, Catalog, CatalogError, CatalogOverviewCounts, CrateDepRecord,
    CrateRecord, CrateVersionRecord, DuckDbCatalog, PublicCrateDetail, PublicCrateVersionDetail,
    PublicPackageSummary, RegistrySseEvent, Sha256Digest, StorageError, TaintRecord,
    TaintedDigestRecord, TokenScope,
};
pub use telemetry::{
    classify_registry_operation, registry_telemetry_middleware, MuObserveRegistrySink,
    RecordingRegistryTelemetrySink, RegistryTelemetrySink, REGISTRY_SERVICE_NAME,
};
