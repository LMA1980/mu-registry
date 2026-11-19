use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::telemetry::{MuObserveRegistrySink, RegistryTelemetrySink};

/// Canonical CAS and DuckDB catalog root directory for `mu-registry`.
pub const DEFAULT_REGISTRY_ROOT_DIR: &str = "/var/lib/mu-registry";

/// Legacy CAS and DuckDB catalog root directory retained as an on-disk fallback.
pub const LEGACY_REGISTRY_ROOT_DIR: &str = "/var/lib/muregist";

/// Canonical TLS CA bundle path for `mu-registry`.
pub const DEFAULT_REGISTRY_TLS_CA: &str = "/etc/mu-registry/tls/ca.crt";
/// Legacy TLS CA bundle path retained as an on-disk fallback.
pub const LEGACY_REGISTRY_TLS_CA: &str = "/etc/muregist/tls/ca.crt";

/// Canonical TLS server certificate path for `mu-registry`.
pub const DEFAULT_REGISTRY_TLS_CERT: &str = "/etc/mu-registry/tls/server.crt";
/// Legacy TLS server certificate path retained as an on-disk fallback.
pub const LEGACY_REGISTRY_TLS_CERT: &str = "/etc/muregist/tls/server.crt";

/// Canonical TLS server private key path for `mu-registry`.
pub const DEFAULT_REGISTRY_TLS_KEY: &str = "/etc/mu-registry/tls/server.key";
/// Legacy TLS server private key path retained as an on-disk fallback.
pub const LEGACY_REGISTRY_TLS_KEY: &str = "/etc/muregist/tls/server.key";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub root_dir: PathBuf,
    pub base_url: String,
    pub tls_ca_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub listen_addr: String,
    pub node_id: String,
    pub require_tls: bool,
    pub trust_proxy_san_header: bool,
    pub telemetry_sink: Arc<dyn RegistryTelemetrySink>,
}

/// Resolves `canonical` unless `canonical` does not exist on disk and `legacy` does.
pub(crate) fn resolve_preferred_path(
    canonical: impl AsRef<Path>,
    legacy: impl AsRef<Path>,
) -> PathBuf {
    let canonical = canonical.as_ref();
    if canonical.exists() {
        return canonical.to_path_buf();
    }
    let legacy = legacy.as_ref();
    if legacy.exists() {
        return legacy.to_path_buf();
    }
    canonical.to_path_buf()
}

/// Resolves the default storage root directory (`/var/lib/mu-registry` with on-disk fallback
/// to `/var/lib/muregist` if only the legacy directory exists).
#[must_use]
pub fn default_root_dir() -> PathBuf {
    resolve_preferred_path(DEFAULT_REGISTRY_ROOT_DIR, LEGACY_REGISTRY_ROOT_DIR)
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root_dir: default_root_dir(),
            base_url: "https://registry.ci.ci.internal:8444".to_string(),
            tls_ca_path: resolve_preferred_path(DEFAULT_REGISTRY_TLS_CA, LEGACY_REGISTRY_TLS_CA),
            tls_cert_path: resolve_preferred_path(
                DEFAULT_REGISTRY_TLS_CERT,
                LEGACY_REGISTRY_TLS_CERT,
            ),
            tls_key_path: resolve_preferred_path(DEFAULT_REGISTRY_TLS_KEY, LEGACY_REGISTRY_TLS_KEY),
            listen_addr: "0.0.0.0:8444".to_string(),
            node_id: "node-a".to_string(),
            require_tls: false,
            trust_proxy_san_header: false,
            telemetry_sink: Arc::new(MuObserveRegistrySink::from_env()),
        }
    }
}

/// Returns the first non-empty trimmed environment variable value matching `keys` in order.
pub(crate) fn env_var_first_with<F>(keys: &[&str], mut lookup: F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    for key in keys {
        if let Some(raw) = lookup(key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Returns the first non-empty trimmed process environment variable matching `keys` in order.
pub(crate) fn env_var_first(keys: &[&str]) -> Option<String> {
    env_var_first_with(keys, |k| std::env::var(k).ok())
}

/// Parses a boolean string flag (`1`, `true`, `yes`, case-insensitive).
fn parse_bool_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Parses the first non-empty boolean flag matching `keys` using `lookup`.
pub(crate) fn parse_env_bool_first_with<F>(keys: &[&str], lookup: F) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    env_var_first_with(keys, lookup).is_some_and(|v| parse_bool_flag(&v))
}

/// Parses the first non-empty boolean environment flag matching `keys` in precedence order.
pub(crate) fn parse_env_bool_first(keys: &[&str]) -> bool {
    parse_env_bool_first_with(keys, |k| std::env::var(k).ok())
}

impl AppConfig {
    pub fn new(root_dir: impl Into<PathBuf>, base_url: impl Into<String>) -> Self {
        let root = root_dir.into();
        Self {
            root_dir: root,
            base_url: base_url.into(),
            ..Default::default()
        }
    }

    /// Attaches a custom [`RegistryTelemetrySink`] for OpenTelemetry span and audit log emission.
    #[must_use]
    pub fn with_telemetry_sink(mut self, sink: Arc<dyn RegistryTelemetrySink>) -> Self {
        self.telemetry_sink = sink;
        self
    }

    /// Sets the logical node identifier emitted on OpenTelemetry records.
    #[must_use]
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }

    /// Overrides the TLS CA, server certificate, and server private key paths.
    #[must_use]
    pub fn with_tls_paths(
        mut self,
        ca_path: impl Into<PathBuf>,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        self.tls_ca_path = ca_path.into();
        self.tls_cert_path = cert_path.into();
        self.tls_key_path = key_path.into();
        self
    }

    /// Configures whether missing TLS artifacts must fail startup instead of falling back to plain TCP.
    #[must_use]
    pub fn with_require_tls(mut self, require_tls: bool) -> Self {
        self.require_tls = require_tls;
        self
    }

    /// Configures whether the `x-client-cert-san` proxy header fallback is trusted.
    #[must_use]
    pub fn with_trust_proxy_san_header(mut self, trust_proxy_san_header: bool) -> Self {
        self.trust_proxy_san_header = trust_proxy_san_header;
        self
    }

    pub fn catalog_path(&self) -> PathBuf {
        self.root_dir.join("catalog.duckdb")
    }

    pub fn cargo_index_dir(&self) -> PathBuf {
        self.root_dir.join("index").join("cargo")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root_dir.join("blobs").join("sha256")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root_dir.join("tmp")
    }

    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Resolves [`AppConfig`] from a custom environment lookup closure, preferring `MU_REGISTRY_*`
    /// variables before falling back to legacy `MUREGIST_*` variables.
    pub fn from_env_with<F>(mut lookup: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut cfg = Self {
            telemetry_sink: Arc::new(MuObserveRegistrySink::from_env_with(&mut lookup)),
            ..Self::default()
        };
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_ROOT_DIR", "MUREGIST_ROOT_DIR"], &mut lookup)
        {
            cfg.root_dir = PathBuf::from(val);
        }
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_BASE_URL", "MUREGIST_BASE_URL"], &mut lookup)
        {
            cfg.base_url = val;
        }
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_TLS_CA", "MUREGIST_TLS_CA"], &mut lookup)
        {
            cfg.tls_ca_path = PathBuf::from(val);
        }
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_TLS_CERT", "MUREGIST_TLS_CERT"], &mut lookup)
        {
            cfg.tls_cert_path = PathBuf::from(val);
        }
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_TLS_KEY", "MUREGIST_TLS_KEY"], &mut lookup)
        {
            cfg.tls_key_path = PathBuf::from(val);
        }
        if let Some(val) = env_var_first_with(
            &["MU_REGISTRY_LISTEN_ADDR", "MUREGIST_LISTEN_ADDR"],
            &mut lookup,
        ) {
            cfg.listen_addr = val;
        }
        if let Some(val) =
            env_var_first_with(&["MU_REGISTRY_NODE_ID", "MUREGIST_NODE_ID"], &mut lookup)
        {
            cfg.node_id = val;
        }
        cfg.require_tls = parse_env_bool_first_with(
            &["MU_REGISTRY_REQUIRE_TLS", "MUREGIST_REQUIRE_TLS"],
            &mut lookup,
        );
        cfg.trust_proxy_san_header = parse_env_bool_first_with(
            &[
                "MU_REGISTRY_TRUST_PROXY_SAN_HEADER",
                "MUREGIST_TRUST_PROXY_SAN_HEADER",
            ],
            &mut lookup,
        );
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn test_default_paths_prefer_mu_registry() {
        let cfg = AppConfig::default();
        if !Path::new(LEGACY_REGISTRY_ROOT_DIR).exists()
            || Path::new(DEFAULT_REGISTRY_ROOT_DIR).exists()
        {
            assert_eq!(cfg.root_dir, PathBuf::from(DEFAULT_REGISTRY_ROOT_DIR));
        }
        if !Path::new(LEGACY_REGISTRY_TLS_CA).exists()
            || Path::new(DEFAULT_REGISTRY_TLS_CA).exists()
        {
            assert_eq!(cfg.tls_ca_path, PathBuf::from(DEFAULT_REGISTRY_TLS_CA));
        }
        if !Path::new(LEGACY_REGISTRY_TLS_CERT).exists()
            || Path::new(DEFAULT_REGISTRY_TLS_CERT).exists()
        {
            assert_eq!(cfg.tls_cert_path, PathBuf::from(DEFAULT_REGISTRY_TLS_CERT));
        }
        if !Path::new(LEGACY_REGISTRY_TLS_KEY).exists()
            || Path::new(DEFAULT_REGISTRY_TLS_KEY).exists()
        {
            assert_eq!(cfg.tls_key_path, PathBuf::from(DEFAULT_REGISTRY_TLS_KEY));
        }
    }

    #[test]
    fn test_resolve_preferred_path_on_disk_fallback() {
        let tmp = tempdir().expect("tempdir");
        let canonical = tmp.path().join("mu-registry");
        let legacy = tmp.path().join("muregist");

        // Neither exists -> canonical
        assert_eq!(resolve_preferred_path(&canonical, &legacy), canonical);

        // Only legacy exists -> legacy
        std::fs::create_dir_all(&legacy).unwrap();
        assert_eq!(resolve_preferred_path(&canonical, &legacy), legacy);

        // Both exist -> canonical wins
        std::fs::create_dir_all(&canonical).unwrap();
        assert_eq!(resolve_preferred_path(&canonical, &legacy), canonical);
    }

    #[test]
    fn test_mu_registry_env_precedence_and_muregist_fallback() {
        let legacy_only: HashMap<&str, &str> = HashMap::from([
            ("MUREGIST_ROOT_DIR", "/legacy/root"),
            ("MUREGIST_BASE_URL", "https://legacy.cluster.internal:8444"),
            ("MUREGIST_TLS_CA", "/legacy/ca.crt"),
            ("MUREGIST_TLS_CERT", "/legacy/server.crt"),
            ("MUREGIST_TLS_KEY", "/legacy/server.key"),
            ("MUREGIST_LISTEN_ADDR", "127.0.0.1:9444"),
            ("MUREGIST_NODE_ID", "legacy-node"),
            ("MUREGIST_REQUIRE_TLS", "true"),
            ("MUREGIST_TRUST_PROXY_SAN_HEADER", "yes"),
        ]);
        let cfg_legacy = AppConfig::from_env_with(|k| legacy_only.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg_legacy.root_dir, PathBuf::from("/legacy/root"));
        assert_eq!(cfg_legacy.base_url, "https://legacy.cluster.internal:8444");
        assert_eq!(cfg_legacy.tls_ca_path, PathBuf::from("/legacy/ca.crt"));
        assert_eq!(
            cfg_legacy.tls_cert_path,
            PathBuf::from("/legacy/server.crt")
        );
        assert_eq!(cfg_legacy.tls_key_path, PathBuf::from("/legacy/server.key"));
        assert_eq!(cfg_legacy.listen_addr, "127.0.0.1:9444");
        assert_eq!(cfg_legacy.node_id, "legacy-node");
        assert!(cfg_legacy.require_tls);
        assert!(cfg_legacy.trust_proxy_san_header);

        let mixed: HashMap<&str, &str> = HashMap::from([
            ("MU_REGISTRY_ROOT_DIR", "/canon/root"),
            ("MUREGIST_ROOT_DIR", "/legacy/root"),
            (
                "MU_REGISTRY_BASE_URL",
                "https://canon.cluster.internal:8444",
            ),
            ("MUREGIST_BASE_URL", "https://legacy.cluster.internal:8444"),
            ("MU_REGISTRY_TLS_CA", "/canon/ca.crt"),
            ("MUREGIST_TLS_CA", "/legacy/ca.crt"),
            ("MU_REGISTRY_TLS_CERT", "/canon/server.crt"),
            ("MUREGIST_TLS_CERT", "/legacy/server.crt"),
            ("MU_REGISTRY_TLS_KEY", "/canon/server.key"),
            ("MUREGIST_TLS_KEY", "/legacy/server.key"),
            ("MU_REGISTRY_LISTEN_ADDR", "0.0.0.0:8444"),
            ("MUREGIST_LISTEN_ADDR", "127.0.0.1:9444"),
            ("MU_REGISTRY_NODE_ID", "node-b"),
            ("MUREGIST_NODE_ID", "legacy-node"),
            ("MU_REGISTRY_REQUIRE_TLS", "false"),
            ("MUREGIST_REQUIRE_TLS", "true"),
            ("MU_REGISTRY_TRUST_PROXY_SAN_HEADER", "false"),
            ("MUREGIST_TRUST_PROXY_SAN_HEADER", "true"),
        ]);
        let cfg_canon = AppConfig::from_env_with(|k| mixed.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg_canon.root_dir, PathBuf::from("/canon/root"));
        assert_eq!(cfg_canon.base_url, "https://canon.cluster.internal:8444");
        assert_eq!(cfg_canon.tls_ca_path, PathBuf::from("/canon/ca.crt"));
        assert_eq!(cfg_canon.tls_cert_path, PathBuf::from("/canon/server.crt"));
        assert_eq!(cfg_canon.tls_key_path, PathBuf::from("/canon/server.key"));
        assert_eq!(cfg_canon.listen_addr, "0.0.0.0:8444");
        assert_eq!(cfg_canon.node_id, "node-b");
        assert!(!cfg_canon.require_tls);
        assert!(!cfg_canon.trust_proxy_san_header);
    }
}
