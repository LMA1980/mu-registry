use std::path::PathBuf;
use std::sync::Arc;

use crate::telemetry::{MuObserveRegistrySink, RegistryTelemetrySink};

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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("/var/lib/muregist"),
            base_url: "https://registry.ci.ci.internal:8444".to_string(),
            tls_ca_path: PathBuf::from("/etc/muregist/tls/ca.crt"),
            tls_cert_path: PathBuf::from("/etc/muregist/tls/server.crt"),
            tls_key_path: PathBuf::from("/etc/muregist/tls/server.key"),
            listen_addr: "0.0.0.0:8444".to_string(),
            node_id: "node-a".to_string(),
            require_tls: false,
            trust_proxy_san_header: false,
            telemetry_sink: Arc::new(MuObserveRegistrySink::from_env()),
        }
    }
}

/// Parses a boolean environment flag (`1`, `true`, `yes`, case-insensitive).
pub(crate) fn parse_env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
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
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("MUREGIST_ROOT_DIR") {
            cfg.root_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_BASE_URL") {
            cfg.base_url = val;
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_CA") {
            cfg.tls_ca_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_CERT") {
            cfg.tls_cert_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_KEY") {
            cfg.tls_key_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_LISTEN_ADDR") {
            cfg.listen_addr = val;
        }
        cfg.require_tls = parse_env_bool("MUREGIST_REQUIRE_TLS");
        cfg.trust_proxy_san_header = parse_env_bool("MUREGIST_TRUST_PROXY_SAN_HEADER");
        cfg
    }
}
