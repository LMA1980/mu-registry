use chrono::Utc;
use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("DuckDB error: {0}")]
    DuckDb(#[from] duckdb::Error),

    #[error("Duplicate crate version: {name} v{vers}")]
    DuplicateVersion { name: String, vers: String },

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Lock error: {0}")]
    Lock(String),

    #[error("Unsupported or invalid package ecosystem: {0}")]
    InvalidEcosystem(String),

    #[error("Invalid W3C trace_id: {0}")]
    InvalidTraceId(String),
}

/// Validates a W3C TraceContext `trace-id` (32 lowercase hexadecimal characters, not all zeros).
pub fn validate_w3c_trace_id(trace_id: &str) -> Result<String, CatalogError> {
    let trimmed = trace_id.trim();
    if trimmed.len() != 32 {
        return Err(CatalogError::InvalidTraceId(format!(
            "Expected 32 lowercase hex characters, got length {}",
            trimmed.len()
        )));
    }
    if !trimmed.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(CatalogError::InvalidTraceId(
            "trace_id must contain only lowercase hexadecimal characters (0-9, a-f)".to_string(),
        ));
    }
    if trimmed.chars().all(|c| c == '0') {
        return Err(CatalogError::InvalidTraceId(
            "trace_id must not be all zeros".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn is_private_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let Ok(a) = parts[0].parse::<u8>() else {
        return false;
    };
    let Ok(b) = parts[1].parse::<u8>() else {
        return false;
    };
    if parts[2].parse::<u8>().is_err() || parts[3].parse::<u8>().is_err() {
        return false;
    }
    (a == 192 && b == 168) || a == 10 || (a == 172 && (16..=31).contains(&b))
}

fn replace_word_boundary(haystack: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(idx) = rest.find(needle) {
        let before = &rest[..idx];
        let after = &rest[idx + needle.len()..];
        let prev_ok = before
            .chars()
            .next_back()
            .map(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(true);
        let next_ok = after
            .chars()
            .next()
            .map(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(true);
        out.push_str(before);
        if prev_ok && next_ok {
            out.push_str(replacement);
        } else {
            out.push_str(needle);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Scrubs internal lab hostnames, internal domains, RFC1918 private LAN IPs, and host
/// filesystem paths from public read-only strings.
pub fn sanitize_public_text(input: &str) -> String {
    let mut s = input.to_string();
    let mappings_res =
        std::env::var("MUREGISTRY_NODE_MAP").or_else(|_| std::env::var("MUCONDE_NODE_MAP"));
    if let Ok(mappings) = mappings_res {
        for pair in mappings.split(',') {
            if let Some((k, v)) = pair.split_once('=').or_else(|| pair.split_once(':')) {
                let k_trim = k.trim();
                let v_trim = v.trim();
                if !k_trim.is_empty() && !v_trim.is_empty() {
                    s = replace_word_boundary(&s, k_trim, v_trim);
                }
            }
        }
    }

    for suffix in &[".corp.internal", ".internal", ".local", ".lan"] {
        s = s.replace(suffix, ".example.invalid");
    }
    s = replace_word_boundary(&s, "corp.internal", "example.invalid");
    s = replace_word_boundary(&s, "local", "example.invalid");

    // Scrub private IPv4 literals (192.168.x.y, 10.x.y.z, 172.16-31.x.y)
    let bytes = s.as_bytes();
    let mut ipv4_scrubbed = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut end = i;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                end += 1;
            }
            let trimmed_end = if end > i && bytes[end - 1] == b'.' {
                end - 1
            } else {
                end
            };
            let candidate = &s[i..trimmed_end];
            if is_private_ipv4(candidate) {
                ipv4_scrubbed.push_str("192.0.2.x");
                i = trimmed_end;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        ipv4_scrubbed.push(ch);
        i += ch.len_utf8();
    }

    // Scrub host filesystem paths (/var/..., /etc/..., /tmp/..., /Users/..., /home/...)
    let prefixes = [
        "/var/", "/etc/", "/tmp/", "/Users/", "/home/", "/opt/", "/root/", "/srv/",
    ];
    let mut final_out = String::with_capacity(ipv4_scrubbed.len());
    let mut cursor = 0;
    while cursor < ipv4_scrubbed.len() {
        let tail = &ipv4_scrubbed[cursor..];
        if prefixes.iter().any(|p| tail.starts_with(p)) {
            let end_rel = tail
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, ')' | ']' | '}' | '"' | '\'' | ',' | ';')
                })
                .unwrap_or(tail.len());
            final_out.push_str("<redacted-path>");
            cursor += end_rel;
        } else {
            let ch = tail.chars().next().unwrap();
            final_out.push(ch);
            cursor += ch.len_utf8();
        }
    }

    final_out
}

/// Scrubs a node identifier to its public alias (`node-a`, `node-b`, `worker-riscv64`).
pub fn sanitize_node_alias(node_id: &str) -> String {
    sanitize_public_text(node_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenScope {
    #[serde(rename = "publish")]
    Publish,
    #[serde(rename = "yank")]
    Yank,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "canary:manage")]
    CanaryManage,
}

impl TokenScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenScope::Publish => "publish",
            TokenScope::Yank => "yank",
            TokenScope::Read => "read",
            TokenScope::CanaryManage => "canary:manage",
        }
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TokenScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "publish" => Ok(TokenScope::Publish),
            "yank" => Ok(TokenScope::Yank),
            "read" => Ok(TokenScope::Read),
            "canary:manage" => Ok(TokenScope::CanaryManage),
            other => Err(format!("Unknown token scope: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateRecord {
    pub name: String,
    pub created_at: i64,
    pub description: Option<String>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateVersionRecord {
    pub name: String,
    pub vers: String,
    pub cksum: String,
    pub features_json: String,
    pub yanked: bool,
    pub links: Option<String>,
    pub published_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrateDepRecord {
    pub crate_name: String,
    pub crate_vers: String,
    pub dep_name: String,
    pub req: String,
    pub features_json: String,
    pub optional: bool,
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: Option<String>,
    pub registry: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryBundleRecord {
    pub bundle_id: String,
    pub service_name: String,
    pub binary_digest: String,
    pub it_archive_digest: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedDigestRecord {
    pub digest: String,
    pub service_name: String,
    pub node_id: String,
    pub reason: String,
    pub tainted_at: i64,
    #[serde(default)]
    pub trace_id: Option<String>,
}

pub type TaintRecord = TaintedDigestRecord;

/// Public read-only package summary DTO across supported registry backends (`cargo`, `nuget`, `maven`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPackageSummary {
    pub ecosystem: String,
    pub name: String,
    pub latest_version: String,
    pub versions_count: u32,
    pub dependency_count: u32,
    pub sha256: String,
    pub published_at: i64,
    pub yanked: bool,
    pub tainted: bool,
    pub description: Option<String>,
    pub repository: Option<String>,
}

/// Public read-only version detail DTO for a specific crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicCrateVersionDetail {
    pub vers: String,
    pub cksum: String,
    pub yanked: bool,
    pub tainted: bool,
    pub published_at: i64,
    pub features: serde_json::Value,
    pub links: Option<String>,
    pub dependencies: Vec<CrateDepRecord>,
}

/// Public read-only crate detail DTO including version history and dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicCrateDetail {
    pub ecosystem: String,
    pub name: String,
    pub created_at: i64,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub latest_version: Option<String>,
    pub versions_count: u32,
    pub versions: Vec<PublicCrateVersionDetail>,
}

/// Aggregate catalog counts for registry overview telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogOverviewCounts {
    pub total_packages: u32,
    pub total_crates: u32,
    pub total_versions: u32,
    pub total_bundles: u32,
    pub tainted_digests_count: u32,
}

/// Sanitized public registry event broadcast over `GET /api/v1/registry/events` SSE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySseEvent {
    pub event_type: String,
    pub ecosystem: String,
    pub subject: String,
    pub version_or_status: String,
    pub digest: Option<String>,
    pub trace_id: Option<String>,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenRecord {
    pub token_id: String,
    pub token_hash: String,
    pub scopes_json: String,
    pub created_at: i64,
}

impl ApiTokenRecord {
    pub fn scopes(&self) -> Result<HashSet<TokenScope>, CatalogError> {
        let list: Vec<String> = serde_json::from_str(&self.scopes_json)?;
        let mut set = HashSet::new();
        for s in list {
            if let Ok(scope) = TokenScope::from_str(&s) {
                set.insert(scope);
            }
        }
        Ok(set)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryStatusSummary {
    pub status: String,
    pub active_canary_digest: Option<String>,
    pub last_promoted_digest: Option<String>,
    pub tainted_count: u32,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct DuckDbCatalog {
    conn: Arc<Mutex<Connection>>,
    event_tx: broadcast::Sender<RegistrySseEvent>,
}

pub type Catalog = DuckDbCatalog;

impl DuckDbCatalog {
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, CatalogError> {
        let path = db_path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        let (event_tx, _) = broadcast::channel(256);
        let catalog = Self {
            conn: Arc::new(Mutex::new(conn)),
            event_tx,
        };
        catalog.init_schema()?;
        Ok(catalog)
    }

    pub fn in_memory() -> Result<Self, CatalogError> {
        let conn = Connection::open_in_memory()?;
        let (event_tx, _) = broadcast::channel(256);
        let catalog = Self {
            conn: Arc::new(Mutex::new(conn)),
            event_tx,
        };
        catalog.init_schema()?;
        Ok(catalog)
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<RegistrySseEvent> {
        self.event_tx.subscribe()
    }

    pub fn emit_event(&self, event: RegistrySseEvent) {
        let _ = self.event_tx.send(event);
    }

    fn init_schema(&self) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS crates (
                name TEXT PRIMARY KEY,
                created_at BIGINT,
                description TEXT,
                repository TEXT
            );

            CREATE TABLE IF NOT EXISTS crate_versions (
                name TEXT,
                vers TEXT,
                cksum TEXT,
                features_json TEXT,
                yanked BOOLEAN DEFAULT FALSE,
                links TEXT,
                published_at BIGINT,
                PRIMARY KEY (name, vers)
            );

            CREATE TABLE IF NOT EXISTS crate_deps (
                crate_name TEXT,
                crate_vers TEXT,
                dep_name TEXT,
                req TEXT,
                features_json TEXT,
                optional BOOLEAN,
                default_features BOOLEAN,
                target TEXT,
                kind TEXT,
                registry TEXT,
                package TEXT
            );

            CREATE TABLE IF NOT EXISTS ecosystem_packages (
                ecosystem TEXT,
                name TEXT,
                vers TEXT,
                cksum TEXT,
                deps_count INTEGER DEFAULT 0,
                yanked BOOLEAN DEFAULT FALSE,
                published_at BIGINT,
                description TEXT,
                repository TEXT,
                PRIMARY KEY (ecosystem, name, vers)
            );

            CREATE TABLE IF NOT EXISTS canary_bundles (
                bundle_id TEXT PRIMARY KEY,
                service_name TEXT,
                binary_digest TEXT,
                it_archive_digest TEXT,
                status TEXT,
                created_at BIGINT,
                updated_at BIGINT,
                trace_id TEXT
            );

            ALTER TABLE canary_bundles ADD COLUMN IF NOT EXISTS trace_id TEXT;

            CREATE TABLE IF NOT EXISTS tainted_digests (
                digest TEXT PRIMARY KEY,
                service_name TEXT,
                node_id TEXT,
                reason TEXT,
                tainted_at BIGINT,
                trace_id TEXT
            );

            ALTER TABLE tainted_digests ADD COLUMN IF NOT EXISTS trace_id TEXT;

            CREATE TABLE IF NOT EXISTS api_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                created_at BIGINT
            );
            "#,
        )?;

        Ok(())
    }

    pub fn insert_crate(
        &self,
        name: &str,
        description: Option<&str>,
        repository: Option<&str>,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();

        let mut stmt = conn.prepare(
            "INSERT INTO crates (name, created_at, description, repository)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (name) DO UPDATE SET
                 description = COALESCE(excluded.description, crates.description),
                 repository = COALESCE(excluded.repository, crates.repository)",
        )?;
        stmt.execute(params![name, now, description, repository])?;
        Ok(())
    }

    pub fn get_crate(&self, name: &str) -> Result<Option<CrateRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT name, created_at, description, repository FROM crates WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(CrateRecord {
                name: row.get(0)?,
                created_at: row.get(1)?,
                description: row.get(2)?,
                repository: row.get(3)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_crate_version(
        &self,
        name: &str,
        vers: &str,
        cksum: &str,
        features_json: &str,
        yanked: bool,
        links: Option<&str>,
        deps: &[CrateDepRecord],
    ) -> Result<(), CatalogError> {
        let now = Utc::now().timestamp_millis();
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;

            // Check if duplicate
            let mut check_stmt =
                conn.prepare("SELECT 1 FROM crate_versions WHERE name = ?1 AND vers = ?2")?;
            let mut existing = check_stmt.query(params![name, vers])?;
            if existing.next()?.is_some() {
                return Err(CatalogError::DuplicateVersion {
                    name: name.to_string(),
                    vers: vers.to_string(),
                });
            }

            // Ensure crate row exists
            let mut crate_stmt = conn.prepare(
                "INSERT OR IGNORE INTO crates (name, created_at, description, repository) VALUES (?1, ?2, NULL, NULL)"
            )?;
            crate_stmt.execute(params![name, now])?;

            // Insert version
            let mut ver_stmt = conn.prepare(
                "INSERT INTO crate_versions (name, vers, cksum, features_json, yanked, links, published_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            ver_stmt.execute(params![
                name,
                vers,
                cksum,
                features_json,
                yanked,
                links,
                now
            ])?;

            // Insert deps
            let mut dep_stmt = conn.prepare(
                "INSERT INTO crate_deps (crate_name, crate_vers, dep_name, req, features_json, optional, default_features, target, kind, registry, package)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for dep in deps {
                dep_stmt.execute(params![
                    name,
                    vers,
                    dep.dep_name,
                    dep.req,
                    dep.features_json,
                    dep.optional,
                    dep.default_features,
                    dep.target,
                    dep.kind,
                    dep.registry,
                    dep.package,
                ])?;
            }
        }

        self.emit_event(RegistrySseEvent {
            event_type: "package.published".to_string(),
            ecosystem: "cargo".to_string(),
            subject: sanitize_public_text(name),
            version_or_status: sanitize_public_text(vers),
            digest: Some(cksum.to_string()),
            trace_id: None,
            timestamp_ms: now,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ecosystem_package(
        &self,
        ecosystem: &str,
        name: &str,
        vers: &str,
        cksum: &str,
        deps_count: u32,
        yanked: bool,
        description: Option<&str>,
        repository: Option<&str>,
    ) -> Result<(), CatalogError> {
        let eco = ecosystem.trim().to_ascii_lowercase();
        if !matches!(eco.as_str(), "cargo" | "nuget" | "maven") {
            return Err(CatalogError::InvalidEcosystem(ecosystem.to_string()));
        }
        if eco == "cargo" {
            self.insert_crate(name, description, repository)?;
            let dummy_deps: Vec<CrateDepRecord> = (0..deps_count)
                .map(|idx| CrateDepRecord {
                    crate_name: name.to_string(),
                    crate_vers: vers.to_string(),
                    dep_name: format!("dep-{idx}"),
                    req: "*".to_string(),
                    features_json: "[]".to_string(),
                    optional: false,
                    default_features: true,
                    target: None,
                    kind: Some("normal".to_string()),
                    registry: None,
                    package: None,
                })
                .collect();
            return self.insert_crate_version(name, vers, cksum, "{}", yanked, None, &dummy_deps);
        }

        let now = Utc::now().timestamp_millis();
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;
            let mut stmt = conn.prepare(
                "INSERT OR REPLACE INTO ecosystem_packages
                 (ecosystem, name, vers, cksum, deps_count, yanked, published_at, description, repository)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            stmt.execute(params![
                eco,
                name,
                vers,
                cksum,
                deps_count as i64,
                yanked,
                now,
                description,
                repository
            ])?;
        }

        self.emit_event(RegistrySseEvent {
            event_type: "package.published".to_string(),
            ecosystem: eco,
            subject: sanitize_public_text(name),
            version_or_status: sanitize_public_text(vers),
            digest: Some(cksum.to_string()),
            trace_id: None,
            timestamp_ms: now,
        });

        Ok(())
    }

    pub fn set_crate_yanked(
        &self,
        name: &str,
        vers: &str,
        yanked: bool,
    ) -> Result<(), CatalogError> {
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;
            let mut stmt = conn
                .prepare("UPDATE crate_versions SET yanked = ?1 WHERE name = ?2 AND vers = ?3")?;
            let count = stmt.execute(params![yanked, name, vers])?;
            if count == 0 {
                return Err(CatalogError::NotFound(format!("Crate {name} v{vers}")));
            }
        }

        self.emit_event(RegistrySseEvent {
            event_type: if yanked {
                "package.yanked".to_string()
            } else {
                "package.unyanked".to_string()
            },
            ecosystem: "cargo".to_string(),
            subject: sanitize_public_text(name),
            version_or_status: sanitize_public_text(vers),
            digest: None,
            trace_id: None,
            timestamp_ms: Utc::now().timestamp_millis(),
        });

        Ok(())
    }

    pub fn get_crate_versions(&self, name: &str) -> Result<Vec<CrateVersionRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT name, vers, cksum, features_json, yanked, links, published_at
             FROM crate_versions WHERE name = ?1 ORDER BY published_at ASC",
        )?;
        let rows = stmt.query_map(params![name], |row| {
            Ok(CrateVersionRecord {
                name: row.get(0)?,
                vers: row.get(1)?,
                cksum: row.get(2)?,
                features_json: row.get(3)?,
                yanked: row.get(4)?,
                links: row.get(5)?,
                published_at: row.get(6)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_crate_deps(
        &self,
        name: &str,
        vers: &str,
    ) -> Result<Vec<CrateDepRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT crate_name, crate_vers, dep_name, req, features_json, optional, default_features, target, kind, registry, package
             FROM crate_deps WHERE crate_name = ?1 AND crate_vers = ?2",
        )?;
        let rows = stmt.query_map(params![name, vers], |row| {
            Ok(CrateDepRecord {
                crate_name: row.get(0)?,
                crate_vers: row.get(1)?,
                dep_name: row.get(2)?,
                req: row.get(3)?,
                features_json: row.get(4)?,
                optional: row.get(5)?,
                default_features: row.get(6)?,
                target: row.get(7)?,
                kind: row.get(8)?,
                registry: row.get(9)?,
                package: row.get(10)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Aggregates published package metadata across supported registry backends (`cargo`, `nuget`,
    /// `maven`) into a deterministic, sorted list of [`PublicPackageSummary`] DTOs with sanitized
    /// metadata and zero internal path or secret leakage.
    pub fn list_public_packages(
        &self,
        ecosystem_filter: Option<&str>,
    ) -> Result<Vec<PublicPackageSummary>, CatalogError> {
        let normalized_filter = match ecosystem_filter.map(|s| s.trim().to_ascii_lowercase()) {
            None => None,
            Some(ref s) if s.is_empty() || s == "all" => None,
            Some(ref s) if matches!(s.as_str(), "cargo" | "nuget" | "maven") => Some(s.clone()),
            Some(other) => return Err(CatalogError::InvalidEcosystem(other)),
        };

        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        // Load tainted digests set
        let mut taint_stmt = conn.prepare("SELECT digest FROM tainted_digests")?;
        let taint_rows = taint_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut tainted_set = HashSet::new();
        for r in taint_rows {
            tainted_set.insert(r?);
        }

        let mut results = Vec::new();

        // 1. Cargo ecosystem packages
        if normalized_filter.is_none() || normalized_filter.as_deref() == Some("cargo") {
            let mut crate_stmt =
                conn.prepare("SELECT name, description, repository FROM crates ORDER BY name ASC")?;
            let crate_rows = crate_stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;

            for c in crate_rows {
                let (name, desc, repo) = c?;
                let mut ver_stmt = conn.prepare(
                    "SELECT vers, cksum, yanked, published_at
                     FROM crate_versions
                     WHERE name = ?1
                     ORDER BY published_at DESC, vers DESC",
                )?;
                let ver_rows = ver_stmt.query_map(params![name], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?;

                let mut vers_list = Vec::new();
                for v in ver_rows {
                    vers_list.push(v?);
                }

                if let Some((latest_vers, latest_cksum, latest_yanked, latest_pub_at)) =
                    vers_list.first().cloned()
                {
                    let mut dep_count_stmt = conn.prepare(
                        "SELECT COUNT(*) FROM crate_deps WHERE crate_name = ?1 AND crate_vers = ?2",
                    )?;
                    let dep_count: i64 =
                        dep_count_stmt.query_row(params![name, latest_vers], |row| row.get(0))?;
                    let any_tainted = vers_list
                        .iter()
                        .any(|(_, cksum, _, _)| tainted_set.contains(cksum));

                    results.push(PublicPackageSummary {
                        ecosystem: "cargo".to_string(),
                        name: sanitize_public_text(&name),
                        latest_version: sanitize_public_text(&latest_vers),
                        versions_count: vers_list.len() as u32,
                        dependency_count: dep_count as u32,
                        sha256: latest_cksum,
                        published_at: latest_pub_at,
                        yanked: latest_yanked,
                        tainted: any_tainted,
                        description: desc.map(|d| sanitize_public_text(&d)),
                        repository: repo.map(|r| sanitize_public_text(&r)),
                    });
                }
            }
        }

        // 2. NuGet and Maven ecosystem packages from ecosystem_packages table
        for eco in ["nuget", "maven"] {
            if normalized_filter.is_none() || normalized_filter.as_deref() == Some(eco) {
                let mut pkg_names_stmt = conn.prepare(
                    "SELECT DISTINCT name FROM ecosystem_packages WHERE ecosystem = ?1 ORDER BY name ASC",
                )?;
                let name_rows =
                    pkg_names_stmt.query_map(params![eco], |row| row.get::<_, String>(0))?;

                for n in name_rows {
                    let pkg_name = n?;
                    let mut ver_stmt = conn.prepare(
                        "SELECT vers, cksum, deps_count, yanked, published_at, description, repository
                         FROM ecosystem_packages
                         WHERE ecosystem = ?1 AND name = ?2
                         ORDER BY published_at DESC, vers DESC",
                    )?;
                    let ver_rows = ver_stmt.query_map(params![eco, pkg_name], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    })?;

                    let mut vers_list = Vec::new();
                    for v in ver_rows {
                        vers_list.push(v?);
                    }

                    if let Some((
                        latest_vers,
                        latest_cksum,
                        deps_cnt,
                        latest_yanked,
                        latest_pub_at,
                        desc,
                        repo,
                    )) = vers_list.first().cloned()
                    {
                        let any_tainted = vers_list
                            .iter()
                            .any(|(_, cksum, _, _, _, _, _)| tainted_set.contains(cksum));
                        results.push(PublicPackageSummary {
                            ecosystem: eco.to_string(),
                            name: sanitize_public_text(&pkg_name),
                            latest_version: sanitize_public_text(&latest_vers),
                            versions_count: vers_list.len() as u32,
                            dependency_count: deps_cnt.max(0) as u32,
                            sha256: latest_cksum,
                            published_at: latest_pub_at,
                            yanked: latest_yanked,
                            tainted: any_tainted,
                            description: desc.map(|d| sanitize_public_text(&d)),
                            repository: repo.map(|r| sanitize_public_text(&r)),
                        });
                    }
                }
            }
        }

        // Deterministic sort by (ecosystem ASC, name ASC)
        results.sort_by(|a, b| {
            a.ecosystem
                .cmp(&b.ecosystem)
                .then_with(|| a.name.cmp(&b.name))
        });

        Ok(results)
    }

    /// Returns a deterministically ordered paginated slice of Cargo crates.
    pub fn list_crates_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PublicPackageSummary>, CatalogError> {
        let all_cargo = self.list_public_packages(Some("cargo"))?;
        let capped_limit = limit.clamp(1, 500);
        Ok(all_cargo
            .into_iter()
            .skip(offset)
            .take(capped_limit)
            .collect())
    }

    /// Returns full version history and dependency graph for a specific crate.
    pub fn get_crate_detail(&self, name: &str) -> Result<Option<PublicCrateDetail>, CatalogError> {
        let Some(crate_rec) = self.get_crate(name)? else {
            return Ok(None);
        };
        let versions = self.get_crate_versions(name)?;
        if versions.is_empty() {
            return Ok(Some(PublicCrateDetail {
                ecosystem: "cargo".to_string(),
                name: sanitize_public_text(&crate_rec.name),
                created_at: crate_rec.created_at,
                description: crate_rec.description.map(|d| sanitize_public_text(&d)),
                repository: crate_rec.repository.map(|r| sanitize_public_text(&r)),
                latest_version: None,
                versions_count: 0,
                versions: Vec::new(),
            }));
        }

        let mut detailed_versions = Vec::with_capacity(versions.len());
        for v in &versions {
            let deps = self.get_crate_deps(name, &v.vers)?;
            let tainted = self.is_digest_tainted(&v.cksum)?;
            let features: serde_json::Value =
                serde_json::from_str(&v.features_json).unwrap_or_else(|_| serde_json::json!({}));
            detailed_versions.push(PublicCrateVersionDetail {
                vers: sanitize_public_text(&v.vers),
                cksum: v.cksum.clone(),
                yanked: v.yanked,
                tainted,
                published_at: v.published_at,
                features,
                links: v.links.as_ref().map(|l| sanitize_public_text(l)),
                dependencies: deps,
            });
        }

        let latest_version = detailed_versions.last().map(|v| v.vers.clone());

        Ok(Some(PublicCrateDetail {
            ecosystem: "cargo".to_string(),
            name: sanitize_public_text(&crate_rec.name),
            created_at: crate_rec.created_at,
            description: crate_rec.description.map(|d| sanitize_public_text(&d)),
            repository: crate_rec.repository.map(|r| sanitize_public_text(&r)),
            latest_version,
            versions_count: detailed_versions.len() as u32,
            versions: detailed_versions,
        }))
    }

    pub fn insert_canary_bundle(&self, bundle: &CanaryBundleRecord) -> Result<(), CatalogError> {
        let validated_trace = match bundle.trace_id.as_deref() {
            Some(t) => Some(validate_w3c_trace_id(t)?),
            None => None,
        };
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;
            let mut stmt = conn.prepare(
                "INSERT INTO canary_bundles (bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at, trace_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            stmt.execute(params![
                bundle.bundle_id,
                bundle.service_name,
                bundle.binary_digest,
                bundle.it_archive_digest,
                bundle.status,
                bundle.created_at,
                bundle.updated_at,
                validated_trace
            ])?;
        }

        self.emit_event(RegistrySseEvent {
            event_type: "canary.bundle.created".to_string(),
            ecosystem: "canary".to_string(),
            subject: sanitize_public_text(&bundle.service_name),
            version_or_status: sanitize_public_text(&bundle.status),
            digest: Some(bundle.binary_digest.clone()),
            trace_id: validated_trace,
            timestamp_ms: bundle.created_at,
        });

        Ok(())
    }

    pub fn get_canary_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<Option<CanaryBundleRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at, trace_id
             FROM canary_bundles WHERE bundle_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![bundle_id], |row| {
            Ok(CanaryBundleRecord {
                bundle_id: row.get(0)?,
                service_name: row.get(1)?,
                binary_digest: row.get(2)?,
                it_archive_digest: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                trace_id: row.get(7)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn find_bundle_by_binary_digest(
        &self,
        binary_digest: &str,
    ) -> Result<Option<CanaryBundleRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at, trace_id
             FROM canary_bundles WHERE binary_digest = ?1 ORDER BY created_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![binary_digest], |row| {
            Ok(CanaryBundleRecord {
                bundle_id: row.get(0)?,
                service_name: row.get(1)?,
                binary_digest: row.get(2)?,
                it_archive_digest: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                trace_id: row.get(7)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn list_canary_bundles(&self) -> Result<Vec<CanaryBundleRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at, trace_id
             FROM canary_bundles ORDER BY updated_at DESC, bundle_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(CanaryBundleRecord {
                bundle_id: row.get(0)?,
                service_name: row.get(1)?,
                binary_digest: row.get(2)?,
                it_archive_digest: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                trace_id: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn list_sanitized_canary_bundles(&self) -> Result<Vec<CanaryBundleRecord>, CatalogError> {
        let bundles = self.list_canary_bundles()?;
        Ok(bundles
            .into_iter()
            .map(|mut b| {
                b.service_name = sanitize_public_text(&b.service_name);
                b.status = sanitize_public_text(&b.status);
                b
            })
            .collect())
    }

    pub fn update_canary_bundle_status(
        &self,
        bundle_id: &str,
        status: &str,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let mut stmt = conn.prepare(
            "UPDATE canary_bundles SET status = ?1, updated_at = ?2 WHERE bundle_id = ?3",
        )?;
        let updated = stmt.execute(params![status, now, bundle_id])?;
        if updated == 0 {
            return Err(CatalogError::NotFound(format!("Bundle {bundle_id}")));
        }
        Ok(())
    }

    pub fn update_bundle_status_by_binary_digest(
        &self,
        binary_digest: &str,
        status: &str,
    ) -> Result<(), CatalogError> {
        let now = Utc::now().timestamp_millis();
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;
            let mut stmt = conn.prepare(
                "UPDATE canary_bundles SET status = ?1, updated_at = ?2 WHERE binary_digest = ?3",
            )?;
            stmt.execute(params![status, now, binary_digest])?;
        }

        self.emit_event(RegistrySseEvent {
            event_type: "canary.bundle.status".to_string(),
            ecosystem: "canary".to_string(),
            subject: binary_digest.to_string(),
            version_or_status: sanitize_public_text(status),
            digest: Some(binary_digest.to_string()),
            trace_id: None,
            timestamp_ms: now,
        });

        Ok(())
    }

    pub fn taint_digest(
        &self,
        digest: &str,
        service_name: &str,
        node_id: &str,
        reason: &str,
    ) -> Result<(), CatalogError> {
        self.taint_digest_with_trace(digest, service_name, node_id, reason, None)
    }

    pub fn taint_digest_with_trace(
        &self,
        digest: &str,
        service_name: &str,
        node_id: &str,
        reason: &str,
        trace_id: Option<&str>,
    ) -> Result<(), CatalogError> {
        let validated_trace = match trace_id {
            Some(t) => Some(validate_w3c_trace_id(t)?),
            None => None,
        };
        let now = Utc::now().timestamp_millis();
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| CatalogError::Lock(e.to_string()))?;
            let mut stmt = conn.prepare(
                "INSERT OR REPLACE INTO tainted_digests (digest, service_name, node_id, reason, tainted_at, trace_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            stmt.execute(params![
                digest,
                service_name,
                node_id,
                reason,
                now,
                validated_trace
            ])?;

            // Update corresponding canary bundle status to tainted and preserve/attach trace_id
            let mut b_stmt = conn.prepare(
                "UPDATE canary_bundles
                 SET status = 'tainted',
                     updated_at = ?1,
                     trace_id = COALESCE(?2, trace_id)
                 WHERE binary_digest = ?3",
            )?;
            b_stmt.execute(params![now, validated_trace, digest])?;
        }

        self.emit_event(RegistrySseEvent {
            event_type: "canary.digest.tainted".to_string(),
            ecosystem: "canary".to_string(),
            subject: sanitize_public_text(service_name),
            version_or_status: "tainted".to_string(),
            digest: Some(digest.to_string()),
            trace_id: validated_trace,
            timestamp_ms: now,
        });

        Ok(())
    }

    pub fn is_digest_tainted(&self, digest: &str) -> Result<bool, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare("SELECT 1 FROM tainted_digests WHERE digest = ?1")?;
        let mut rows = stmt.query(params![digest])?;
        Ok(rows.next()?.is_some())
    }

    pub fn get_tainted_digest(
        &self,
        digest: &str,
    ) -> Result<Option<TaintedDigestRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT digest, service_name, node_id, reason, tainted_at, trace_id FROM tainted_digests WHERE digest = ?1",
        )?;
        let mut rows = stmt.query_map(params![digest], |row| {
            Ok(TaintedDigestRecord {
                digest: row.get(0)?,
                service_name: row.get(1)?,
                node_id: row.get(2)?,
                reason: row.get(3)?,
                tainted_at: row.get(4)?,
                trace_id: row.get(5)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn list_tainted_digests(&self) -> Result<Vec<TaintedDigestRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT digest, service_name, node_id, reason, tainted_at, trace_id FROM tainted_digests ORDER BY tainted_at DESC, digest ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaintedDigestRecord {
                digest: row.get(0)?,
                service_name: row.get(1)?,
                node_id: row.get(2)?,
                reason: row.get(3)?,
                tainted_at: row.get(4)?,
                trace_id: row.get(5)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Returns all taint records with internal hostnames, private domains, RFC1918 LAN
    /// IPs, and host filesystem paths scrubbed to public placeholders.
    pub fn list_sanitized_tainted_digests(&self) -> Result<Vec<TaintedDigestRecord>, CatalogError> {
        let records = self.list_tainted_digests()?;
        Ok(records
            .into_iter()
            .map(|mut rec| {
                rec.service_name = sanitize_public_text(&rec.service_name);
                rec.node_id = sanitize_node_alias(&rec.node_id);
                rec.reason = sanitize_public_text(&rec.reason);
                rec
            })
            .collect())
    }

    pub fn get_catalog_overview_counts(&self) -> Result<CatalogOverviewCounts, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        let crates_cnt: i64 = conn.query_row("SELECT COUNT(*) FROM crates", [], |r| r.get(0))?;
        let eco_pkgs_cnt: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT ecosystem || ':' || name) FROM ecosystem_packages",
            [],
            |r| r.get(0),
        )?;
        let versions_cnt: i64 =
            conn.query_row("SELECT COUNT(*) FROM crate_versions", [], |r| r.get(0))?;
        let eco_vers_cnt: i64 =
            conn.query_row("SELECT COUNT(*) FROM ecosystem_packages", [], |r| r.get(0))?;
        let bundles_cnt: i64 =
            conn.query_row("SELECT COUNT(*) FROM canary_bundles", [], |r| r.get(0))?;
        let taints_cnt: i64 =
            conn.query_row("SELECT COUNT(*) FROM tainted_digests", [], |r| r.get(0))?;

        Ok(CatalogOverviewCounts {
            total_packages: (crates_cnt + eco_pkgs_cnt).max(0) as u32,
            total_crates: crates_cnt.max(0) as u32,
            total_versions: (versions_cnt + eco_vers_cnt).max(0) as u32,
            total_bundles: bundles_cnt.max(0) as u32,
            tainted_digests_count: taints_cnt.max(0) as u32,
        })
    }

    pub fn get_canary_status_summary(&self) -> Result<CanaryStatusSummary, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        // Active canary: bundle in "testing" status
        let mut test_stmt = conn.prepare(
            "SELECT binary_digest FROM canary_bundles WHERE status = 'testing' ORDER BY created_at DESC LIMIT 1",
        )?;
        let mut test_rows = test_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let active_canary_digest = test_rows.next().transpose()?;

        // Last promoted: bundle in "healthy" status
        let mut prom_stmt = conn.prepare(
            "SELECT binary_digest FROM canary_bundles WHERE status = 'healthy' ORDER BY updated_at DESC LIMIT 1",
        )?;
        let mut prom_rows = prom_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let last_promoted_digest = prom_rows.next().transpose()?;

        // Count tainted
        let mut taint_stmt = conn.prepare("SELECT COUNT(*) FROM tainted_digests")?;
        let tainted_count: i64 = taint_stmt.query_row([], |row| row.get(0))?;

        let mut latest_stmt =
            conn.prepare("SELECT status FROM canary_bundles ORDER BY updated_at DESC LIMIT 1")?;
        let mut latest_rows = latest_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let latest_status = latest_rows.next().transpose()?;

        let status = match latest_status {
            Some(s) => s,
            None => "healthy".to_string(),
        };

        let now = Utc::now().timestamp_millis();

        Ok(CanaryStatusSummary {
            status,
            active_canary_digest,
            last_promoted_digest,
            tainted_count: tainted_count as u32,
            updated_at: now,
        })
    }

    pub fn insert_api_token(
        &self,
        token_id: &str,
        token_hash: &str,
        scopes: &[TokenScope],
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let scopes_strings: Vec<&'static str> = scopes.iter().map(|s| s.as_str()).collect();
        let scopes_json = serde_json::to_string(&scopes_strings)?;

        let mut stmt = conn.prepare(
            "INSERT INTO api_tokens (token_id, token_hash, scopes_json, created_at) VALUES (?1, ?2, ?3, ?4)",
        )?;
        stmt.execute(params![token_id, token_hash, scopes_json, now])?;
        Ok(())
    }

    pub fn get_api_tokens(&self) -> Result<Vec<ApiTokenRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT token_id, token_hash, scopes_json, created_at FROM api_tokens ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ApiTokenRecord {
                token_id: row.get(0)?,
                token_hash: row.get(1)?,
                scopes_json: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn find_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiTokenRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT token_id, token_hash, scopes_json, created_at FROM api_tokens WHERE token_hash = ?1",
        )?;
        let mut rows = stmt.query_map(params![token_hash], |row| {
            Ok(ApiTokenRecord {
                token_id: row.get(0)?,
                token_hash: row.get(1)?,
                scopes_json: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn delete_api_token(&self, token_id: &str) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare("DELETE FROM api_tokens WHERE token_id = ?1")?;
        stmt.execute(params![token_id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pure_rust_sanitization_and_token_scopes() {
        let raw_paths = "Built in /var/lib/muregist/work, /home/builder/src, /Users/dev/proj, /tmp/stage, and /etc/muregist/config.toml";
        let sanitized_paths = sanitize_public_text(raw_paths);
        assert_eq!(
            sanitized_paths,
            "Built in <redacted-path>, <redacted-path>, <redacted-path>, <redacted-path>, and <redacted-path>"
        );

        std::env::set_var(
            "MUREGISTRY_NODE_MAP",
            "test-node-a=node-a,test-node-b=node-b,test-worker-rv=worker-riscv64",
        );
        let raw_net = format!(
            "Node {} at {} on {}",
            "test-node-a", "192.168.10.25", "service.corp.internal"
        );
        let sanitized_net = sanitize_public_text(&raw_net);
        assert_eq!(
            sanitized_net,
            "Node node-a at 192.0.2.x on service.example.invalid"
        );

        assert!(validate_w3c_trace_id("4bf92f3577b34da6a3ce929d0e0e4736").is_ok());
        assert!(validate_w3c_trace_id("00000000000000000000000000000000").is_err());
        assert!(validate_w3c_trace_id("short").is_err());

        let token_rec = ApiTokenRecord {
            token_id: "tok-pure".to_string(),
            token_hash: "deadbeef".to_string(),
            scopes_json: r#"["publish","read","canary:manage","unknown:ignored"]"#.to_string(),
            created_at: 1_700_000_000_000,
        };
        let scopes = token_rec.scopes().unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&TokenScope::Publish));
        assert!(scopes.contains(&TokenScope::Read));
        assert!(scopes.contains(&TokenScope::CanaryManage));
        assert!(!scopes.contains(&TokenScope::Yank));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_duckdb_catalog_crud_and_sql_injection_defense() {
        let catalog = DuckDbCatalog::in_memory().unwrap();

        // 1. Crate insertion
        catalog
            .insert_crate(
                "my-pkg",
                Some("A test package"),
                Some("https://example.com/repo"),
            )
            .unwrap();
        let pkg = catalog
            .get_crate("my-pkg")
            .unwrap()
            .expect("crate should exist");
        assert_eq!(pkg.name, "my-pkg");
        assert_eq!(pkg.description.as_deref(), Some("A test package"));

        // 2. Crate version and deps
        let dep = CrateDepRecord {
            crate_name: "my-pkg".to_string(),
            crate_vers: "0.1.0".to_string(),
            dep_name: "serde".to_string(),
            req: "^1.0".to_string(),
            features_json: "[]".to_string(),
            optional: false,
            default_features: true,
            target: None,
            kind: Some("normal".to_string()),
            registry: None,
            package: None,
        };
        catalog
            .insert_crate_version("my-pkg", "0.1.0", "abcdef123456", "{}", false, None, &[dep])
            .unwrap();

        // 3. Duplicate version detection
        let dup =
            catalog.insert_crate_version("my-pkg", "0.1.0", "abcdef123456", "{}", false, None, &[]);
        assert!(matches!(dup, Err(CatalogError::DuplicateVersion { .. })));

        // 4. Query versions and deps
        let versions = catalog.get_crate_versions("my-pkg").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].vers, "0.1.0");
        assert!(!versions[0].yanked);

        let deps = catalog.get_crate_deps("my-pkg", "0.1.0").unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].dep_name, "serde");

        // 5. Yanking
        catalog.set_crate_yanked("my-pkg", "0.1.0", true).unwrap();
        let versions_after_yank = catalog.get_crate_versions("my-pkg").unwrap();
        assert!(versions_after_yank[0].yanked);

        // 6. SQL injection resistance on adversarial inputs
        let malicious_input = "' OR '1'='1'; DROP TABLE crates; --";
        catalog
            .insert_crate(malicious_input, Some("evil"), None)
            .unwrap();
        let found = catalog.get_crate(malicious_input).unwrap();
        assert!(found.is_some());

        // Verify the crates table is NOT dropped
        let original = catalog.get_crate("my-pkg").unwrap();
        assert!(original.is_some());

        // 7. Canary bundle & Taint lifecycle with trace_id
        let now = Utc::now().timestamp_millis();
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let bundle = CanaryBundleRecord {
            bundle_id: "bundle-1".to_string(),
            service_name: "test-service".to_string(),
            binary_digest: "bin-digest-1".to_string(),
            it_archive_digest: "it-digest-1".to_string(),
            status: "testing".to_string(),
            created_at: now,
            updated_at: now,
            trace_id: Some(trace_id.to_string()),
        };
        catalog.insert_canary_bundle(&bundle).unwrap();

        let summary1 = catalog.get_canary_status_summary().unwrap();
        assert_eq!(summary1.status, "testing");
        assert_eq!(
            summary1.active_canary_digest.as_deref(),
            Some("bin-digest-1")
        );

        // Taint digest with trace_id
        let rollback_trace = "0af7651916cd43dd8448eb211c80319c";
        catalog
            .taint_digest_with_trace(
                "bin-digest-1",
                "test-service",
                "node-a",
                "Integration test failed",
                Some(rollback_trace),
            )
            .unwrap();
        assert!(catalog.is_digest_tainted("bin-digest-1").unwrap());
        let taint_rec = catalog.get_tainted_digest("bin-digest-1").unwrap().unwrap();
        assert_eq!(taint_rec.trace_id.as_deref(), Some(rollback_trace));

        let summary2 = catalog.get_canary_status_summary().unwrap();
        assert_eq!(summary2.status, "tainted");
        assert_eq!(summary2.tainted_count, 1);

        // API Token CRUD
        catalog
            .insert_api_token(
                "tok-1",
                "hash-12345",
                &[TokenScope::Publish, TokenScope::Read],
            )
            .unwrap();
        let token = catalog.find_token_by_hash("hash-12345").unwrap().unwrap();
        let scopes = token.scopes().unwrap();
        assert!(scopes.contains(&TokenScope::Publish));
        assert!(scopes.contains(&TokenScope::Read));
        assert!(!scopes.contains(&TokenScope::Yank));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_public_packages_and_sanitization() {
        let catalog = DuckDbCatalog::in_memory().unwrap();
        catalog
            .insert_ecosystem_package(
                "cargo",
                "k3-core",
                "0.2.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                2,
                false,
                Some("Core library built on /var/lib/muregist/work"),
                Some("https://github.com/LMA1980/k3-core"),
            )
            .unwrap();
        catalog
            .insert_ecosystem_package(
                "nuget",
                "MuRegist.Client",
                "1.0.0",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1,
                false,
                Some("NuGet client package"),
                None,
            )
            .unwrap();
        catalog
            .insert_ecosystem_package(
                "maven",
                "org.k3:mu-client",
                "0.5.0",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                0,
                false,
                Some("Maven artifact"),
                None,
            )
            .unwrap();

        let all_pkgs = catalog.list_public_packages(None).unwrap();
        assert_eq!(all_pkgs.len(), 3);
        assert_eq!(all_pkgs[0].ecosystem, "cargo");
        assert_eq!(
            all_pkgs[0].description.as_deref(),
            Some("Core library built on <redacted-path>")
        );
        assert_eq!(all_pkgs[1].ecosystem, "maven");
        assert_eq!(all_pkgs[2].ecosystem, "nuget");

        let cargo_only = catalog.list_public_packages(Some("cargo")).unwrap();
        assert_eq!(cargo_only.len(), 1);
        assert_eq!(cargo_only[0].name, "k3-core");

        assert!(matches!(
            catalog.list_public_packages(Some("pypi")),
            Err(CatalogError::InvalidEcosystem(_))
        ));
    }
}
