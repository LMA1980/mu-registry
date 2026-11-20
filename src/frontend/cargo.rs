use crate::api::canary::AppState;
use crate::auth::AuthContext;
use crate::frontend::RegistryFrontend;
use crate::storage::catalog::{CrateDepRecord, TokenScope};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path as StdPath, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Helper function implementing RFC 2789 sparse index prefix layout rules.
/// Returns relative path for the crate index file:
/// - 1 character: `1/{crate}`
/// - 2 characters: `2/{crate}`
/// - 3 characters: `3/{first_char}/{crate}`
/// - 4+ characters: `{first_two}/{second_two}/{crate}`
///
/// All prefixes and names are lowercase.
pub fn cargo_index_relative_path(crate_name: &str) -> PathBuf {
    let lower = crate_name.trim().to_ascii_lowercase();
    let char_count = lower.chars().count();

    match char_count {
        1 => PathBuf::from("1").join(&lower),
        2 => PathBuf::from("2").join(&lower),
        3 => {
            let first: String = lower.chars().take(1).collect();
            PathBuf::from("3").join(first).join(&lower)
        }
        _ => {
            let p1: String = lower.chars().take(2).collect();
            let p2: String = lower.chars().skip(2).take(2).collect();
            PathBuf::from(p1).join(p2).join(&lower)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseIndexDep {
    pub name: String,
    pub req: String,
    pub features: Vec<String>,
    pub optional: bool,
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: String,
    pub registry: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseIndexEntry {
    pub name: String,
    pub vers: String,
    pub deps: Vec<SparseIndexDep>,
    pub cksum: String,
    pub features: HashMap<String, Vec<String>>,
    pub yanked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<String>,
    pub v: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishDependency {
    pub name: String,
    pub version_req: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "default_true")]
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: Option<String>,
    pub registry: Option<String>,
    pub explicit_name_in_toml: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishMetadata {
    pub name: String,
    pub vers: String,
    #[serde(default)]
    pub deps: Vec<PublishDependency>,
    #[serde(default)]
    pub features: HashMap<String, Vec<String>>,
    pub authors: Option<Vec<String>>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub readme: Option<String>,
    pub readme_file: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub repository: Option<String>,
    pub badges: Option<serde_json::Value>,
    pub links: Option<String>,
}

pub struct CargoSparseFrontend;

impl RegistryFrontend for CargoSparseFrontend {
    fn name(&self) -> &'static str {
        "cargo-sparse"
    }

    fn router(&self) -> Router<AppState> {
        Router::new()
            .route("/config.json", get(config_json_handler))
            .route("/index/config.json", get(config_json_handler))
            .route("/index/{*path}", get(get_sparse_index_handler))
            .route(
                "/api/v1/crates/{crate}/{version}/download",
                get(download_crate_handler),
            )
            .route(
                "/api/v1/crates/{crate}/{version}/yank",
                delete(yank_crate_handler),
            )
            .route(
                "/api/v1/crates/{crate}/{version}/unyank",
                put(unyank_crate_handler),
            )
            .route("/api/v1/crates/new", put(publish_crate_handler))
    }
}

async fn config_json_handler(State(state): State<AppState>) -> impl IntoResponse {
    let base = &state.config.base_url;
    let json_body = serde_json::json!({
        "dl": format!("{base}/api/v1/crates"),
        "api": base
    });

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, headers, Json(json_body))
}

async fn get_sparse_index_handler(
    State(state): State<AppState>,
    Path(path_str): Path<String>,
    headers: HeaderMap,
) -> Response {
    let clean_path = path_str.trim().trim_start_matches('/');
    let index_root = state.config.cargo_index_dir();
    let file_path = index_root.join(clean_path);

    // If file doesn't exist on disk, attempt to regenerate from DuckDB
    let content_bytes = if tokio::fs::try_exists(&file_path).await.unwrap_or(false) {
        match tokio::fs::read(&file_path).await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to read index file: {e}"),
                )
                    .into_response()
            }
        }
    } else {
        // Extract crate name (last path component)
        let crate_name = StdPath::new(clean_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(clean_path);

        match regenerate_index_file(&state, crate_name).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "crate_not_found",
                        "message": format!("Crate {crate_name} not found in index")
                    })),
                )
                    .into_response()
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        }
    };

    // Calculate ETag as sha256:<hex>
    let mut hasher = Sha256::new();
    hasher.update(&content_bytes);
    let hex_digest = hex::encode(hasher.finalize());
    let etag_val = format!("sha256:{hex_digest}");

    // Check If-None-Match
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(inm_str) = inm.to_str() {
            let trimmed = inm_str.trim().trim_matches('"');
            if trimmed == etag_val || trimmed == hex_digest {
                let mut resp_headers = HeaderMap::new();
                resp_headers.insert(
                    header::ETAG,
                    HeaderValue::from_str(&format!("\"{etag_val}\"")).unwrap(),
                );
                resp_headers.insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-cache, must-revalidate"),
                );
                return (StatusCode::NOT_MODIFIED, resp_headers).into_response();
            }
        }
    }

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, must-revalidate"),
    );
    resp_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{etag_val}\"")).unwrap(),
    );

    (StatusCode::OK, resp_headers, content_bytes).into_response()
}

async fn download_crate_handler(
    State(state): State<AppState>,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    let versions = match state.catalog.get_crate_versions(&crate_name) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let matching = match versions.iter().find(|v| v.vers == version) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "version_not_found",
                    "message": format!("Crate {crate_name} v{version} not found")
                })),
            )
                .into_response()
        }
    };

    let bytes = match state.cas.get_blob(&matching.cksum).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "blob_not_found",
                    "digest": matching.cksum,
                    "detail": e.to_string()
                })),
            )
                .into_response()
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{crate_name}-{version}.crate\""
        ))
        .unwrap(),
    );

    (StatusCode::OK, headers, bytes).into_response()
}

async fn yank_crate_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    if !auth.is_authenticated() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }
    if !auth.has_scope(TokenScope::Yank) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires yank scope"
            })),
        )
            .into_response();
    }

    if let Err(e) = state.catalog.set_crate_yanked(&crate_name, &version, true) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Rewrite sparse index file atomically
    let _ = regenerate_index_file(&state, &crate_name).await;

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

async fn unyank_crate_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    if !auth.is_authenticated() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }
    if !auth.has_scope(TokenScope::Yank) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires yank scope"
            })),
        )
            .into_response();
    }

    if let Err(e) = state.catalog.set_crate_yanked(&crate_name, &version, false) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let _ = regenerate_index_file(&state, &crate_name).await;

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

async fn publish_crate_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    body: Bytes,
) -> Response {
    if !auth.is_authenticated() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "errors": [{"detail": "Authentication credentials required"}]
            })),
        )
            .into_response();
    }
    if !auth.has_scope(TokenScope::Publish) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "errors": [{"detail": "Requires publish scope"}]
            })),
        )
            .into_response();
    }

    // Binary wire framing:
    // 4-byte LE JSON length -> JSON bytes -> 4-byte LE tarball length -> tarball bytes
    let raw = &body[..];
    if raw.len() < 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "errors": [{"detail": "Payload too short to read JSON metadata length"}]
            })),
        )
            .into_response();
    }

    let json_len = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let json_end = 4 + json_len;

    if raw.len() < json_end + 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "errors": [{"detail": "Payload truncated before crate tarball length"}]
            })),
        )
            .into_response();
    }

    let json_slice = &raw[4..json_end];
    let metadata: PublishMetadata = match serde_json::from_slice(json_slice) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "errors": [{"detail": format!("Invalid publish metadata JSON: {e}")}]
                })),
            )
                .into_response()
        }
    };

    let crate_len = u32::from_le_bytes(raw[json_end..json_end + 4].try_into().unwrap()) as usize;
    let crate_end = json_end + 4 + crate_len;

    if raw.len() < crate_end {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "errors": [{"detail": "Payload truncated before crate tarball finished"}]
            })),
        )
            .into_response();
    }

    let tarball_bytes = &raw[json_end + 4..crate_end];

    // Check duplicate version
    let existing_versions = state
        .catalog
        .get_crate_versions(&metadata.name)
        .unwrap_or_default();
    if existing_versions.iter().any(|v| v.vers == metadata.vers) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "errors": [{
                    "detail": format!("crate version `{}` already exists", metadata.vers)
                }]
            })),
        )
            .into_response();
    }

    // Put tarball into CAS
    let cksum = match state.cas.put_blob(tarball_bytes).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "errors": [{"detail": format!("Failed to store tarball in CAS: {e}")}]
                })),
            )
                .into_response()
        }
    };

    // Prepare deps
    let mut db_deps = Vec::new();
    let mut index_deps = Vec::new();

    for d in &metadata.deps {
        let features_json = serde_json::to_string(&d.features).unwrap_or_else(|_| "[]".to_string());
        db_deps.push(CrateDepRecord {
            crate_name: metadata.name.clone(),
            crate_vers: metadata.vers.clone(),
            dep_name: d.name.clone(),
            req: d.version_req.clone(),
            features_json: features_json.clone(),
            optional: d.optional,
            default_features: d.default_features,
            target: d.target.clone(),
            kind: d.kind.clone(),
            registry: d.registry.clone(),
            package: d.explicit_name_in_toml.clone(),
        });

        index_deps.push(SparseIndexDep {
            name: d.name.clone(),
            req: d.version_req.clone(),
            features: d.features.clone(),
            optional: d.optional,
            default_features: d.default_features,
            target: d.target.clone(),
            kind: d.kind.clone().unwrap_or_else(|| "normal".to_string()),
            registry: d.registry.clone(),
            package: d.explicit_name_in_toml.clone(),
        });
    }

    let features_json =
        serde_json::to_string(&metadata.features).unwrap_or_else(|_| "{}".to_string());

    // Insert crate version in catalog
    if let Err(e) = state.catalog.insert_crate_version(
        &metadata.name,
        &metadata.vers,
        cksum.as_str(),
        &features_json,
        false,
        metadata.links.as_deref(),
        &db_deps,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "errors": [{"detail": format!("Database error inserting crate version: {e}")}]
            })),
        )
            .into_response();
    }

    // Update crate metadata
    let _ = state.catalog.insert_crate(
        &metadata.name,
        metadata.description.as_deref(),
        metadata.repository.as_deref(),
    );

    // Write / append to sparse index file atomically
    let index_rel_path = cargo_index_relative_path(&metadata.name);
    let target_index_file = state.config.cargo_index_dir().join(&index_rel_path);

    let entry = SparseIndexEntry {
        name: metadata.name.clone(),
        vers: metadata.vers.clone(),
        deps: index_deps,
        cksum: cksum.to_string(),
        features: metadata.features.clone(),
        yanked: false,
        links: metadata.links.clone(),
        v: 2,
    };
    let entry_line = match serde_json::to_string(&entry) {
        Ok(line) => line,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"errors": [{"detail": e.to_string()}]})),
            )
                .into_response()
        }
    };

    // Atomic file update: read existing lines, append new line, write to tmp, sync, and rename
    let mut all_lines = Vec::new();
    if tokio::fs::try_exists(&target_index_file)
        .await
        .unwrap_or(false)
    {
        if let Ok(content) = tokio::fs::read_to_string(&target_index_file).await {
            for line in content.lines() {
                if !line.trim().is_empty() {
                    all_lines.push(line.to_string());
                }
            }
        }
    }
    all_lines.push(entry_line);

    let mut combined_content = all_lines.join("\n");
    combined_content.push('\n');

    let tmp_path = state
        .config
        .tmp_dir()
        .join(format!("index-update-{}.tmp", Uuid::new_v4()));
    if let Some(parent) = tmp_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Some(parent) = target_index_file.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    let write_res: Result<(), (StatusCode, Json<serde_json::Value>)> = async {
        let mut tmp_file = tokio::fs::File::create(&tmp_path).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"errors": [{"detail": e.to_string()}]})),
            )
        })?;
        tmp_file
            .write_all(combined_content.as_bytes())
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"errors": [{"detail": e.to_string()}]})),
                )
            })?;
        tmp_file.sync_all().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"errors": [{"detail": e.to_string()}]})),
            )
        })?;
        tokio::fs::rename(&tmp_path, &target_index_file)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"errors": [{"detail": e.to_string()}]})),
                )
            })?;
        Ok(())
    }
    .await;

    if let Err(e) = write_res {
        return e.into_response();
    }

    // Success response according to Cargo publish protocol
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "warnings": {
                "invalid_categories": [],
                "invalid_badges": [],
                "other": []
            }
        })),
    )
        .into_response()
}

/// Helper function to regenerate an index file from the DuckDB catalog
pub async fn regenerate_index_file(
    state: &AppState,
    crate_name: &str,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let versions = state.catalog.get_crate_versions(crate_name)?;
    if versions.is_empty() {
        return Ok(None);
    }

    let mut lines = Vec::new();
    for v in versions {
        let deps = state.catalog.get_crate_deps(crate_name, &v.vers)?;
        let sparse_deps: Vec<SparseIndexDep> = deps
            .into_iter()
            .map(|d| {
                let feats: Vec<String> = serde_json::from_str(&d.features_json).unwrap_or_default();
                SparseIndexDep {
                    name: d.dep_name,
                    req: d.req,
                    features: feats,
                    optional: d.optional,
                    default_features: d.default_features,
                    target: d.target,
                    kind: d.kind.unwrap_or_else(|| "normal".to_string()),
                    registry: d.registry,
                    package: d.package,
                }
            })
            .collect();

        let features: HashMap<String, Vec<String>> =
            serde_json::from_str(&v.features_json).unwrap_or_default();

        let entry = SparseIndexEntry {
            name: v.name,
            vers: v.vers,
            deps: sparse_deps,
            cksum: v.cksum,
            features,
            yanked: v.yanked,
            links: v.links,
            v: 2,
        };

        lines.push(serde_json::to_string(&entry)?);
    }

    let mut output = lines.join("\n");
    output.push('\n');

    let bytes = output.into_bytes();

    // Write file to disk
    let rel_path = cargo_index_relative_path(crate_name);
    let target_path = state.config.cargo_index_dir().join(rel_path);
    if let Some(parent) = target_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&target_path, &bytes).await?;

    Ok(Some(bytes))
}

/// Helper function to construct a binary frame for `cargo publish` PUT /api/v1/crates/new
pub fn encode_publish_frame(metadata_json: &[u8], tarball_bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    let json_len = metadata_json.len() as u32;
    frame.extend_from_slice(&json_len.to_le_bytes());
    frame.extend_from_slice(metadata_json);

    let tarball_len = tarball_bytes.len() as u32;
    frame.extend_from_slice(&tarball_len.to_le_bytes());
    frame.extend_from_slice(tarball_bytes);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_index_prefix_layout() {
        assert_eq!(cargo_index_relative_path("a"), PathBuf::from("1/a"));
        assert_eq!(cargo_index_relative_path("ab"), PathBuf::from("2/ab"));
        assert_eq!(cargo_index_relative_path("abc"), PathBuf::from("3/a/abc"));
        assert_eq!(
            cargo_index_relative_path("serde"),
            PathBuf::from("se/rd/serde")
        );
        assert_eq!(
            cargo_index_relative_path("ACTIONRUNNER"),
            PathBuf::from("ac/ti/actionrunner")
        );
    }

    #[test]
    fn test_publish_frame_encoding() {
        let meta = b"{\"name\":\"my-pkg\"}";
        let tarball = b"fake tarball bytes 123456";
        let frame = encode_publish_frame(meta, tarball);

        assert_eq!(frame.len(), 4 + meta.len() + 4 + tarball.len());
        let read_meta_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(read_meta_len, meta.len());
        assert_eq!(&frame[4..4 + read_meta_len], meta);

        let offset = 4 + read_meta_len;
        let read_tar_len =
            u32::from_le_bytes(frame[offset..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(read_tar_len, tarball.len());
        assert_eq!(&frame[offset + 4..offset + 4 + read_tar_len], tarball);
    }
}
