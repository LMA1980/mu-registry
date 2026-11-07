use crate::auth::AuthContext;
use crate::config::AppConfig;
use crate::storage::cas::CasStore;
use crate::storage::catalog::{
    validate_w3c_trace_id, CanaryBundleRecord, DuckDbCatalog, TokenScope,
};
use axum::{
    extract::{FromRef, FromRequest, Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use mu_observable_ipc::TraceContext;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub cas: Arc<CasStore>,
    pub catalog: DuckDbCatalog,
}

impl FromRef<AppState> for DuckDbCatalog {
    fn from_ref(state: &AppState) -> Self {
        state.catalog.clone()
    }
}

impl FromRef<AppState> for Arc<CasStore> {
    fn from_ref(state: &AppState) -> Self {
        state.cas.clone()
    }
}

impl FromRef<AppState> for Arc<AppConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateBundleJsonRequest {
    pub service_name: String,
    pub binary_digest: String,
    pub it_archive_digest: String,
    pub trace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TaintRequest {
    pub service_name: Option<String>,
    pub node_id: Option<String>,
    pub reason: Option<String>,
    pub trace_id: Option<String>,
}

fn extract_trace_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| TraceContext::parse_traceparent(s).ok())
        .map(|ctx| ctx.trace_id_hex())
}

#[derive(Debug, Deserialize)]
pub struct BundleDownloadQuery {
    pub download: Option<String>,
}

pub fn canary_router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/bundles/it", post(create_bundle_handler))
        .route("/api/v1/bundles/it/{id}", get(get_bundle_handler))
        .route(
            "/api/v1/canary/{digest}/promote",
            post(promote_canary_handler),
        )
        .route("/api/v1/canary/{digest}/taint", post(taint_canary_handler))
        .route("/api/v1/canary/status", get(get_canary_status_handler))
}

async fn create_bundle_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    // Requires canary:manage or publish
    if !auth.is_authenticated() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized",
                "message": "Authentication credentials required"
            })),
        )
            .into_response();
    }
    if !auth.has_scope(TokenScope::CanaryManage) && !auth.has_scope(TokenScope::Publish) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires canary:manage or publish scope"
            })),
        )
            .into_response();
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut service_name = String::new();
    let mut binary_digest = String::new();
    let mut it_archive_digest = String::new();
    let mut explicit_trace_id: Option<String> = None;

    if content_type.starts_with("multipart/form-data") {
        let req = match axum::http::Request::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(body)
        {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        };

        let mut multipart = match Multipart::from_request(req, &()).await {
            Ok(m) => m,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        };

        loop {
            match multipart.next_field().await {
                Ok(Some(field)) => {
                    let field_name = field.name().unwrap_or("").to_string();
                    if field_name == "service_name" {
                        service_name = field.text().await.unwrap_or_default();
                    } else if field_name == "binary" {
                        match field.bytes().await {
                            Ok(bytes) => match state.cas.put_blob(&bytes).await {
                                Ok(d) => binary_digest = d.to_string(),
                                Err(e) => {
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(serde_json::json!({"error": e.to_string()})),
                                    )
                                        .into_response()
                                }
                            },
                            Err(e) => {
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({"error": e.to_string()})),
                                )
                                    .into_response()
                            }
                        }
                    } else if field_name == "it_archive" {
                        match field.bytes().await {
                            Ok(bytes) => match state.cas.put_blob(&bytes).await {
                                Ok(d) => it_archive_digest = d.to_string(),
                                Err(e) => {
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(serde_json::json!({"error": e.to_string()})),
                                    )
                                        .into_response()
                                }
                            },
                            Err(e) => {
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({"error": e.to_string()})),
                                )
                                    .into_response()
                            }
                        }
                    } else if field_name == "binary_digest" {
                        binary_digest = field.text().await.unwrap_or_default();
                    } else if field_name == "it_archive_digest" {
                        it_archive_digest = field.text().await.unwrap_or_default();
                    } else if field_name == "trace_id" {
                        let t = field.text().await.unwrap_or_default();
                        if !t.trim().is_empty() {
                            explicit_trace_id = Some(t);
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            }
        }
    } else {
        // Assume JSON
        let bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        };
        let parsed: CreateBundleJsonRequest = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        };
        service_name = parsed.service_name;
        binary_digest = parsed.binary_digest;
        it_archive_digest = parsed.it_archive_digest;
        explicit_trace_id = parsed.trace_id;
    }

    if service_name.trim().is_empty()
        || binary_digest.trim().is_empty()
        || it_archive_digest.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing_fields",
                "message": "service_name, binary_digest, and it_archive_digest are required"
            })),
        )
            .into_response();
    }

    let resolved_trace_id = match explicit_trace_id {
        Some(raw) => match validate_w3c_trace_id(&raw) {
            Ok(valid) => Some(valid),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_trace_id",
                        "message": e.to_string()
                    })),
                )
                    .into_response()
            }
        },
        None => extract_trace_id_from_headers(&headers),
    };

    let bundle_id = format!("bundle-{}", Uuid::new_v4());
    let now = Utc::now().timestamp_millis();
    let bundle = CanaryBundleRecord {
        bundle_id: bundle_id.clone(),
        service_name: service_name.clone(),
        binary_digest: binary_digest.clone(),
        it_archive_digest: it_archive_digest.clone(),
        status: "testing".to_string(),
        created_at: now,
        updated_at: now,
        trace_id: resolved_trace_id,
    };

    if let Err(e) = state.catalog.insert_canary_bundle(&bundle) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    (StatusCode::CREATED, Json(bundle)).into_response()
}

async fn get_bundle_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<String>,
    Query(query): Query<BundleDownloadQuery>,
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
    if !auth.has_scope(TokenScope::Read) && !auth.has_scope(TokenScope::CanaryManage) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires read or canary:manage scope"
            })),
        )
            .into_response();
    }

    let bundle = match state.catalog.get_canary_bundle(&id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "bundle not found"})),
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
    };

    match query.download.as_deref() {
        Some("binary") => match state.cas.get_blob(&bundle.binary_digest).await {
            Ok(bytes) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                headers.insert(
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_str(&format!(
                        "attachment; filename=\"{}-bin\"",
                        bundle.service_name
                    ))
                    .unwrap(),
                );
                (StatusCode::OK, headers, bytes).into_response()
            }
            Err(e) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "blob_not_found",
                    "digest": bundle.binary_digest,
                    "detail": e.to_string()
                })),
            )
                .into_response(),
        },
        Some("archive") | Some("it_archive") => {
            match state.cas.get_blob(&bundle.it_archive_digest).await {
                Ok(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/gzip"),
                    );
                    headers.insert(
                        header::CONTENT_DISPOSITION,
                        HeaderValue::from_str(&format!(
                            "attachment; filename=\"{}-it.tar.gz\"",
                            bundle.service_name
                        ))
                        .unwrap(),
                    );
                    (StatusCode::OK, headers, bytes).into_response()
                }
                Err(e) => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "blob_not_found",
                        "digest": bundle.it_archive_digest,
                        "detail": e.to_string()
                    })),
                )
                    .into_response(),
            }
        }
        _ => (StatusCode::OK, Json(bundle)).into_response(),
    }
}

async fn promote_canary_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(digest): Path<String>,
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
    if !auth.has_scope(TokenScope::CanaryManage) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires canary:manage scope"
            })),
        )
            .into_response();
    }

    match state.catalog.is_digest_tainted(&digest) {
        Ok(true) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "cannot_promote_tainted",
                "message": format!("Digest {digest} is tainted and cannot be promoted")
            })),
        )
            .into_response(),
        Ok(false) => {
            if let Err(e) = state
                .catalog
                .update_bundle_status_by_binary_digest(&digest, "healthy")
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "healthy",
                    "digest": digest
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn taint_canary_handler(
    State(state): State<AppState>,
    auth: AuthContext,
    headers: HeaderMap,
    Path(digest): Path<String>,
    Json(payload): Json<Option<TaintRequest>>,
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
    if !auth.has_scope(TokenScope::CanaryManage) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "Requires canary:manage scope"
            })),
        )
            .into_response();
    }

    let p = payload.unwrap_or(TaintRequest {
        service_name: None,
        node_id: None,
        reason: None,
        trace_id: None,
    });

    let resolved_trace_id = match p.trace_id {
        Some(raw) => match validate_w3c_trace_id(&raw) {
            Ok(valid) => Some(valid),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_trace_id",
                        "message": e.to_string()
                    })),
                )
                    .into_response()
            }
        },
        None => extract_trace_id_from_headers(&headers),
    };

    let service = p
        .service_name
        .unwrap_or_else(|| "unknown-service".to_string());
    let node = p.node_id.unwrap_or_else(|| "worker-node".to_string());
    let reason = p
        .reason
        .unwrap_or_else(|| "Integration test failure / timeout".to_string());

    if let Err(e) = state.catalog.taint_digest_with_trace(
        &digest,
        &service,
        &node,
        &reason,
        resolved_trace_id.as_deref(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "tainted",
            "digest": digest,
            "reason": reason,
            "trace_id": resolved_trace_id
        })),
    )
        .into_response()
}

async fn get_canary_status_handler(State(state): State<AppState>) -> Response {
    let summary = match state.catalog.get_canary_status_summary() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let mut headers = HeaderMap::new();
    let status_val = HeaderValue::from_str(&summary.status)
        .unwrap_or_else(|_| HeaderValue::from_static("healthy"));
    headers.insert("canary-repository", status_val);

    (StatusCode::OK, headers, Json(summary)).into_response()
}
