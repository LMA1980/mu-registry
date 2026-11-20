pub mod canary;

use crate::api::canary::AppState;
use crate::frontend::cargo::CargoSparseFrontend;
use crate::frontend::{Maven2Frontend, NuGetV3Frontend, RegistryFrontend};
use crate::storage::catalog::CatalogError;
use crate::telemetry::registry_telemetry_middleware;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::get,
    Json, Router,
};
use futures_util::stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;

pub use canary::canary_router;

#[derive(Debug, Default, Deserialize)]
pub struct PublicPackagesQuery {
    pub ecosystem: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Assembles all routes across Frontends and APIs into a unified Axum Router
/// instrumented with OpenTelemetry W3C-traced span and audit log middleware.
pub fn build_app_router(state: AppState) -> Router {
    let cargo_fe = CargoSparseFrontend;
    let nuget_fe = NuGetV3Frontend;
    let maven_fe = Maven2Frontend;

    Router::new()
        .merge(cargo_fe.router())
        .merge(nuget_fe.router())
        .merge(maven_fe.router())
        .merge(canary_router())
        .merge(readonly_registry_router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            registry_telemetry_middleware,
        ))
        .with_state(state)
}

pub fn readonly_registry_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(registry_health_handler))
        .route("/api/health", get(registry_health_handler))
        .route("/api/v1/cas/health", get(registry_health_handler))
        .route("/api/v1/packages", get(list_public_packages_handler))
        .route(
            "/api/v1/console/packages",
            get(list_public_packages_handler),
        )
        .route(
            "/api/v1/registry/crates",
            get(list_crates_paginated_handler),
        )
        .route(
            "/api/v1/registry/crates/{name}",
            get(get_crate_detail_handler),
        )
        .route("/api/v1/canaries", get(get_sanitized_canaries_handler))
        .route(
            "/api/v1/console/canaries",
            get(get_sanitized_canaries_handler),
        )
        .route(
            "/api/v1/registry/bundles",
            get(list_registry_bundles_handler),
        )
        .route("/api/v1/registry/taints", get(list_registry_taints_handler))
        .route("/api/v1/cas/status", get(get_cas_status_handler))
        .route("/api/v1/console/cas", get(get_cas_status_handler))
        .route(
            "/api/v1/registry/overview",
            get(get_registry_overview_handler),
        )
        .route("/api/v1/registry/events", get(registry_events_sse_handler))
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

async fn list_public_packages_handler(
    State(state): State<AppState>,
    Query(query): Query<PublicPackagesQuery>,
) -> Response {
    let filter_raw = query.ecosystem.as_deref();
    let packages = match state.catalog.list_public_packages(filter_raw) {
        Ok(list) => list,
        Err(CatalogError::InvalidEcosystem(bad)) => {
            return (
                StatusCode::BAD_REQUEST,
                no_store_headers(),
                Json(serde_json::json!({
                    "error": "invalid_ecosystem",
                    "message": format!("Unsupported ecosystem '{bad}'; expected all, cargo, nuget, or maven")
                })),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let total = packages.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(500).clamp(1, 500);
    let paged: Vec<_> = packages.into_iter().skip(offset).take(limit).collect();
    let eco_label = filter_raw
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "all".to_string());

    (
        StatusCode::OK,
        no_store_headers(),
        Json(serde_json::json!({
            "ecosystem": eco_label,
            "total": total,
            "packages": paged
        })),
    )
        .into_response()
}

async fn list_crates_paginated_handler(
    State(state): State<AppState>,
    Query(query): Query<PublicPackagesQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);

    match state.catalog.list_crates_paginated(limit, offset) {
        Ok(crates) => (
            StatusCode::OK,
            no_store_headers(),
            Json(serde_json::json!({
                "total": crates.len(),
                "limit": limit,
                "offset": offset,
                "crates": crates,
                "packages": crates
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_crate_detail_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    match state.catalog.get_crate_detail(&name) {
        Ok(Some(detail)) => (StatusCode::OK, no_store_headers(), Json(detail)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(serde_json::json!({
                "error": "crate_not_found",
                "message": format!("Crate '{name}' not found")
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_sanitized_canaries_handler(State(state): State<AppState>) -> Response {
    let summary = match state.catalog.get_canary_status_summary() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let bundles = match state.catalog.list_sanitized_canary_bundles() {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let taints = match state.catalog.list_sanitized_tainted_digests() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    (
        StatusCode::OK,
        no_store_headers(),
        Json(serde_json::json!({
            "status": summary,
            "bundles": bundles,
            "taints": taints
        })),
    )
        .into_response()
}

async fn list_registry_bundles_handler(State(state): State<AppState>) -> Response {
    match state.catalog.list_sanitized_canary_bundles() {
        Ok(bundles) => (
            StatusCode::OK,
            no_store_headers(),
            Json(serde_json::json!({
                "total": bundles.len(),
                "bundles": bundles
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_registry_taints_handler(State(state): State<AppState>) -> Response {
    match state.catalog.list_sanitized_tainted_digests() {
        Ok(taints) => (
            StatusCode::OK,
            no_store_headers(),
            Json(serde_json::json!({
                "total": taints.len(),
                "taints": taints
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn registry_health_handler(State(state): State<AppState>) -> Response {
    match state.cas.storage_health_summary().await {
        Ok(summary) => {
            let status_code = if summary.healthy {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let status_label = if summary.healthy { "ok" } else { "degraded" };
            (
                status_code,
                no_store_headers(),
                Json(serde_json::json!({
                    "status": status_label,
                    "service": "mu-registry",
                    "version": env!("CARGO_PKG_VERSION"),
                    "healthy": summary.healthy,
                    "total_blobs": summary.total_blobs,
                    "total_bytes": summary.total_bytes,
                    "corrupted_blobs": summary.corrupted_blobs
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({
                "status": "unhealthy",
                "healthy": false,
                "error": e.to_string()
            })),
        )
            .into_response(),
    }
}

async fn get_cas_status_handler(State(state): State<AppState>) -> Response {
    match state.cas.storage_health_summary().await {
        Ok(summary) => (StatusCode::OK, no_store_headers(), Json(summary)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_registry_overview_handler(State(state): State<AppState>) -> Response {
    let cas_summary = match state.cas.storage_summary().await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let catalog_counts = match state.catalog.get_catalog_overview_counts() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    (
        StatusCode::OK,
        no_store_headers(),
        Json(serde_json::json!({
            "cas": cas_summary,
            "catalog": catalog_counts,
            "total_blobs": cas_summary.total_blobs,
            "total_bytes": cas_summary.total_bytes,
            "dedup_ratio_bps": cas_summary.dedup_ratio_bps,
            "dedup_savings_bytes": cas_summary.dedup_savings_bytes,
            "healthy": cas_summary.healthy,
            "total_packages": catalog_counts.total_packages,
            "total_crates": catalog_counts.total_crates,
            "total_versions": catalog_counts.total_versions,
            "total_bundles": catalog_counts.total_bundles,
            "tainted_digests_count": catalog_counts.tainted_digests_count
        })),
    )
        .into_response()
}

async fn registry_events_sse_handler(State(state): State<AppState>) -> Response {
    let rx = state.catalog.subscribe_events();
    let event_stream = stream::unfold((rx, false), |(mut rx, sent_init)| async move {
        if !sent_init {
            let init_ev = Event::default()
                .event("connected")
                .data("{\"status\":\"connected\"}");
            return Some((Ok::<Event, Infallible>(init_ev), (rx, true)));
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(15), rx.recv()).await {
                Ok(Ok(ev)) => {
                    let payload = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
                    let sse_ev = Event::default().event(ev.event_type).data(payload);
                    return Some((Ok::<Event, Infallible>(sse_ev), (rx, true)));
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return None,
                Err(_) => {
                    let hb = Event::default()
                        .event("heartbeat")
                        .data("{\"type\":\"heartbeat\"}");
                    return Some((Ok::<Event, Infallible>(hb), (rx, true)));
                }
            }
        }
    });

    let sse = Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    );

    let mut resp = sse.into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
