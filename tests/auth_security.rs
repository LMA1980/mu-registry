use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mu_registry::{
    api::build_app_router, auth::hash_token_sha256, encode_publish_frame, AppConfig, AppState,
    CasStore, DuckDbCatalog, TokenScope,
};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_auth_security_enforcement() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let read_token = "tok-read-only";
    let publish_token = "tok-publish-only";
    let canary_token = "tok-canary-only";

    catalog
        .insert_api_token("r-tok", &hash_token_sha256(read_token), &[TokenScope::Read])
        .unwrap();

    catalog
        .insert_api_token(
            "p-tok",
            &hash_token_sha256(publish_token),
            &[TokenScope::Publish],
        )
        .unwrap();

    catalog
        .insert_api_token(
            "c-tok",
            &hash_token_sha256(canary_token),
            &[TokenScope::CanaryManage],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    let dummy_frame = encode_publish_frame(b"{}", b"");

    // 1. Missing credentials -> 401 Unauthorized
    let unauth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/new")
                .method("PUT")
                .body(Body::from(dummy_frame.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid bearer token -> 401 Unauthorized
    let invalid_tok_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/new")
                .method("PUT")
                .header(header::AUTHORIZATION, "Bearer invalid-token-value")
                .body(Body::from(dummy_frame.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_tok_res.status(), StatusCode::UNAUTHORIZED);

    // 3. Read-only token attempting publish -> 403 Forbidden
    let ro_pub_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/new")
                .method("PUT")
                .header(header::AUTHORIZATION, format!("Bearer {read_token}"))
                .body(Body::from(dummy_frame.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ro_pub_res.status(), StatusCode::FORBIDDEN);

    // 4. Read-only token attempting canary taint -> 403 Forbidden
    let ro_taint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/fake-digest/taint")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {read_token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ro_taint_res.status(), StatusCode::FORBIDDEN);

    // 5. Canary token attempting canary taint -> 200 OK
    let c_taint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/taint")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(c_taint_res.status(), StatusCode::OK);

    // 6. Valid mTLS client cert SAN header grants access -> 200 OK
    let mtls_taint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210/taint")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-client-cert-san", "registry.ci.ci.internal")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mtls_taint_res.status(), StatusCode::OK);
}
