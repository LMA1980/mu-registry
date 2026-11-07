use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use mu_registry::{
    api::build_app_router, auth::hash_token_sha256, encode_publish_frame, AppConfig, AppState,
    CasStore, DuckDbCatalog, TokenScope,
};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_cargo_publish_wire_framing_and_rejections() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let publish_token = "pub-token-secret";
    let read_token = "read-token-secret";

    catalog
        .insert_api_token(
            "pub-tok",
            &hash_token_sha256(publish_token),
            &[TokenScope::Publish],
        )
        .unwrap();

    catalog
        .insert_api_token(
            "read-tok",
            &hash_token_sha256(read_token),
            &[TokenScope::Read],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    let metadata_json = serde_json::json!({
        "name": "wire-pkg",
        "vers": "1.0.0",
        "deps": [
            {
                "name": "tokio",
                "version_req": "^1.0",
                "features": ["macros"],
                "optional": false,
                "default_features": true,
                "kind": "normal"
            }
        ],
        "features": {
            "default": []
        },
        "description": "Wire test crate"
    });
    let metadata_bytes = serde_json::to_vec(&metadata_json).unwrap();
    let tarball_bytes = b"wire-test-tarball-content-1.0.0";
    let frame = encode_publish_frame(&metadata_bytes, tarball_bytes);

    // 1. Unauthenticated publish -> 401 Unauthorized
    let unauth_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .body(Body::from(frame.clone()))
        .unwrap();
    let unauth_res = app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

    // 2. Read-only token publish -> 403 Forbidden
    let forbidden_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {read_token}"))
        .body(Body::from(frame.clone()))
        .unwrap();
    let forbidden_res = app.clone().oneshot(forbidden_req).await.unwrap();
    assert_eq!(forbidden_res.status(), StatusCode::FORBIDDEN);

    // 3. Valid publish with publish token -> 200 OK
    let ok_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {publish_token}"))
        .body(Body::from(frame.clone()))
        .unwrap();
    let ok_res = app.clone().oneshot(ok_req).await.unwrap();
    assert_eq!(ok_res.status(), StatusCode::OK);
    let ok_body = ok_res.into_body().collect().await.unwrap().to_bytes();
    let resp_json: serde_json::Value = serde_json::from_slice(&ok_body).unwrap();
    assert!(resp_json["warnings"].is_object());

    // 4. Duplicate publish -> 409 Conflict
    let dup_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {publish_token}"))
        .body(Body::from(frame.clone()))
        .unwrap();
    let dup_res = app.clone().oneshot(dup_req).await.unwrap();
    assert_eq!(dup_res.status(), StatusCode::CONFLICT);
    let dup_body = dup_res.into_body().collect().await.unwrap().to_bytes();
    let dup_json: serde_json::Value = serde_json::from_slice(&dup_body).unwrap();
    assert!(dup_json["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("already exists"));

    // 5. Malformed payload -> 400 Bad Request
    let bad_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {publish_token}"))
        .body(Body::from(vec![1, 2, 3]))
        .unwrap();
    let bad_res = app.clone().oneshot(bad_req).await.unwrap();
    assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);

    // 6. Verify CAS storage of tarball
    let versions = catalog.get_crate_versions("wire-pkg").unwrap();
    assert_eq!(versions.len(), 1);
    let cksum = &versions[0].cksum;
    let stored_bytes = cas.get_blob(cksum).await.unwrap();
    assert_eq!(stored_bytes, tarball_bytes);
}
