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
async fn test_sparse_index_lifecycle() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    // Insert admin token with publish, yank, read scopes
    let raw_token = "secret-token-admin";
    let token_hash = hash_token_sha256(raw_token);
    catalog
        .insert_api_token(
            "admin-tok",
            &token_hash,
            &[TokenScope::Publish, TokenScope::Yank, TokenScope::Read],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    // 1. GET /config.json
    let req = Request::builder()
        .uri("/config.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let cfg_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        cfg_val["dl"],
        "https://registry.ci.ci.internal:8444/api/v1/crates"
    );
    assert_eq!(cfg_val["api"], "https://registry.ci.ci.internal:8444");

    // 2. Publish a crate via PUT /api/v1/crates/new
    let metadata_json = serde_json::json!({
        "name": "sample-crate",
        "vers": "0.1.0",
        "deps": [
            {
                "name": "serde",
                "version_req": "^1.0",
                "features": ["derive"],
                "optional": false,
                "default_features": true
            }
        ],
        "features": {
            "default": ["std"]
        },
        "description": "Sample crate description",
        "links": null
    });
    let metadata_bytes = serde_json::to_vec(&metadata_json).unwrap();
    let tarball_bytes = b"tarball-payload-for-sample-crate-0.1.0";
    let frame = encode_publish_frame(&metadata_bytes, tarball_bytes);

    let pub_req = Request::builder()
        .uri("/api/v1/crates/new")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
        .body(Body::from(frame))
        .unwrap();
    let pub_res = app.clone().oneshot(pub_req).await.unwrap();
    assert_eq!(pub_res.status(), StatusCode::OK);

    // 3. Query index via GET /index/sa/mp/sample-crate
    let idx_req = Request::builder()
        .uri("/index/sa/mp/sample-crate")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let idx_res = app.clone().oneshot(idx_req).await.unwrap();
    assert_eq!(idx_res.status(), StatusCode::OK);

    // Verify Cache-Control and ETag
    let cache_control = idx_res
        .headers()
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cache_control, "no-cache, must-revalidate");
    let etag = idx_res
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(etag.contains("sha256:"));

    let idx_body = idx_res.into_body().collect().await.unwrap().to_bytes();
    let idx_str = String::from_utf8(idx_body.to_vec()).unwrap();
    let entry_val: serde_json::Value = serde_json::from_str(idx_str.trim()).unwrap();
    assert_eq!(entry_val["name"], "sample-crate");
    assert_eq!(entry_val["vers"], "0.1.0");
    assert_eq!(entry_val["yanked"], false);
    assert_eq!(entry_val["v"], 2);

    // 4. Test 304 Not Modified when If-None-Match matches
    let inm_req = Request::builder()
        .uri("/index/sa/mp/sample-crate")
        .method("GET")
        .header(header::IF_NONE_MATCH, &etag)
        .body(Body::empty())
        .unwrap();
    let inm_res = app.clone().oneshot(inm_req).await.unwrap();
    assert_eq!(inm_res.status(), StatusCode::NOT_MODIFIED);

    // 5. Download crate blob via GET /api/v1/crates/sample-crate/0.1.0/download
    let dl_req = Request::builder()
        .uri("/api/v1/crates/sample-crate/0.1.0/download")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let dl_res = app.clone().oneshot(dl_req).await.unwrap();
    assert_eq!(dl_res.status(), StatusCode::OK);
    assert_eq!(
        dl_res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/x-tar"
    );
    let dl_bytes = dl_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(dl_bytes.as_ref(), tarball_bytes);

    // 6. Yank version via DELETE /api/v1/crates/sample-crate/0.1.0/yank
    let yank_req = Request::builder()
        .uri("/api/v1/crates/sample-crate/0.1.0/yank")
        .method("DELETE")
        .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
        .body(Body::empty())
        .unwrap();
    let yank_res = app.clone().oneshot(yank_req).await.unwrap();
    assert_eq!(yank_res.status(), StatusCode::OK);

    // Verify index now reflects yanked = true
    let idx_after_yank = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/sa/mp/sample-crate")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let idx_yank_str = String::from_utf8(
        idx_after_yank
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let yank_val: serde_json::Value = serde_json::from_str(idx_yank_str.trim()).unwrap();
    assert_eq!(yank_val["yanked"], true);

    // 7. Unyank version via PUT /api/v1/crates/sample-crate/0.1.0/unyank
    let unyank_req = Request::builder()
        .uri("/api/v1/crates/sample-crate/0.1.0/unyank")
        .method("PUT")
        .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
        .body(Body::empty())
        .unwrap();
    let unyank_res = app.clone().oneshot(unyank_req).await.unwrap();
    assert_eq!(unyank_res.status(), StatusCode::OK);

    // Verify index again reflects yanked = false
    let idx_after_unyank = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/sa/mp/sample-crate")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let idx_unyank_str = String::from_utf8(
        idx_after_unyank
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let unyank_val: serde_json::Value = serde_json::from_str(idx_unyank_str.trim()).unwrap();
    assert_eq!(unyank_val["yanked"], false);
}
