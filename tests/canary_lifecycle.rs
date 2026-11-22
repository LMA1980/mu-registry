use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use mu_registry::{
    api::build_app_router, auth::hash_token_sha256, AppConfig, AppState, CasStore, DuckDbCatalog,
    TokenScope,
};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_canary_bundle_lifecycle_promote_and_taint() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let canary_token = "canary-mgr-token";
    catalog
        .insert_api_token(
            "canary-mgr",
            &hash_token_sha256(canary_token),
            &[TokenScope::CanaryManage, TokenScope::Read],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    // Initial status should default to healthy
    let status_init = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_init.status(), StatusCode::OK);
    assert_eq!(
        status_init.headers().get("canary-repository").unwrap(),
        "healthy"
    );

    // 1. Ingest candidate service binary and integration test archive
    let binary_bytes = b"binary-executable-artifact-content-v1";
    let it_bytes = b"it-test-archive-bundle-tarball-content-v1";

    let bin_digest = cas.put_blob(binary_bytes).await.unwrap();
    let it_digest = cas.put_blob(it_bytes).await.unwrap();

    let bundle_payload = serde_json::json!({
        "service_name": "worker-service",
        "binary_digest": bin_digest.as_str(),
        "it_archive_digest": it_digest.as_str()
    });

    let ingest_req = Request::builder()
        .uri("/api/v1/bundles/it")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::from(serde_json::to_vec(&bundle_payload).unwrap()))
        .unwrap();
    let ingest_res = app.clone().oneshot(ingest_req).await.unwrap();
    assert_eq!(ingest_res.status(), StatusCode::CREATED);
    let ingest_body = ingest_res.into_body().collect().await.unwrap().to_bytes();
    let bundle_obj: serde_json::Value = serde_json::from_slice(&ingest_body).unwrap();
    let bundle_id = bundle_obj["bundle_id"].as_str().unwrap().to_string();
    assert_eq!(bundle_obj["status"], "testing");

    // 2. Query /api/v1/canary/status -> reflects canary-repository: testing
    let status_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);
    assert_eq!(
        status_res.headers().get("canary-repository").unwrap(),
        "testing"
    );
    let status_body = status_res.into_body().collect().await.unwrap().to_bytes();
    let status_obj: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
    assert_eq!(status_obj["status"], "testing");
    assert_eq!(status_obj["active_canary_digest"], bin_digest.as_str());

    // 3. Download bundle metadata and CAS payloads
    let meta_req = Request::builder()
        .uri(format!("/api/v1/bundles/it/{bundle_id}"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::empty())
        .unwrap();
    let meta_res = app.clone().oneshot(meta_req).await.unwrap();
    assert_eq!(meta_res.status(), StatusCode::OK);

    let bin_dl_req = Request::builder()
        .uri(format!("/api/v1/bundles/it/{bundle_id}?download=binary"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::empty())
        .unwrap();
    let bin_dl_res = app.clone().oneshot(bin_dl_req).await.unwrap();
    assert_eq!(bin_dl_res.status(), StatusCode::OK);
    let dl_bin_bytes = bin_dl_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(dl_bin_bytes.as_ref(), binary_bytes);

    let it_dl_req = Request::builder()
        .uri(format!("/api/v1/bundles/it/{bundle_id}?download=archive"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::empty())
        .unwrap();
    let it_dl_res = app.clone().oneshot(it_dl_req).await.unwrap();
    assert_eq!(it_dl_res.status(), StatusCode::OK);
    let dl_it_bytes = it_dl_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(dl_it_bytes.as_ref(), it_bytes);

    // 4. Taint digest via POST /api/v1/canary/{digest}/taint
    let taint_payload = serde_json::json!({
        "service_name": "worker-service",
        "node_id": "node-a",
        "reason": "Integration test failed: assert exit code 0"
    });
    let taint_req = Request::builder()
        .uri(format!("/api/v1/canary/{}/taint", bin_digest.as_str()))
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::from(serde_json::to_vec(&taint_payload).unwrap()))
        .unwrap();
    let taint_res = app.clone().oneshot(taint_req).await.unwrap();
    assert_eq!(taint_res.status(), StatusCode::OK);

    // Status now reflects canary-repository: tainted
    let status_tainted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        status_tainted.headers().get("canary-repository").unwrap(),
        "tainted"
    );
    let st_body = status_tainted
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let st_obj: serde_json::Value = serde_json::from_slice(&st_body).unwrap();
    assert_eq!(st_obj["status"], "tainted");
    assert_eq!(st_obj["tainted_count"], 1);

    // 5. Attempt promotion on tainted digest -> must be rejected with 409 Conflict
    let rej_prom_req = Request::builder()
        .uri(format!("/api/v1/canary/{}/promote", bin_digest.as_str()))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::empty())
        .unwrap();
    let rej_prom_res = app.clone().oneshot(rej_prom_req).await.unwrap();
    assert_eq!(rej_prom_res.status(), StatusCode::CONFLICT);

    // 6. Ingest second candidate bundle and promote
    let binary_bytes2 = b"binary-executable-artifact-content-v2";
    let it_bytes2 = b"it-test-archive-bundle-tarball-content-v2";
    let bin_digest2 = cas.put_blob(binary_bytes2).await.unwrap();
    let it_digest2 = cas.put_blob(it_bytes2).await.unwrap();

    let bundle_payload2 = serde_json::json!({
        "service_name": "worker-service",
        "binary_digest": bin_digest2.as_str(),
        "it_archive_digest": it_digest2.as_str()
    });
    let ingest2_req = Request::builder()
        .uri("/api/v1/bundles/it")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::from(serde_json::to_vec(&bundle_payload2).unwrap()))
        .unwrap();
    let ingest2_res = app.clone().oneshot(ingest2_req).await.unwrap();
    assert_eq!(ingest2_res.status(), StatusCode::CREATED);

    let promote_req = Request::builder()
        .uri(format!("/api/v1/canary/{}/promote", bin_digest2.as_str()))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
        .body(Body::empty())
        .unwrap();
    let promote_res = app.clone().oneshot(promote_req).await.unwrap();
    assert_eq!(promote_res.status(), StatusCode::OK);

    // Final status reflects healthy
    let status_healthy = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canary/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        status_healthy.headers().get("canary-repository").unwrap(),
        "healthy"
    );
    let h_body = status_healthy
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let h_obj: serde_json::Value = serde_json::from_slice(&h_body).unwrap();
    assert_eq!(h_obj["status"], "healthy");
    assert_eq!(h_obj["last_promoted_digest"], bin_digest2.as_str());
}

fn build_multipart_bundle_body(
    boundary: &str,
    service_name: &str,
    binary_bytes: &[u8],
    it_archive_bytes: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(binary_bytes.len() + it_archive_bytes.len() + 512);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"service_name\"\r\n\r\n{service_name}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"service.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(binary_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"it_archive\"; filename=\"it.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(it_archive_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test]
async fn test_multipart_bundle_upload_exceeding_2mib_succeeds_and_stores_exact_digests() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.example.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let token = "large-bundle-upload-token";
    catalog
        .insert_api_token(
            "ci-publisher",
            &hash_token_sha256(token),
            &[TokenScope::CanaryManage, TokenScope::Read],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    // Build a >3 MiB multipart payload (2.5 MiB binary + 0.6 MiB IT archive), exceeding Axum's
    // default 2 MiB DefaultBodyLimit.
    let binary_bytes: Vec<u8> = (0..(2_560 * 1024)).map(|i| (i % 251) as u8).collect();
    let it_archive_bytes: Vec<u8> = (0..(640 * 1024)).map(|i| ((i * 7) % 239) as u8).collect();
    let expected_bin_digest = mu_registry::Sha256Digest::from_bytes(&binary_bytes);
    let expected_it_digest = mu_registry::Sha256Digest::from_bytes(&it_archive_bytes);

    let boundary = "----muRegistryLargeBundleBoundary77";
    let multipart_body =
        build_multipart_bundle_body(boundary, "worker-service", &binary_bytes, &it_archive_bytes);
    assert!(multipart_body.len() > 3 * 1024 * 1024);

    let upload_req = Request::builder()
        .uri("/api/v1/bundles/it")
        .method("POST")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(multipart_body))
        .unwrap();
    let upload_res = app.clone().oneshot(upload_req).await.unwrap();
    assert_eq!(upload_res.status(), StatusCode::CREATED);

    let body_bytes = upload_res.into_body().collect().await.unwrap().to_bytes();
    let bundle_obj: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(bundle_obj["service_name"], "worker-service");
    assert_eq!(bundle_obj["binary_digest"], expected_bin_digest.as_str());
    assert_eq!(bundle_obj["it_archive_digest"], expected_it_digest.as_str());
    assert_eq!(bundle_obj["status"], "testing");

    // Verify CAS blobs round-trip identically by stored SHA-256 digest
    let stored_bin = cas.get_blob(&expected_bin_digest).await.unwrap();
    assert_eq!(stored_bin, binary_bytes);
    let stored_it = cas.get_blob(&expected_it_digest).await.unwrap();
    assert_eq!(stored_it, it_archive_bytes);
}

#[tokio::test]
async fn test_bundle_body_limits_reject_oversized_multipart_json_and_other_routes_with_413() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.example.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let token = "body-limit-check-token";
    catalog
        .insert_api_token(
            "ci-publisher",
            &hash_token_sha256(token),
            &[TokenScope::CanaryManage, TokenScope::Read],
        )
        .unwrap();

    let state = AppState {
        config,
        cas,
        catalog,
    };
    let app = build_app_router(state.clone());

    // 1. JSON payload > 1 MiB on POST /api/v1/bundles/it must fail closed with 413 Payload Too Large.
    let oversized_json = format!(
        r#"{{"service_name":"{}","binary_digest":"sha256:aaa","it_archive_digest":"sha256:bbb"}}"#,
        "a".repeat(1024 * 1024 + 1024)
    );
    let json_req = Request::builder()
        .uri("/api/v1/bundles/it")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(oversized_json))
        .unwrap();
    let json_res = app.clone().oneshot(json_req).await.unwrap();
    assert_eq!(json_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 2. Unrelated route (POST /api/v1/canary/{digest}/taint) keeps Axum's default 2 MiB cap.
    let oversized_taint_json = format!(
        r#"{{"service_name":"worker-service","reason":"{}"}}"#,
        "x".repeat(2 * 1024 * 1024 + 4096)
    );
    let taint_req = Request::builder()
        .uri("/api/v1/canary/sha256:0000000000000000000000000000000000000000000000000000000000000000/taint")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(oversized_taint_json))
        .unwrap();
    let taint_res = app.oneshot(taint_req).await.unwrap();
    assert_eq!(taint_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 3. Multipart upload exceeding the route's DefaultBodyLimit must return 413 Payload Too Large
    //    rather than 500 Internal Server Error.
    let tight_router =
        mu_registry::api::canary::canary_router_with_bundle_limit(64 * 1024).with_state(state);
    let boundary = "----muRegistryTightLimitBoundary";
    let body =
        build_multipart_bundle_body(boundary, "worker-service", &vec![b'B'; 96 * 1024], b"it");
    let tight_req = Request::builder()
        .uri("/api/v1/bundles/it")
        .method("POST")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap();
    let tight_res = tight_router.oneshot(tight_req).await.unwrap();
    assert_eq!(tight_res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
