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
async fn test_m6_public_packages_listing_and_ecosystem_filtering() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let publish_token = "m6-publish-token";
    catalog
        .insert_api_token(
            "m6-pub",
            &hash_token_sha256(publish_token),
            &[
                TokenScope::Publish,
                TokenScope::Yank,
                TokenScope::CanaryManage,
                TokenScope::Read,
            ],
        )
        .unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    // Publish a Cargo crate via PUT /api/v1/crates/new
    let metadata_json = serde_json::json!({
        "name": "k3-runtime",
        "vers": "0.3.0",
        "deps": [
            {
                "name": "tokio",
                "version_req": "^1.0",
                "features": ["rt"],
                "optional": false,
                "default_features": true,
                "kind": "normal"
            },
            {
                "name": "serde",
                "version_req": "^1.0",
                "features": ["derive"],
                "optional": false,
                "default_features": true,
                "kind": "normal"
            }
        ],
        "features": {
            "default": ["rvv"]
        },
        "description": "K3 runtime library stored under /var/lib/muregist/crates",
        "repository": "https://github.com/LMA1980/k3-runtime"
    });
    let tarball_bytes = b"k3-runtime-0.3.0-tarball-payload";
    let frame = encode_publish_frame(&serde_json::to_vec(&metadata_json).unwrap(), tarball_bytes);

    let pub_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/new")
                .method("PUT")
                .header(header::AUTHORIZATION, format!("Bearer {publish_token}"))
                .body(Body::from(frame))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_res.status(), StatusCode::OK);

    // Seed NuGet and Maven packages in catalog
    catalog
        .insert_ecosystem_package(
            "nuget",
            "MuRegist.Sdk",
            "1.2.0",
            "1111111111111111111111111111111111111111111111111111111111111111",
            3,
            false,
            Some("NuGet SDK package"),
            Some("https://github.com/LMA1980/MuRegist"),
        )
        .unwrap();
    catalog
        .insert_ecosystem_package(
            "maven",
            "io.k3:muregist-maven-plugin",
            "2.0.1",
            "2222222222222222222222222222222222222222222222222222222222222222",
            1,
            false,
            Some("Maven plugin artifact"),
            None,
        )
        .unwrap();

    // 1. GET /api/v1/packages (default all ecosystems)
    let all_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/packages")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(all_res.status(), StatusCode::OK);
    assert_eq!(
        all_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let all_body = all_res.into_body().collect().await.unwrap().to_bytes();
    let all_json: serde_json::Value = serde_json::from_slice(&all_body).unwrap();
    assert_eq!(all_json["total"], 3);
    let pkgs = all_json["packages"].as_array().unwrap();
    assert_eq!(pkgs.len(), 3);
    // Deterministic sorting by (ecosystem ASC, name ASC): cargo, maven, nuget
    assert_eq!(pkgs[0]["ecosystem"], "cargo");
    assert_eq!(pkgs[0]["name"], "k3-runtime");
    assert_eq!(pkgs[0]["latest_version"], "0.3.0");
    assert_eq!(pkgs[0]["versions_count"], 1);
    assert_eq!(pkgs[0]["dependency_count"], 2);
    assert_eq!(pkgs[0]["yanked"], false);
    assert_eq!(pkgs[0]["tainted"], false);
    // Verify internal path /var/lib/muregist/crates was scrubbed
    assert!(!pkgs[0]["description"]
        .as_str()
        .unwrap()
        .contains("/var/lib/muregist"));

    assert_eq!(pkgs[1]["ecosystem"], "maven");
    assert_eq!(pkgs[1]["name"], "io.k3:muregist-maven-plugin");
    assert_eq!(pkgs[2]["ecosystem"], "nuget");
    assert_eq!(pkgs[2]["name"], "MuRegist.Sdk");

    // 2. GET /api/v1/packages?ecosystem=cargo
    let cargo_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/packages?ecosystem=cargo")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cargo_res.status(), StatusCode::OK);
    let cargo_body = cargo_res.into_body().collect().await.unwrap().to_bytes();
    let cargo_json: serde_json::Value = serde_json::from_slice(&cargo_body).unwrap();
    assert_eq!(cargo_json["total"], 1);
    assert_eq!(cargo_json["packages"][0]["name"], "k3-runtime");

    // 3. GET /api/v1/packages?ecosystem=unknown -> 400 Bad Request
    let bad_eco_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/packages?ecosystem=rubygems")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_eco_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        bad_eco_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    // 4. GET /api/v1/registry/crates and GET /api/v1/registry/crates/k3-runtime
    let crates_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/crates?limit=10&offset=0")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(crates_res.status(), StatusCode::OK);
    assert_eq!(
        crates_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let crates_body = crates_res.into_body().collect().await.unwrap().to_bytes();
    let crates_json: serde_json::Value = serde_json::from_slice(&crates_body).unwrap();
    assert_eq!(crates_json["total"], 1);
    assert_eq!(crates_json["crates"][0]["name"], "k3-runtime");

    let detail_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/crates/k3-runtime")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail_res.status(), StatusCode::OK);
    assert_eq!(
        detail_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let detail_body = detail_res.into_body().collect().await.unwrap().to_bytes();
    let detail_json: serde_json::Value = serde_json::from_slice(&detail_body).unwrap();
    assert_eq!(detail_json["name"], "k3-runtime");
    assert_eq!(detail_json["versions_count"], 1);
    assert_eq!(
        detail_json["versions"][0]["dependencies"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Missing crate returns 404
    let missing_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/crates/nonexistent-crate")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_m6_canaries_w3c_trace_id_and_hostname_ip_sanitization() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let canary_token = "m6-canary-token";
    catalog
        .insert_api_token(
            "m6-canary",
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

    let bin_digest = cas.put_blob(b"canary-bin-payload-m6").await.unwrap();
    let it_digest = cas.put_blob(b"canary-it-payload-m6").await.unwrap();

    let bundle_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let taint_trace_id = "0af7651916cd43dd8448eb211c80319c";

    // Reject invalid trace_id with 400 Bad Request
    let bad_bundle_req = serde_json::json!({
        "service_name": "action-runner",
        "binary_digest": bin_digest.as_str(),
        "it_archive_digest": it_digest.as_str(),
        "trace_id": "NOT_A_VALID_32_HEX_TRACE_ID"
    });
    let bad_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/bundles/it")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
                .body(Body::from(serde_json::to_vec(&bad_bundle_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);

    // Create bundle with valid W3C trace_id
    let valid_bundle_req = serde_json::json!({
        "service_name": "action-runner",
        "binary_digest": bin_digest.as_str(),
        "it_archive_digest": it_digest.as_str(),
        "trace_id": bundle_trace_id
    });
    let create_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/bundles/it")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
                .body(Body::from(serde_json::to_vec(&valid_bundle_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);

    // Taint bundle with internal hostname, private LAN IP, and W3C trace_id
    std::env::set_var(
        "MUREGISTRY_NODE_MAP",
        "test-node-a=node-a,test-node-b=node-b,test-worker-rv=worker-riscv64",
    );
    let internal_node = "test-worker-rv";
    let priv_ip = format!("{}.{}.100.50", 192, 168);
    let internal_reason = format!(
        "SLO breach connecting to test-node-a.corp.internal ({priv_ip}:8444) and test-node-b (10.0.14.9) from /var/lib/muregist/canary"
    );
    let taint_payload = serde_json::json!({
        "service_name": "action-runner",
        "node_id": internal_node,
        "reason": internal_reason,
        "trace_id": taint_trace_id
    });
    let taint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/canary/{}/taint", bin_digest.as_str()))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {canary_token}"))
                .body(Body::from(serde_json::to_vec(&taint_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(taint_res.status(), StatusCode::OK);

    // Query GET /api/v1/canaries and verify sanitization + trace_id linkage
    let canaries_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/canaries")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(canaries_res.status(), StatusCode::OK);
    assert_eq!(
        canaries_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let canaries_body = canaries_res.into_body().collect().await.unwrap().to_bytes();
    let canaries_str = String::from_utf8(canaries_body.to_vec()).unwrap();
    let canaries_json: serde_json::Value = serde_json::from_str(&canaries_str).unwrap();

    // Ensure zero internal hostnames, private LAN IPs, or host paths leak in response
    assert!(!canaries_str.contains("test-node-a"));
    assert!(!canaries_str.contains("test-node-b"));
    assert!(!canaries_str.contains("test-worker-rv"));
    assert!(!canaries_str.contains("corp.internal"));
    assert!(!canaries_str.contains(&priv_ip));
    assert!(!canaries_str.contains("10.0.14.9"));
    assert!(!canaries_str.contains("/var/lib/muregist"));

    assert_eq!(canaries_json["taints"][0]["node_id"], "worker-riscv64");
    assert_eq!(canaries_json["taints"][0]["trace_id"], taint_trace_id);
    let sanitized_reason = canaries_json["taints"][0]["reason"].as_str().unwrap();
    assert!(sanitized_reason.contains("node-a.example.invalid"));
    assert!(sanitized_reason.contains("node-b"));
    assert!(sanitized_reason.contains("192.0.2.x"));
    assert_eq!(canaries_json["bundles"][0]["trace_id"], taint_trace_id);

    // Also verify GET /api/v1/registry/bundles and GET /api/v1/registry/taints
    let bundles_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/bundles")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundles_res.status(), StatusCode::OK);
    assert_eq!(
        bundles_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let taints_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/taints")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(taints_res.status(), StatusCode::OK);
    assert_eq!(
        taints_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn test_m6_cas_status_overview_and_sse_events() {
    let tmp = tempdir().unwrap();
    let config = Arc::new(AppConfig::new(
        tmp.path(),
        "https://registry.ci.ci.internal:8444",
    ));
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    };
    let app = build_app_router(state);

    let blob1 = b"cas-health-test-blob-1";
    let blob2 = b"cas-health-test-blob-2-extra";
    cas.put_blob(blob1).await.unwrap();
    cas.put_blob(blob2).await.unwrap();
    // Duplicate put to record deduplication savings
    cas.put_blob(blob1).await.unwrap();

    // 1. GET /api/v1/cas/status
    let cas_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/cas/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cas_res.status(), StatusCode::OK);
    assert_eq!(
        cas_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let cas_body = cas_res.into_body().collect().await.unwrap().to_bytes();
    let cas_str = String::from_utf8(cas_body.to_vec()).unwrap();
    assert!(!cas_str.contains(&tmp.path().to_string_lossy().to_string()));

    let cas_json: serde_json::Value = serde_json::from_str(&cas_str).unwrap();
    assert_eq!(cas_json["total_blobs"], 2);
    assert_eq!(cas_json["total_bytes"], (blob1.len() + blob2.len()) as u64);
    assert_eq!(cas_json["dedup_savings_bytes"], blob1.len() as u64);
    assert!(cas_json["dedup_ratio_bps"].as_u64().unwrap() > 0);
    assert_eq!(cas_json["corrupted_blobs"], 0);
    assert_eq!(cas_json["healthy"], true);
    assert!(cas_json["last_scrub_epoch_ms"].as_i64().unwrap() > 0);

    // 2. GET /api/v1/registry/overview
    let ov_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/overview")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ov_res.status(), StatusCode::OK);
    assert_eq!(
        ov_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let ov_body = ov_res.into_body().collect().await.unwrap().to_bytes();
    let ov_json: serde_json::Value = serde_json::from_slice(&ov_body).unwrap();
    assert_eq!(ov_json["total_blobs"], 2);
    assert_eq!(ov_json["healthy"], true);

    // 3. GET /api/v1/registry/events SSE stream
    let sse_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/registry/events")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_res.status(), StatusCode::OK);
    assert_eq!(
        sse_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let ctype = sse_res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ctype.starts_with("text/event-stream"));
}
