use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mu_observable_ipc::{
    decode_log_batch, decode_span_batch, read_frame, MSG_TYPE_ARROW_OTEL_LOGS,
    MSG_TYPE_ARROW_OTEL_SPANS,
};
use mu_registry::{
    api::build_app_router, auth::hash_token_sha256, encode_publish_frame, AppConfig, AppState,
    CasStore, DuckDbCatalog, MuObserveRegistrySink, RecordingRegistryTelemetrySink, TokenScope,
};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tower::ServiceExt;

#[tokio::test]
async fn test_otel_audit_spans_and_logs_across_publish_yank_bundle_and_canary_while_preserving_duckdb_catalog(
) {
    let tmp = tempdir().unwrap();

    // Start a live MUOB Arrow collector listener to verify wire-level batch streaming
    let collector_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let collector_addr = collector_listener.local_addr().expect("addr");
    let collector_task = tokio::spawn(async move {
        let mut received_spans = Vec::new();
        let mut received_logs = Vec::new();
        while let Ok((mut stream, _)) = collector_listener.accept().await {
            if let Ok((hdr, payload)) = read_frame(&mut stream).await {
                if hdr.msg_type == MSG_TYPE_ARROW_OTEL_SPANS {
                    received_spans.extend(decode_span_batch(&payload).expect("decode spans"));
                } else if hdr.msg_type == MSG_TYPE_ARROW_OTEL_LOGS {
                    received_logs.extend(decode_log_batch(&payload).expect("decode logs"));
                }
            }
            if received_spans.len() >= 6 && received_logs.len() >= 5 {
                break;
            }
        }
        (received_spans, received_logs)
    });

    let live_sink = Arc::new(MuObserveRegistrySink::new(
        Some(collector_addr.to_string()),
        "node-a",
    ));
    let recorder = Arc::new(RecordingRegistryTelemetrySink::new().with_forwarder(live_sink));

    let config = Arc::new(
        AppConfig::new(tmp.path(), "https://registry.ci.ci.internal:8444")
            .with_node_id("node-a")
            .with_telemetry_sink(recorder.clone()),
    );
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::new(config.catalog_path()).unwrap();

    let admin_token = "admin-all-scopes-token";
    catalog
        .insert_api_token(
            "admin-token",
            &hash_token_sha256(admin_token),
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

    let incoming_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    // 1. PUT /api/v1/crates/new (publish)
    let meta = serde_json::json!({
        "name": "k3-audit-crate",
        "vers": "0.1.0",
        "deps": [],
        "features": {},
        "description": "Audit test crate"
    });
    let frame = encode_publish_frame(&serde_json::to_vec(&meta).unwrap(), b"crate-tarball-0.1.0");
    let pub_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/new")
                .method("PUT")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header("traceparent", incoming_traceparent)
                .body(Body::from(frame))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_res.status(), StatusCode::OK);
    assert!(pub_res.headers().get("traceparent").is_some());

    // 2. GET /index/k3/-a/k3-audit-crate (sparse index)
    let idx_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/index/k3/-a/k3-audit-crate")
                .method("GET")
                .header("traceparent", incoming_traceparent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(idx_res.status(), StatusCode::OK);

    // 3. DELETE /api/v1/crates/k3-audit-crate/0.1.0/yank
    let yank_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/crates/k3-audit-crate/0.1.0/yank")
                .method("DELETE")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header("traceparent", incoming_traceparent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(yank_res.status(), StatusCode::OK);

    // 4. POST /api/v1/bundles/it
    let bin_digest = cas.put_blob(b"canary-binary-v1").await.unwrap();
    let it_digest = cas.put_blob(b"canary-it-archive-v1").await.unwrap();
    let bundle_req = serde_json::json!({
        "service_name": "action-runner",
        "binary_digest": bin_digest.as_str(),
        "it_archive_digest": it_digest.as_str(),
    });
    let bundle_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/bundles/it")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header("traceparent", incoming_traceparent)
                .body(Body::from(serde_json::to_vec(&bundle_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle_res.status(), StatusCode::CREATED);

    // 5. POST /api/v1/canary/{digest}/promote
    let promote_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/canary/{}/promote", bin_digest.as_str()))
                .method("POST")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header("traceparent", incoming_traceparent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(promote_res.status(), StatusCode::OK);

    // 6. POST /api/v1/canary/{digest}/taint
    let taint_payload = serde_json::json!({
        "service_name": "action-runner",
        "node_id": "worker-riscv64",
        "reason": "Canary SLO latency breach"
    });
    let taint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/canary/{}/taint", bin_digest.as_str()))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header("traceparent", incoming_traceparent)
                .body(Body::from(serde_json::to_vec(&taint_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(taint_res.status(), StatusCode::OK);

    // Verify recorded spans and audit logs
    let spans = recorder.recorded_spans().await;
    assert_eq!(spans.len(), 6);
    let span_names: Vec<&str> = spans.iter().map(|s| s.span_name.as_str()).collect();
    assert!(span_names.contains(&"muregist.cargo.publish"));
    assert!(span_names.contains(&"muregist.cargo.sparse_index"));
    assert!(span_names.contains(&"muregist.cargo.yank"));
    assert!(span_names.contains(&"muregist.canary.bundle.upload"));
    assert!(span_names.contains(&"muregist.canary.promote"));
    assert!(span_names.contains(&"muregist.canary.taint"));

    for span in &spans {
        assert_eq!(span.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(span.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));
    }

    let logs = recorder.recorded_logs().await;
    assert_eq!(logs.len(), 5);
    let log_bodies: Vec<&str> = logs.iter().map(|l| l.body.as_str()).collect();
    assert!(log_bodies.iter().any(|b| b.contains("cargo.crate.publish")));
    assert!(log_bodies.iter().any(|b| b.contains("cargo.crate.yank")));
    assert!(log_bodies
        .iter()
        .any(|b| b.contains("canary.bundle.upload")));
    assert!(log_bodies
        .iter()
        .any(|b| b.contains("canary.release.promote")));
    assert!(log_bodies
        .iter()
        .any(|b| b.contains("canary.release.taint")));

    // Verify wire-level MUOB Arrow batches arrived at the live collector listener
    let (wire_spans, wire_logs) = collector_task.await.expect("collector task");
    assert_eq!(wire_spans.len(), 6);
    assert_eq!(wire_logs.len(), 5);

    // Confirm local DuckDbCatalog (catalog.duckdb) remains 100% intact
    let versions = catalog.get_crate_versions("k3-audit-crate").unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].vers, "0.1.0");
    assert!(versions[0].yanked);
    assert!(catalog.is_digest_tainted(bin_digest.as_str()).unwrap());
}
