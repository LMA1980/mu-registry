#![deny(unsafe_code)]

use mu_registry::{
    api::build_app_router, auth::hash_token_sha256, build_listener_tls_acceptor,
    serve_router_with_listener, AppConfig, AppState, CasStore, DuckDbCatalog, TokenScope,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    bearer_token: Option<String>,
    tls_ca_pem: Option<Vec<u8>>,
    tls_cert_pem: Option<Vec<u8>>,
    tls_key_pem: Option<Vec<u8>>,
    timeout: Duration,
}

fn read_trimmed_secret_file(var_name: &str, path_raw: &str) -> Result<String, String> {
    let path = path_raw.trim();
    if path.is_empty() {
        return Err(format!("{var_name} was set to an empty path"));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {var_name} at '{path}': {e}"))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{var_name} at '{path}' is empty"));
    }
    Ok(trimmed)
}

fn read_non_empty_file_bytes(var_name: &str, path_raw: &str) -> Result<Vec<u8>, String> {
    let path = path_raw.trim();
    if path.is_empty() {
        return Err(format!("{var_name} was set to an empty path"));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("Failed to read {var_name} at '{path}': {e}"))?;
    if bytes.is_empty() {
        return Err(format!("{var_name} at '{path}' is empty"));
    }
    Ok(bytes)
}

fn load_smoke_config_with<F>(get_env: F) -> Result<SmokeConfig, String>
where
    F: Fn(&str) -> Option<String>,
{
    let target_url = get_env("MU_SMOKE_TARGET_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let bearer_token = match get_env("MU_SMOKE_BEARER_TOKEN_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(path) => Some(read_trimmed_secret_file(
            "MU_SMOKE_BEARER_TOKEN_FILE",
            &path,
        )?),
        None => None,
    };

    let tls_ca_pem = match get_env("MU_SMOKE_TLS_CA_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(path) => Some(read_non_empty_file_bytes("MU_SMOKE_TLS_CA_FILE", &path)?),
        None => None,
    };

    let cert_path = get_env("MU_SMOKE_TLS_CERT_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let key_path = get_env("MU_SMOKE_TLS_KEY_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (tls_cert_pem, tls_key_pem) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (
            Some(read_non_empty_file_bytes("MU_SMOKE_TLS_CERT_FILE", &cert)?),
            Some(read_non_empty_file_bytes("MU_SMOKE_TLS_KEY_FILE", &key)?),
        ),
        (Some(_), None) | (None, Some(_)) => {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set together"
                    .to_string(),
            );
        }
        (None, None) => (None, None),
    };

    let timeout_secs = match get_env("MU_SMOKE_TIMEOUT_SECS")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let secs = raw.parse::<u64>().map_err(|e| {
                format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': expected positive integer ({e})")
            })?;
            if secs == 0 {
                return Err("MU_SMOKE_TIMEOUT_SECS must be greater than zero".to_string());
            }
            secs
        }
        None => 10,
    };

    Ok(SmokeConfig {
        target_url,
        bearer_token,
        tls_ca_pem,
        tls_cert_pem,
        tls_key_pem,
        timeout: Duration::from_secs(timeout_secs),
    })
}

fn load_smoke_config() -> Result<SmokeConfig, String> {
    load_smoke_config_with(|k| std::env::var(k).ok())
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    is_https: bool,
    host: String,
    port: u16,
    base_path: String,
}

fn parse_target_url(raw_url: &str) -> Result<ParsedUrl, String> {
    let (is_https, rest) = if let Some(r) = raw_url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = raw_url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!(
            "Unsupported target URL '{raw_url}': expected http:// or https://"
        ));
    };

    let (authority, path_raw) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let parsed_port = p
            .parse::<u16>()
            .map_err(|e| format!("Invalid TCP port in '{raw_url}': {e}"))?;
        (h.to_string(), parsed_port)
    } else {
        (authority.to_string(), if is_https { 443 } else { 80 })
    };
    Ok(ParsedUrl {
        is_https,
        host,
        port,
        base_path: path_raw.trim_end_matches('/').to_string(),
    })
}

fn build_tls_connector_from_pems(
    ca_pem: &[u8],
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<TlsConnector, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut ca_reader = BufReader::new(ca_pem);
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid TLS CA PEM: {e}"))?;
    if ca_certs.is_empty() {
        return Err("TLS CA PEM contains zero certificates".to_string());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| format!("Failed adding CA cert: {e}"))?;
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_cfg = match (client_cert_pem, client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let mut cert_reader = BufReader::new(cert_pem);
            let certs: Vec<CertificateDer<'static>> =
                rustls_pki_types::CertificateDer::pem_reader_iter(&mut cert_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("Invalid client cert PEM: {e}"))?;
            let mut key_reader = BufReader::new(key_pem);
            let key: PrivateKeyDer<'static> =
                rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key_reader)
                    .map_err(|e| format!("Invalid client key PEM: {e}"))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("Failed configuring client mTLS identity: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err("Both client cert and key must be supplied together".to_string());
        }
    };

    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

struct HttpResp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let Some(rel_crlf) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err("Malformed chunked HTTP body: missing size CRLF".to_string());
        };
        let size_hex = std::str::from_utf8(&raw[pos..pos + rel_crlf])
            .map_err(|e| format!("Invalid chunk size UTF-8: {e}"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| format!("Invalid chunk size '{size_hex}': {e}"))?;
        pos += rel_crlf + 2;
        if size == 0 {
            break;
        }
        if pos + size + 2 > raw.len() {
            return Err("Truncated chunked HTTP body".to_string());
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2;
    }
    Ok(out)
}

async fn send_http_get_on_stream<S>(
    mut stream: S,
    host_header: &str,
    path: &str,
    bearer_token: Option<&str>,
    timeout: Duration,
) -> Result<HttpResp, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n");
    if let Some(tok) = bearer_token {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    req.push_str("\r\n");

    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| format!("Timed out sending HTTP GET {path}"))?
        .map_err(|e| format!("Failed sending HTTP GET {path}: {e}"))?;
    tokio::time::timeout(timeout, stream.flush())
        .await
        .map_err(|_| format!("Timed out flushing HTTP GET {path}"))?
        .map_err(|e| format!("Failed flushing HTTP GET {path}: {e}"))?;

    let mut raw = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut raw))
        .await
        .map_err(|_| format!("Timed out reading HTTP GET {path}"))?
        .map_err(|e| format!("Failed reading HTTP GET {path}: {e}"))?;

    let split_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("Malformed HTTP response from {path}"))?;
    let head = String::from_utf8_lossy(&raw[..split_pos]);
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| format!("Empty HTTP response from {path}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid HTTP status line '{status_line}'"))?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let body_raw = &raw[split_pos + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        decode_chunked_body(body_raw)?
    } else {
        body_raw.to_vec()
    };

    Ok(HttpResp {
        status,
        headers,
        body,
    })
}

async fn http_get(
    target: &ParsedUrl,
    path: &str,
    bearer_token: Option<&str>,
    tls: Option<&TlsConnector>,
    timeout: Duration,
) -> Result<HttpResp, String> {
    let full_path = if target.base_path.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", target.base_path, path)
    };
    let addr_str = format!("{}:{}", target.host, target.port);
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr_str))
        .await
        .map_err(|_| format!("Timed out connecting to {addr_str}"))?
        .map_err(|e| format!("Failed connecting to {addr_str}: {e}"))?;

    if target.is_https {
        let connector =
            tls.ok_or_else(|| "TLS connector required for https:// target".to_string())?;
        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|e| format!("Invalid TLS server name '{}': {e}", target.host))?;
        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| format!("Timed out during TLS handshake with {addr_str}"))?
            .map_err(|e| format!("TLS handshake failed with {addr_str}: {e}"))?;
        send_http_get_on_stream(tls_stream, &target.host, &full_path, bearer_token, timeout).await
    } else {
        send_http_get_on_stream(tcp, &addr_str, &full_path, bearer_token, timeout).await
    }
}

fn generate_ca(common_name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().unwrap();
    CertifiedIssuer::self_signed(params, key).unwrap()
}

fn generate_leaf(
    common_name: &str,
    sans: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> (String, String) {
    let mut params = CertificateParams::new(sans).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![eku];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

async fn verify_readonly_endpoints(
    target: &ParsedUrl,
    bearer_token: Option<&str>,
    tls: Option<&TlsConnector>,
    timeout: Duration,
) {
    // 1. /health
    let health = http_get(target, "/health", bearer_token, tls, timeout)
        .await
        .expect("GET /health must succeed");
    assert_eq!(health.status, 200);
    let health_json: serde_json::Value = serde_json::from_slice(&health.body).unwrap();
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["healthy"], true);
    assert_eq!(health_json["service"], "mu-registry");

    // 2. Sparse-index /index/config.json readiness
    let idx_cfg = http_get(target, "/index/config.json", bearer_token, tls, timeout)
        .await
        .expect("GET /index/config.json must succeed");
    assert_eq!(idx_cfg.status, 200);
    let idx_json: serde_json::Value = serde_json::from_slice(&idx_cfg.body).unwrap();
    assert!(idx_json["dl"]
        .as_str()
        .is_some_and(|s| s.ends_with("/api/v1/crates")));
    assert!(idx_json["api"].as_str().is_some_and(|s| !s.is_empty()));

    // 3. Read-only CAS, canary, catalog, bundles & taints query endpoints
    let cas_status = http_get(target, "/api/v1/cas/status", bearer_token, tls, timeout)
        .await
        .unwrap();
    assert_eq!(cas_status.status, 200);
    let cas_json: serde_json::Value = serde_json::from_slice(&cas_status.body).unwrap();
    assert_eq!(cas_json["healthy"], true);

    let canary_status = http_get(target, "/api/v1/canary/status", bearer_token, tls, timeout)
        .await
        .unwrap();
    assert_eq!(canary_status.status, 200);
    assert!(canary_status.headers.contains_key("canary-repository"));

    let packages = http_get(target, "/api/v1/packages", bearer_token, tls, timeout)
        .await
        .unwrap();
    assert_eq!(packages.status, 200);
    let pkg_json: serde_json::Value = serde_json::from_slice(&packages.body).unwrap();
    assert!(pkg_json["packages"].is_array());

    let bundles = http_get(
        target,
        "/api/v1/registry/bundles",
        bearer_token,
        tls,
        timeout,
    )
    .await
    .unwrap();
    assert_eq!(bundles.status, 200);
    let bundles_json: serde_json::Value = serde_json::from_slice(&bundles.body).unwrap();
    assert!(bundles_json["bundles"].is_array());

    let taints = http_get(
        target,
        "/api/v1/registry/taints",
        bearer_token,
        tls,
        timeout,
    )
    .await
    .unwrap();
    assert_eq!(taints.status, 200);
    let taints_json: serde_json::Value = serde_json::from_slice(&taints.body).unwrap();
    assert!(taints_json["taints"].is_array());
}

#[tokio::test]
async fn smoke_mu_registry_read_only_and_auth() {
    let cfg = load_smoke_config().expect("Smoke environment configuration must be valid");

    if let Some(ref target_url) = cfg.target_url {
        let parsed = parse_target_url(target_url).expect("Valid MU_SMOKE_TARGET_URL required");
        let tls = if parsed.is_https {
            let ca = cfg
                .tls_ca_pem
                .as_deref()
                .expect("MU_SMOKE_TLS_CA_FILE is required for https:// live probes");
            Some(
                build_tls_connector_from_pems(
                    ca,
                    cfg.tls_cert_pem.as_deref(),
                    cfg.tls_key_pem.as_deref(),
                )
                .unwrap(),
            )
        } else {
            None
        };

        verify_readonly_endpoints(
            &parsed,
            cfg.bearer_token.as_deref(),
            tls.as_ref(),
            cfg.timeout,
        )
        .await;

        let probe_digest = "0000000000000000000000000000000000000000000000000000000000000000";
        let blob_path = format!("/api/v1/cas/blobs/sha256/{probe_digest}");
        if parsed.is_https {
            // Without client cert on mTLS server, handshake or HTTP request must fail closed
            if let Some(ca) = cfg.tls_ca_pem.as_deref() {
                let no_client_tls = build_tls_connector_from_pems(ca, None, None).unwrap();
                match http_get(&parsed, &blob_path, None, Some(&no_client_tls), cfg.timeout).await {
                    Ok(resp) => assert!(
                        resp.status == 401 || resp.status == 403,
                        "Expected fail-closed 401/403 without credentials, got {}",
                        resp.status
                    ),
                    Err(_) => {
                        // Expected mTLS client-certificate handshake rejection
                    }
                }
            }
        } else {
            let unauth = http_get(&parsed, &blob_path, None, None, cfg.timeout)
                .await
                .unwrap();
            assert_eq!(unauth.status, 401);
        }

        if cfg.bearer_token.is_some() || cfg.tls_cert_pem.is_some() {
            let auth_probe = http_get(
                &parsed,
                &blob_path,
                cfg.bearer_token.as_deref(),
                tls.as_ref(),
                cfg.timeout,
            )
            .await
            .unwrap();
            assert!(
                auth_probe.status == 200 || auth_probe.status == 404,
                "Authenticated read-only CAS probe should pass auth (200/404), got {}",
                auth_probe.status
            );
        }
        return;
    }

    // Ephemeral in-process local mode (exercises mTLS listener + bearer auth + read-only handlers)
    let tmp = tempdir().unwrap();
    let ca = generate_ca("Jero-Mu Ephemeral Smoke CA");
    let (srv_cert_pem, srv_key_pem) = generate_leaf(
        "127.0.0.1",
        vec!["127.0.0.1".to_string(), "localhost".to_string()],
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
    );
    let (cli_cert_pem, cli_key_pem) = generate_leaf(
        "node-a.example",
        vec!["node-a.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
    );
    let rogue_ca = generate_ca("Rogue Smoke CA");
    let (rogue_cert_pem, rogue_key_pem) = generate_leaf(
        "rogue.example",
        vec!["rogue.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
        &rogue_ca,
    );

    let ca_path = tmp.path().join("ca.crt");
    let srv_cert_path = tmp.path().join("server.crt");
    let srv_key_path = tmp.path().join("server.key");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&srv_cert_path, &srv_cert_pem).unwrap();
    std::fs::write(&srv_key_path, &srv_key_pem).unwrap();

    let cas = Arc::new(CasStore::new(tmp.path()));
    cas.init().await.unwrap();
    let probe_payload = b"mu-registry-smoke-probe-blob-v1";
    let blob_digest = cas.put_blob(probe_payload).await.unwrap();

    let catalog = DuckDbCatalog::in_memory().unwrap();
    let read_token = "smoke-read-token-valid";
    let publish_only_token = "smoke-publish-only-token";
    catalog
        .insert_api_token(
            "smoke-read",
            &hash_token_sha256(read_token),
            &[TokenScope::Read],
        )
        .unwrap();
    catalog
        .insert_api_token(
            "smoke-pub",
            &hash_token_sha256(publish_only_token),
            &[TokenScope::Publish],
        )
        .unwrap();

    // A) Ephemeral mTLS server
    let mtls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_addr = mtls_listener.local_addr().unwrap();
    let mtls_cfg = Arc::new(
        AppConfig::new(tmp.path(), format!("https://{mtls_addr}")).with_tls_paths(
            &ca_path,
            &srv_cert_path,
            &srv_key_path,
        ),
    );
    let tls_acceptor = build_listener_tls_acceptor(&mtls_cfg).unwrap().unwrap();
    let mtls_app = build_app_router(AppState {
        config: mtls_cfg,
        cas: cas.clone(),
        catalog: catalog.clone(),
    });
    let (mtls_stop_tx, mtls_stop_rx) = oneshot::channel::<()>();
    let mtls_handle = tokio::spawn(async move {
        serve_router_with_listener(mtls_listener, mtls_app, Some(tls_acceptor), async move {
            let _ = mtls_stop_rx.await;
        })
        .await
    });

    let mtls_target = parse_target_url(&format!("https://{mtls_addr}")).unwrap();
    let ca_pem_bytes = ca.pem().into_bytes();

    // Missing client cert fails closed at TLS handshake
    let no_cert_tls = build_tls_connector_from_pems(&ca_pem_bytes, None, None).unwrap();
    assert!(
        http_get(
            &mtls_target,
            "/health",
            None,
            Some(&no_cert_tls),
            cfg.timeout
        )
        .await
        .is_err(),
        "mTLS listener must reject connection without client certificate"
    );

    // Untrusted rogue client cert fails closed at TLS handshake
    let rogue_tls = build_tls_connector_from_pems(
        &ca_pem_bytes,
        Some(rogue_cert_pem.as_bytes()),
        Some(rogue_key_pem.as_bytes()),
    )
    .unwrap();
    assert!(
        http_get(&mtls_target, "/health", None, Some(&rogue_tls), cfg.timeout)
            .await
            .is_err(),
        "mTLS listener must reject untrusted rogue client certificate"
    );

    // Valid mTLS client cert succeeds across all read-only endpoints + CAS blob download
    let valid_mtls = build_tls_connector_from_pems(
        &ca_pem_bytes,
        Some(cli_cert_pem.as_bytes()),
        Some(cli_key_pem.as_bytes()),
    )
    .unwrap();
    verify_readonly_endpoints(&mtls_target, None, Some(&valid_mtls), cfg.timeout).await;
    let blob_path = format!("/api/v1/cas/blobs/sha256/{}", blob_digest.as_str());
    let mtls_blob = http_get(
        &mtls_target,
        &blob_path,
        None,
        Some(&valid_mtls),
        cfg.timeout,
    )
    .await
    .unwrap();
    assert_eq!(mtls_blob.status, 200);
    assert_eq!(mtls_blob.body, probe_payload);

    // B) Ephemeral plain HTTP server (verifying bearer token 401/403/200 enforcement)
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_cfg = Arc::new(AppConfig::new(tmp.path(), format!("http://{http_addr}")));
    let http_app = build_app_router(AppState {
        config: http_cfg,
        cas,
        catalog,
    });
    let (http_stop_tx, http_stop_rx) = oneshot::channel::<()>();
    let http_handle = tokio::spawn(async move {
        serve_router_with_listener(http_listener, http_app, None, async move {
            let _ = http_stop_rx.await;
        })
        .await
    });

    let http_target = parse_target_url(&format!("http://{http_addr}")).unwrap();
    verify_readonly_endpoints(&http_target, None, None, cfg.timeout).await;

    let unauth_blob = http_get(&http_target, &blob_path, None, None, cfg.timeout)
        .await
        .unwrap();
    assert_eq!(unauth_blob.status, 401);

    let bad_tok_blob = http_get(
        &http_target,
        &blob_path,
        Some("wrong-bearer-token"),
        None,
        cfg.timeout,
    )
    .await
    .unwrap();
    assert_eq!(bad_tok_blob.status, 401);

    let forbidden_blob = http_get(
        &http_target,
        &blob_path,
        Some(publish_only_token),
        None,
        cfg.timeout,
    )
    .await
    .unwrap();
    assert_eq!(forbidden_blob.status, 403);

    let authorized_blob = http_get(
        &http_target,
        &blob_path,
        Some(read_token),
        None,
        cfg.timeout,
    )
    .await
    .unwrap();
    assert_eq!(authorized_blob.status, 200);
    assert_eq!(authorized_blob.body, probe_payload);

    let _ = mtls_stop_tx.send(());
    let _ = http_stop_tx.send(());
    let _ = mtls_handle.await;
    let _ = http_handle.await;
}

#[test]
fn smoke_mu_registry_fail_closed_credential_files() {
    let missing_tok = load_smoke_config_with(|k| match k {
        "MU_SMOKE_BEARER_TOKEN_FILE" => Some("/nonexistent/registry-smoke-token".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(missing_tok.contains("MU_SMOKE_BEARER_TOKEN_FILE"));

    let missing_ca = load_smoke_config_with(|k| match k {
        "MU_SMOKE_TLS_CA_FILE" => Some("/nonexistent/registry-smoke-ca.pem".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(missing_ca.contains("MU_SMOKE_TLS_CA_FILE"));

    let partial_mtls = load_smoke_config_with(|k| match k {
        "MU_SMOKE_TLS_CERT_FILE" => Some("/tmp/only-cert.pem".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(partial_mtls.contains("MU_SMOKE_TLS_KEY_FILE"));

    let tmp = tempdir().unwrap();
    let tok_file = tmp.path().join("bearer");
    std::fs::write(&tok_file, "  registry-smoke-secret\n").unwrap();
    let ok = load_smoke_config_with(|k| match k {
        "MU_SMOKE_BEARER_TOKEN_FILE" => Some(tok_file.to_string_lossy().into_owned()),
        _ => None,
    })
    .unwrap();
    assert_eq!(ok.bearer_token.as_deref(), Some("registry-smoke-secret"));
    assert_eq!(ok.timeout, Duration::from_secs(10));
}
