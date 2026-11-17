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
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

struct TestPki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_der: CertificateDer<'static>,
    client_key_der: Vec<u8>,
    rogue_cert_der: CertificateDer<'static>,
    rogue_key_der: Vec<u8>,
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
    san_dns: &str,
    eku: ExtendedKeyUsagePurpose,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> (String, CertificateDer<'static>, String, Vec<u8>) {
    let mut params = CertificateParams::new(vec![san_dns.to_string()]).unwrap();
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
    let cert_pem = cert.pem();
    let cert_der = cert.der().clone();
    let key_pem = key.serialize_pem();
    let key_der = key.serialize_der();
    (cert_pem, cert_der, key_pem, key_der)
}

fn build_test_pki() -> TestPki {
    let ca = generate_ca("Jero-Mu Test Root CA");
    let (server_cert_pem, _, server_key_pem, _) = generate_leaf(
        "registry.example",
        "registry.example",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
    );
    let (_, client_cert_der, _, client_key_der) = generate_leaf(
        "node-a.example",
        "node-a.example",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
    );

    let rogue_ca = generate_ca("Rogue Test CA");
    let (_, rogue_cert_der, _, rogue_key_der) = generate_leaf(
        "rogue.example",
        "rogue.example",
        ExtendedKeyUsagePurpose::ClientAuth,
        &rogue_ca,
    );

    TestPki {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        server_cert_pem,
        server_key_pem,
        client_cert_der,
        client_key_der,
        rogue_cert_der,
        rogue_key_der,
    }
}

fn write_server_pki(
    dir: &Path,
    pki: &TestPki,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let ca_path = dir.join("ca.crt");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&ca_path, &pki.ca_pem).unwrap();
    std::fs::write(&cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&key_path, &pki.server_key_pem).unwrap();
    (ca_path, cert_path, key_path)
}

fn build_client_tls_connector(
    ca_der: CertificateDer<'static>,
    client_identity: Option<(CertificateDer<'static>, Vec<u8>)>,
) -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = match client_identity {
        Some((cert_der, key_der)) => {
            let key = PrivateKeyDer::try_from(key_der).unwrap();
            builder.with_client_auth_cert(vec![cert_der], key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    TlsConnector::from(Arc::new(client_config))
}

async fn send_http_request<S>(mut stream: S, raw_req: &str) -> (u16, String, Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(raw_req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut raw_resp = Vec::new();
    stream.read_to_end(&mut raw_resp).await.unwrap();

    let header_end = raw_resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("missing HTTP header separator");
    let head = String::from_utf8_lossy(&raw_resp[..header_end]).to_string();
    let status_code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .expect("missing HTTP status code");
    let body = raw_resp[header_end + 4..].to_vec();
    (status_code, head, body)
}

#[tokio::test]
async fn test_mtls_listener_handshake_san_auth_and_cas_blob_download() {
    let tmp = tempdir().unwrap();
    let pki = build_test_pki();
    let (ca_path, cert_path, key_path) = write_server_pki(tmp.path(), &pki);

    let config = Arc::new(
        AppConfig::new(tmp.path(), "https://registry.example:8444")
            .with_tls_paths(&ca_path, &cert_path, &key_path),
    );
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let payload = b"\x7fELF-mu-registry-mtls-cas-blob-payload-v1";
    let digest = cas.put_blob(payload).await.unwrap();

    let app = build_app_router(AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    });
    let tls_acceptor = build_listener_tls_acceptor(&config)
        .unwrap()
        .expect("expected mTLS acceptor when certs exist");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        serve_router_with_listener(listener, app, Some(tls_acceptor), async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // 1. Valid mTLS client cert -> downloads CAS blob at /api/v1/cas/blobs/sha256/{digest}
    let valid_connector = build_client_tls_connector(
        pki.ca_der.clone(),
        Some((pki.client_cert_der.clone(), pki.client_key_der.clone())),
    );
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("registry.example").unwrap();
    let tls_stream = valid_connector
        .connect(server_name.clone(), tcp)
        .await
        .unwrap();

    let req = format!(
        "GET /api/v1/cas/blobs/sha256/{} HTTP/1.1\r\nHost: registry.example\r\nConnection: close\r\n\r\n",
        digest.as_str()
    );
    let (status, headers, body) = send_http_request(tls_stream, &req).await;
    assert_eq!(status, 200);
    assert!(headers
        .to_ascii_lowercase()
        .contains("content-type: application/octet-stream"));
    assert_eq!(body, payload);

    // 2. Alias route /api/v1/blobs/sha256/{digest} returns identical payload over mTLS
    let tcp_alias = TcpStream::connect(addr).await.unwrap();
    let tls_alias = valid_connector
        .connect(server_name.clone(), tcp_alias)
        .await
        .unwrap();
    let req_alias = format!(
        "GET /api/v1/blobs/sha256/{} HTTP/1.1\r\nHost: registry.example\r\nConnection: close\r\n\r\n",
        digest.as_str()
    );
    let (alias_status, _, alias_body) = send_http_request(tls_alias, &req_alias).await;
    assert_eq!(alias_status, 200);
    assert_eq!(alias_body, payload);

    // 3. Even if client sends a spoofed x-client-cert-san header over mTLS, server strips it
    //    and authenticates with verified peer certificate SAN (node-a.example)
    let tcp_taint = TcpStream::connect(addr).await.unwrap();
    let tls_taint = valid_connector
        .connect(server_name.clone(), tcp_taint)
        .await
        .unwrap();
    let req_taint = format!(
        "POST /api/v1/canary/{}/taint HTTP/1.1\r\nHost: registry.example\r\nContent-Type: application/json\r\nx-client-cert-san: spoofed.attacker.example\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
        digest.as_str()
    );
    let (taint_status, _, _) = send_http_request(tls_taint, &req_taint).await;
    assert_eq!(taint_status, 200);

    // 4. Client without client certificate is rejected at TLS handshake / connection
    let no_auth_connector = build_client_tls_connector(pki.ca_der.clone(), None);
    let tcp_no_cert = TcpStream::connect(addr).await.unwrap();
    let no_cert_res = match no_auth_connector
        .connect(server_name.clone(), tcp_no_cert)
        .await
    {
        Err(_) => true,
        Ok(tls_stream) => {
            // TLS 1.3 delivers client cert rejection alert during initial post-handshake read
            let mut s = tls_stream;
            let _ = s
                .write_all(b"GET /api/v1/cas/status HTTP/1.1\r\nHost: registry.example\r\nConnection: close\r\n\r\n")
                .await;
            let _ = s.flush().await;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.is_err() || buf.is_empty()
        }
    };
    assert!(no_cert_res, "connection without client cert must fail mTLS");

    // 5. Client with certificate from untrusted CA is rejected
    let rogue_connector = build_client_tls_connector(
        pki.ca_der.clone(),
        Some((pki.rogue_cert_der.clone(), pki.rogue_key_der.clone())),
    );
    let tcp_rogue = TcpStream::connect(addr).await.unwrap();
    let rogue_res = match rogue_connector.connect(server_name, tcp_rogue).await {
        Err(_) => true,
        Ok(tls_stream) => {
            let mut s = tls_stream;
            let _ = s
                .write_all(b"GET /api/v1/cas/status HTTP/1.1\r\nHost: registry.example\r\nConnection: close\r\n\r\n")
                .await;
            let _ = s.flush().await;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.is_err() || buf.is_empty()
        }
    };
    assert!(rogue_res, "untrusted CA client cert must fail mTLS");

    // Verify PEM parser compatibility check matches generated PKI
    let _parsed = CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let _ = shutdown_tx.send(());
    server_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_cas_blob_auth_spoofed_header_rejection_and_error_codes() {
    let tmp = tempdir().unwrap();
    let missing_ca = tmp.path().join("missing-ca.crt");
    let missing_cert = tmp.path().join("missing-server.crt");
    let missing_key = tmp.path().join("missing-server.key");

    let config = Arc::new(
        AppConfig::new(tmp.path(), "http://127.0.0.1")
            .with_tls_paths(&missing_ca, &missing_cert, &missing_key)
            .with_require_tls(false),
    );
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await.unwrap();
    let catalog = DuckDbCatalog::in_memory().unwrap();

    let read_token = "cas-blob-read-token";
    let publish_token = "cas-blob-publish-only-token";
    catalog
        .insert_api_token(
            "cas-reader",
            &hash_token_sha256(read_token),
            &[TokenScope::Read],
        )
        .unwrap();
    catalog
        .insert_api_token(
            "cas-publisher",
            &hash_token_sha256(publish_token),
            &[TokenScope::Publish],
        )
        .unwrap();

    let blob_bytes = b"cas-blob-binary-contents-v1";
    let digest = cas.put_blob(blob_bytes).await.unwrap();

    let app = build_app_router(AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog: catalog.clone(),
    });
    let tls_acceptor = build_listener_tls_acceptor(&config).unwrap();
    assert!(tls_acceptor.is_none());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        serve_router_with_listener(listener, app, tls_acceptor, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // 1. Spoofed x-client-cert-san rejected when MUREGIST_TRUST_PROXY_SAN_HEADER is disabled -> 401
    let tcp_spoof = TcpStream::connect(addr).await.unwrap();
    let spoof_req = format!(
        "GET /api/v1/cas/blobs/sha256/{} HTTP/1.1\r\nHost: localhost\r\nx-client-cert-san: node-a.example\r\nConnection: close\r\n\r\n",
        digest.as_str()
    );
    let (spoof_status, _, _) = send_http_request(tcp_spoof, &spoof_req).await;
    assert_eq!(spoof_status, 401);

    // 2. Publish-only token lacks TokenScope::Read -> 403 Forbidden
    let tcp_forbid = TcpStream::connect(addr).await.unwrap();
    let forbid_req = format!(
        "GET /api/v1/cas/blobs/sha256/{} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {publish_token}\r\nConnection: close\r\n\r\n",
        digest.as_str()
    );
    let (forbid_status, _, _) = send_http_request(tcp_forbid, &forbid_req).await;
    assert_eq!(forbid_status, 403);

    // 3. Invalid SHA-256 digest format -> 400 Bad Request
    let tcp_bad = TcpStream::connect(addr).await.unwrap();
    let bad_req = format!(
        "GET /api/v1/cas/blobs/sha256/INVALID-DIGEST HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {read_token}\r\nConnection: close\r\n\r\n"
    );
    let (bad_status, _, _) = send_http_request(tcp_bad, &bad_req).await;
    assert_eq!(bad_status, 400);

    // 4. Valid hex digest absent from CAS -> 404 Not Found
    let missing_digest = "0".repeat(64);
    let tcp_missing = TcpStream::connect(addr).await.unwrap();
    let missing_req = format!(
        "GET /api/v1/cas/blobs/sha256/{missing_digest} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {read_token}\r\nConnection: close\r\n\r\n"
    );
    let (missing_status, _, _) = send_http_request(tcp_missing, &missing_req).await;
    assert_eq!(missing_status, 404);

    // 5. Valid Bearer Read token downloads raw blob bytes -> 200 OK
    let tcp_ok = TcpStream::connect(addr).await.unwrap();
    let ok_req = format!(
        "GET /api/v1/cas/blobs/sha256/{} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {read_token}\r\nConnection: close\r\n\r\n",
        digest.as_str()
    );
    let (ok_status, ok_headers, ok_body) = send_http_request(tcp_ok, &ok_req).await;
    assert_eq!(ok_status, 200);
    assert!(ok_headers
        .to_ascii_lowercase()
        .contains("content-type: application/octet-stream"));
    assert_eq!(ok_body, blob_bytes);

    let _ = shutdown_tx.send(());
    server_handle.await.unwrap().unwrap();
}
