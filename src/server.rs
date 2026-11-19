use crate::auth::{
    build_tls_server_config, extract_primary_cert_san, AuthError, VerifiedClientSan,
};
use crate::config::{parse_env_bool_first, AppConfig};
use axum::Router;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::service::Service as HyperService;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tracing::{debug, info, warn};

/// Builds a [`TlsAcceptor`] when CA, server certificate, and server key files all exist.
///
/// If any TLS artifact is absent and `require_tls` (via [`AppConfig::require_tls`] or
/// `MU_REGISTRY_REQUIRE_TLS=true` / `MUREGIST_REQUIRE_TLS=true`) is false, logs a warning and returns `Ok(None)` so local
/// development can fall back to plain TCP. Fails closed with [`AuthError::Tls`] when TLS
/// is required but artifacts are missing.
pub fn build_listener_tls_acceptor(config: &AppConfig) -> Result<Option<TlsAcceptor>, AuthError> {
    let certs_present = config.tls_ca_path.exists()
        && config.tls_cert_path.exists()
        && config.tls_key_path.exists();

    if certs_present {
        let server_config = build_tls_server_config(
            &config.tls_ca_path,
            &config.tls_cert_path,
            &config.tls_key_path,
        )?;
        return Ok(Some(TlsAcceptor::from(Arc::new(server_config))));
    }

    let require_tls = config.require_tls
        || parse_env_bool_first(&["MU_REGISTRY_REQUIRE_TLS", "MUREGIST_REQUIRE_TLS"]);
    if require_tls {
        return Err(AuthError::Tls(format!(
            "TLS is required (MU_REGISTRY_REQUIRE_TLS=true), but required TLS files are missing (ca={}, cert={}, key={})",
            config.tls_ca_path.display(),
            config.tls_cert_path.display(),
            config.tls_key_path.display(),
        )));
    }

    warn!(
        ca_path = %config.tls_ca_path.display(),
        cert_path = %config.tls_cert_path.display(),
        key_path = %config.tls_key_path.display(),
        "TLS certificate artifacts absent and MU_REGISTRY_REQUIRE_TLS is not enabled; falling back to plain TCP listener for local development"
    );
    Ok(None)
}

/// Extracts the primary non-empty SAN from the peer leaf certificate of an accepted mTLS stream.
pub fn extract_verified_client_san<IO>(tls_stream: &TlsStream<IO>) -> Option<VerifiedClientSan> {
    let (_, server_conn) = tls_stream.get_ref();
    let leaf_cert = server_conn.peer_certificates()?.first()?;
    extract_primary_cert_san(leaf_cert.as_ref())
        .ok()
        .flatten()
        .map(VerifiedClientSan)
}

/// Strips any client-supplied `x-client-cert-san` header and attaches [`VerifiedClientSan`]
/// when a verified mTLS peer SAN was extracted from the TLS handshake.
pub fn prepare_mtls_request<B>(
    mut req: Request<B>,
    verified_san: Option<&VerifiedClientSan>,
) -> Request<B> {
    req.headers_mut().remove("x-client-cert-san");
    if let Some(san) = verified_san {
        req.extensions_mut().insert(san.clone());
    }
    req
}

/// Serves an Axum [`Router`] on `listener`, terminating mTLS via `tls_acceptor` when configured
/// or serving plain TCP otherwise, until `shutdown` resolves.
pub async fn serve_router_with_listener<F>(
    listener: TcpListener,
    app: Router,
    tls_acceptor: Option<TlsAcceptor>,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: Future<Output = ()> + Send,
{
    let local_addr = listener.local_addr()?;
    if tls_acceptor.is_some() {
        info!(listen_addr = %local_addr, "mu-registry listening with mTLS enabled");
    } else {
        info!(listen_addr = %local_addr, "mu-registry listening on plain TCP (local dev fallback)");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        while connections.try_join_next().is_some() {}

        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((tcp_stream, peer_addr)) => {
                        let app_clone = app.clone();
                        let acceptor = tls_acceptor.clone();
                        let conn_shutdown = shutdown_rx.clone();
                        connections.spawn(async move {
                            serve_accepted_connection(
                                tcp_stream,
                                peer_addr,
                                app_clone,
                                acceptor,
                                conn_shutdown,
                            )
                            .await;
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "Failed accepting incoming TCP connection");
                    }
                }
            }
        }
    }

    let _ = shutdown_tx.send(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_accepted_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    app: Router,
    tls_acceptor: Option<TlsAcceptor>,
    shutdown_rx: watch::Receiver<bool>,
) {
    match tls_acceptor {
        Some(acceptor) => match acceptor.accept(tcp_stream).await {
            Ok(tls_stream) => {
                let verified_san = extract_verified_client_san(&tls_stream);
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let mut router = app.clone();
                    let san = verified_san.clone();
                    async move {
                        let req = prepare_mtls_request(req, san.as_ref());
                        let _ = std::future::poll_fn(|cx| {
                            <Router as TowerService<Request<Incoming>>>::poll_ready(&mut router, cx)
                        })
                        .await;
                        <Router as TowerService<Request<Incoming>>>::call(&mut router, req).await
                    }
                });
                serve_io(tls_stream, service, peer_addr, shutdown_rx).await;
            }
            Err(err) => {
                warn!(peer = %peer_addr, error = %err, "mTLS handshake failed");
            }
        },
        None => {
            let service = TowerToHyperService::new(app);
            serve_io(tcp_stream, service, peer_addr, shutdown_rx).await;
        }
    }
}

async fn serve_io<I, S, B>(
    io: I,
    service: S,
    peer_addr: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: HyperService<Request<Incoming>, Response = Response<B>>,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let builder = AutoConnBuilder::new(TokioExecutor::new());
    let conn = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(conn);

    let wait_shutdown = async {
        let _ = shutdown_rx.wait_for(|&shutting_down| shutting_down).await;
    };

    tokio::select! {
        res = &mut conn => {
            if let Err(err) = res {
                debug!(peer = %peer_addr, error = %err, "HTTP connection closed with error");
            }
        }
        () = wait_shutdown => {
            conn.as_mut().graceful_shutdown();
            if let Err(err) = conn.await {
                debug!(peer = %peer_addr, error = %err, "HTTP connection error during graceful shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use tempfile::tempdir;

    #[test]
    fn test_prepare_mtls_request_strips_spoofed_header_and_attaches_extension() {
        let mut req = Request::builder()
            .uri("/api/v1/cas/status")
            .body(())
            .unwrap();
        req.headers_mut().insert(
            "x-client-cert-san",
            HeaderValue::from_static("spoofed.node-a.example"),
        );

        let prepared_with_san = prepare_mtls_request(
            req,
            Some(&VerifiedClientSan("verified.node-a.example".into())),
        );
        assert!(prepared_with_san
            .headers()
            .get("x-client-cert-san")
            .is_none());
        assert_eq!(
            prepared_with_san
                .extensions()
                .get::<VerifiedClientSan>()
                .map(|v| v.0.as_str()),
            Some("verified.node-a.example")
        );

        let mut req_no_san = Request::builder()
            .uri("/api/v1/cas/status")
            .body(())
            .unwrap();
        req_no_san.headers_mut().insert(
            "x-client-cert-san",
            HeaderValue::from_static("spoofed.node-a.example"),
        );
        let prepared_without_san = prepare_mtls_request(req_no_san, None);
        assert!(prepared_without_san
            .headers()
            .get("x-client-cert-san")
            .is_none());
        assert!(prepared_without_san
            .extensions()
            .get::<VerifiedClientSan>()
            .is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_build_listener_tls_acceptor_fallback_and_require_tls() {
        let tmp = tempdir().unwrap();
        let missing_ca = tmp.path().join("missing-ca.crt");
        let missing_cert = tmp.path().join("missing-server.crt");
        let missing_key = tmp.path().join("missing-server.key");

        let cfg_fallback = AppConfig::new(tmp.path(), "https://registry.example:8444")
            .with_tls_paths(&missing_ca, &missing_cert, &missing_key)
            .with_require_tls(false);
        assert!(build_listener_tls_acceptor(&cfg_fallback)
            .unwrap()
            .is_none());

        let cfg_required = AppConfig::new(tmp.path(), "https://registry.example:8444")
            .with_tls_paths(&missing_ca, &missing_cert, &missing_key)
            .with_require_tls(true);
        let err = match build_listener_tls_acceptor(&cfg_required) {
            Ok(_) => panic!("expected error when require_tls is true"),
            Err(err) => err,
        };
        assert!(matches!(err, AuthError::Tls(_)));
    }
}
