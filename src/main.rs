use axum::Router;
use mu_registry::{
    api::build_app_router,
    server::{
        build_listener_tls_acceptor, serve_router_with_listener, spawn_periodic_cas_scrub,
        DEFAULT_CAS_SCRUB_INTERVAL,
    },
    AppConfig, AppState, CasStore, DuckDbCatalog,
};
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting mu-registry Daemon...");

    let config = Arc::new(AppConfig::from_env());
    let cas = Arc::new(CasStore::new(&config.root_dir));
    cas.init().await?;

    let catalog = DuckDbCatalog::new(config.catalog_path())?;

    let state = AppState {
        config: config.clone(),
        cas: cas.clone(),
        catalog,
    };

    let app = build_app_router(state);
    let listener = TcpListener::bind(&config.listen_addr).await?;
    let (scrub_shutdown_tx, scrub_shutdown_rx) = tokio::sync::watch::channel(false);
    let scrub_handle =
        spawn_periodic_cas_scrub(cas.clone(), DEFAULT_CAS_SCRUB_INTERVAL, scrub_shutdown_rx);

    let serve_res = serve_with_config(listener, app, &config, shutdown_signal()).await;
    let _ = scrub_shutdown_tx.send(true);
    scrub_handle.abort();
    let _ = scrub_handle.await;
    serve_res?;

    info!("mu-registry daemon stopped cleanly.");
    Ok(())
}

/// Serves `app` over `listener` using mTLS when TLS artifacts exist, or plain TCP fallback
/// when absent and `MU_REGISTRY_REQUIRE_TLS` is not enabled.
async fn serve_with_config<F>(
    listener: TcpListener,
    app: Router,
    config: &AppConfig,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: Future<Output = ()> + Send,
{
    let tls_acceptor = build_listener_tls_acceptor(config)?;
    serve_router_with_listener(listener, app, tls_acceptor, shutdown).await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_serve_with_config_plain_tcp_fallback_and_require_tls_failure() {
        let tmp = tempdir().unwrap();
        let cas = Arc::new(CasStore::new(tmp.path()));
        cas.init().await.unwrap();
        let catalog = DuckDbCatalog::in_memory().unwrap();

        let missing_ca = tmp.path().join("ca.crt");
        let missing_cert = tmp.path().join("server.crt");
        let missing_key = tmp.path().join("server.key");

        let required_cfg = Arc::new(
            AppConfig::new(tmp.path(), "https://registry.example:8444")
                .with_tls_paths(&missing_ca, &missing_cert, &missing_key)
                .with_require_tls(true),
        );
        let required_app = build_app_router(AppState {
            config: required_cfg.clone(),
            cas: cas.clone(),
            catalog: catalog.clone(),
        });
        let listener_req = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(
            serve_with_config(listener_req, required_app, &required_cfg, async {})
                .await
                .is_err()
        );

        let fallback_cfg = Arc::new(
            AppConfig::new(tmp.path(), "http://127.0.0.1")
                .with_tls_paths(&missing_ca, &missing_cert, &missing_key)
                .with_require_tls(false),
        );
        let fallback_app = build_app_router(AppState {
            config: fallback_cfg.clone(),
            cas,
            catalog,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            serve_with_config(listener, fallback_app, &fallback_cfg, async move {
                let _ = rx.await;
            })
            .await
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /api/v1/cas/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));

        let _ = tx.send(());
        server_task.await.unwrap().unwrap();
    }
}
