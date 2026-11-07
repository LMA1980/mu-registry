use mu_registry::{api::build_app_router, AppConfig, AppState, CasStore, DuckDbCatalog};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("mu-registry listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("mu-registry daemon stopped cleanly.");
    Ok(())
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
