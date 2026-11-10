mod auth;
mod config;
mod db;
mod error;
mod routes;
mod storage;
mod validate;

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("fuzzforge_api=info,info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = Arc::new(config::Config::from_env()?);
    let pool = db::connect(&config.database_url).await?;
    let storage = storage::Storage::new(&config.storage_dir)?;

    tracing::info!(
        storage_dir = %storage.root().display(),
        addr = %config.bind_addr,
        "starting fuzzforge api"
    );

    let state = routes::AppState {
        pool,
        storage,
        config: config.clone(),
    };
    let app = routes::router(state, &config)?;

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
