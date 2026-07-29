// Shieldgrid Core — entry point.
//
// Initialises tracing, loads config from the environment, builds the Axum
// router and starts the HTTP listener.  All config is read via `config.rs`;
// nothing else in the codebase should call `std::env::var` directly.

use std::sync::Arc;
use std::net::SocketAddr;
use tracing::info;

mod config;
mod connectors;
mod models;
mod routes;
mod services;

use connectors::wazuh::WazuhConnector;
use routes::AppState;

#[tokio::main]
async fn main() {
    // Structured logging — default to INFO, overridable via RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::from_env().unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    // Build the connector registry.  Phase 0: Wazuh only.
    let wazuh = WazuhConnector::new(
        cfg.opensearch_url.clone(),
        cfg.opensearch_user.clone(),
        cfg.opensearch_pass.clone(),
    );
    let state = AppState {
        connectors: vec![Arc::new(wazuh)],
    };

    let app = routes::build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    info!("listening on {}", addr);

    axum::serve(listener, app).await.unwrap();
}
