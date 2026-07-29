//! Route definitions for the Shieldgrid API.
//!
//! `build_router` is the single construction point for the Axum [`Router`].
//! It accepts [`AppState`] containing the registered connectors so every
//! handler can reach them via Axum's state extraction.

use axum::{routing::get, Router};
use std::sync::Arc;

use crate::connectors::Connector;

pub mod alerts;
pub mod health;

// ── App state ─────────────────────────────────────────────────────────────────

/// Shared state threaded through every Axum request handler.
///
/// Cloning is cheap — `Arc<dyn Connector>` bumps a reference count, and the
/// outer `Vec` is small (one entry per registered connector).
#[derive(Clone)]
pub struct AppState {
    /// All registered connectors.  Empty in tests; populated at startup.
    pub connectors: Vec<Arc<dyn Connector>>,
    /// Connection pool for the PostgreSQL database.
    #[allow(dead_code)]
    pub db: sqlx::PgPool,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the main application router with all registered routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/api/v1/alerts", get(alerts::alerts_handler))
        .with_state(state)
}
