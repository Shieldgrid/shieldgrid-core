//! Route definitions for the Shieldgrid API.
//!
//! `build_router` is the single construction point for the Axum [`Router`].
//! It accepts [`AppState`] containing the registered connectors so every
//! handler can reach them via Axum's state extraction.

use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::connectors::Connector;

pub mod alerts;
pub mod audit;
pub mod auth;
pub mod cases;
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
    pub db: sqlx::PgPool,
    /// Application configuration
    pub config: Arc<crate::config::Config>,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the main application router with all registered routes.
pub fn build_router(state: AppState) -> Router {
    let allowed_origin = state
        .config
        .allowed_origin
        .parse::<axum::http::HeaderValue>()
        .expect("ALLOWED_ORIGIN must be a valid HTTP header value");

    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/api/v1/alerts", get(alerts::alerts_handler))
        .route(
            "/api/v1/auth/login",
            axum::routing::post(auth::login_handler),
        )
        .route(
            "/api/v1/auth/me",
            axum::routing::get(auth::me_handler),
        )
        .route(
            "/api/v1/auth/logout",
            axum::routing::post(auth::logout_handler),
        )
        .route(
            "/api/v1/audit",
            axum::routing::get(audit::list_audit_log_handler),
        )
        .route(
            "/api/v1/cases",
            axum::routing::get(cases::list_cases_handler).post(cases::create_case_handler),
        )
        .route(
            "/api/v1/cases/{id}",
            axum::routing::get(cases::get_case_handler).patch(cases::update_case_handler),
        )
        .route(
            "/api/v1/cases/{id}/alerts",
            axum::routing::get(cases::list_case_alerts_handler).post(cases::attach_alert_handler),
        )
        .route(
            "/api/v1/cases/{id}/alerts/{alert_id}",
            axum::routing::delete(cases::detach_alert_handler),
        )
        .layer(cors)
        .with_state(state)
}
