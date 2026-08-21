//! Health & Performance Monitoring API routes.

use axum::{extract::State, http::StatusCode, Json};

use crate::routes::AppState;
use crate::services::health_monitor as health_service;

/// GET /api/v1/monitoring/health
///
/// Get comprehensive system health status.
pub async fn system_health_handler(
    State(state): State<AppState>,
) -> Result<Json<health_service::SystemHealth>, (StatusCode, String)> {
    health_service::get_system_health(&state.connectors, &state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}

/// GET /api/v1/monitoring/metrics
///
/// Get system performance metrics.
pub async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<Json<health_service::SystemMetrics>, (StatusCode, String)> {
    health_service::get_system_metrics(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}

/// GET /api/v1/monitoring/ingestion
///
/// Get alert ingestion rate.
pub async fn ingestion_rate_handler(
    State(state): State<AppState>,
) -> Result<Json<health_service::IngestionRate>, (StatusCode, String)> {
    health_service::get_ingestion_rate(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}

/// GET /api/v1/monitoring/dashboard
///
/// Get comprehensive performance dashboard data.
pub async fn dashboard_handler(
    State(state): State<AppState>,
) -> Result<Json<health_service::PerformanceDashboard>, (StatusCode, String)> {
    health_service::get_performance_dashboard(&state.connectors, &state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}

/// GET /api/v1/monitoring/sources
///
/// Get top alert sources.
pub async fn top_sources_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<health_service::AlertSource>>, (StatusCode, String)> {
    health_service::get_top_alert_sources(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}

/// GET /api/v1/monitoring/severity
///
/// Get severity distribution.
pub async fn severity_distribution_handler(
    State(state): State<AppState>,
) -> Result<Json<health_service::SeverityDistribution>, (StatusCode, String)> {
    health_service::get_severity_distribution(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(Json)
}
