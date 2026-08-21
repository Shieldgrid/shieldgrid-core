//! AI Analyst routes.

use axum::{extract::State, http::StatusCode, Json};

use crate::routes::AppState;
use crate::services::ai_analyst::{self, SecurityPostureSummary, TriageReport, TriageRequest};

/// POST /api/v1/ai/triage
///
/// Run automated autonomous investigation triage.
pub async fn triage_handler(
    State(state): State<AppState>,
    Json(req): Json<TriageRequest>,
) -> Result<Json<TriageReport>, (StatusCode, String)> {
    match ai_analyst::generate_triage_report(req, &state.config, &state.db).await {
        Ok(report) => Ok(Json(report)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/ai/summary
///
/// Retrieve live security posture and incident synopsis.
pub async fn posture_summary_handler(
    State(state): State<AppState>,
) -> Result<Json<SecurityPostureSummary>, (StatusCode, String)> {
    match ai_analyst::get_security_posture_summary(&state.db).await {
        Ok(summary) => Ok(Json(summary)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
