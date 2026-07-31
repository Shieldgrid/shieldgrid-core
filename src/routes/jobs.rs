//! `GET /api/v1/jobs` — ingest scheduler status for every registered connector.
//!
//! Each row reflects the schedule and last outcome of the background ingest
//! job (`services/ingest.rs`) for one connector: when it last ran, whether it
//! succeeded or failed, where its ingestion watermark sits, and when it is
//! next due.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::middleware::RequireRead;
use crate::models::jobs::Job;
use crate::routes::AppState;

/// Handler for `GET /api/v1/jobs`.
pub async fn list_jobs_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let result = sqlx::query_as!(
        Job,
        "SELECT id, connector_id, name, interval_minutes, enabled,
                last_run_at, last_status, last_error, last_watermark,
                next_run_at, created_at, updated_at
         FROM jobs
         ORDER BY connector_id"
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(jobs) => (StatusCode::OK, Json(jobs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list ingest jobs: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
