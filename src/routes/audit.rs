use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::middleware::RequireAdmin;
use crate::models::audit::AuditLog;
use crate::routes::AppState;

/// GET /api/v1/audit
pub async fn list_audit_log_handler(
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let result = sqlx::query_as!(
        AuditLog,
        "SELECT id, actor_id, action, target, timestamp 
         FROM audit_log 
         ORDER BY timestamp DESC 
         LIMIT 100"
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(logs) => (StatusCode::OK, Json(logs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list audit logs: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
