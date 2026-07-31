//! Alert routes — persisted alert store, filled by the background ingest loop
//! (`services/ingest.rs`).
//!
//! # Endpoints
//!
//! - `GET /api/v1/alerts` — list persisted alerts, newest first.
//! - `PATCH /api/v1/alerts/{id}` — set an alert's lifecycle status.
//!
//! # Query parameters (GET)
//!
//! | Parameter | Type | Default | Description |
//! |---|---|---|---|
//! | `since` | RFC 3339 timestamp | 24 h ago | Lower bound (exclusive) on alert timestamp |
//! | `connector_id` | string | — | Only alerts from this connector |
//! | `severity` | string | — | Only alerts of this severity (`info`–`critical`) |
//! | `status` | string | — | Only alerts in this state (`open`/`acknowledged`/`closed`) |
//! | `limit` | integer | 200 | Max rows (capped at 1000) |
//! | `offset` | integer | 0 | Rows to skip for pagination |

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::middleware::{RequireAdmin, RequireRead};
use crate::models::alert::{Severity, UpdateAlertRequest};
use crate::routes::AppState;
use crate::services;

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct AlertsQuery {
    /// Only return alerts newer than this timestamp (RFC 3339).
    /// Defaults to 24 hours ago if omitted.
    since: Option<DateTime<Utc>>,
    /// Only return alerts from this connector.
    connector_id: Option<String>,
    /// Only return alerts of this severity.
    severity: Option<String>,
    /// Only return alerts in this lifecycle state.
    status: Option<String>,
    /// Maximum rows to return (capped at 1000, default 200).
    limit: Option<i64>,
    /// Rows to skip for pagination.
    offset: Option<i64>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Handler for `GET /api/v1/alerts`.
///
/// Reads from the `alerts` table — no live connector query happens on this
/// request path; freshness comes from the background ingest loop.
pub async fn alerts_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
    Query(params): Query<AlertsQuery>,
) -> impl IntoResponse {
    let severity = match params.severity {
        Some(raw) => match Severity::from_str(&raw) {
            Some(s) => Some(s),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                    "invalid severity '{}' (expected one of: info, low, medium, high, critical)",
                    raw
                ),
                )
                    .into_response()
            }
        },
        None => None,
    };

    let filters = services::alerts::ListAlertFilters {
        since: Some(
            params
                .since
                .unwrap_or_else(|| Utc::now() - Duration::hours(24)),
        ),
        connector_id: params.connector_id,
        severity,
        status: params
            .status
            .as_deref()
            .and_then(crate::models::alert::AlertStatus::from_str),
        limit: Some(params.limit.unwrap_or(200).min(1000)),
        offset: params.offset,
    };

    match services::alerts::list_alerts(&state.db, &filters).await {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list alerts: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handler for `PATCH /api/v1/alerts/{id}` — update an alert's status.
pub async fn update_alert_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateAlertRequest>,
) -> impl IntoResponse {
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(uid) => uid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let updated = match services::alerts::update_alert_status(&state.db, id, payload.status).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Failed to update alert status: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'update_alert_status', $3)",
        audit_id,
        actor_id,
        format!("{}:{}", id, updated.status.as_str())
    )
    .execute(&state.db)
    .await;

    (StatusCode::OK, Json(updated)).into_response()
}
