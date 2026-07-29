/// `GET /api/v1/alerts` — alerts from all registered connectors, normalised
/// and merged.
///
/// # Query parameters
///
/// | Parameter | Type | Default | Description |
/// |---|---|---|---|
/// | `since` | RFC 3339 timestamp | 24 h ago | Lower bound (exclusive) on alert timestamp |
///
/// # Response
///
/// Always returns **HTTP 200** with a JSON array of [`NormalizedAlert`].
/// Returns an empty array `[]` if no connectors are registered or none have
/// alerts newer than `since`.
///
/// **Known Phase 0 limitation:** results are capped at 500 per connector.
/// Pagination is deferred to Phase 1.

use axum::{extract::{Query, State}, Json};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::models::alert::NormalizedAlert;
use crate::routes::AppState;

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct AlertsQuery {
    /// Only return alerts newer than this timestamp (RFC 3339).
    /// Defaults to 24 hours ago if omitted.
    since: Option<DateTime<Utc>>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// Handler for `GET /api/v1/alerts`.
pub async fn alerts_handler(
    State(state): State<AppState>,
    Query(params): Query<AlertsQuery>,
) -> Json<Vec<NormalizedAlert>> {
    let since = params
        .since
        .unwrap_or_else(|| Utc::now() - Duration::hours(24));

    let mut all_alerts: Vec<NormalizedAlert> = Vec::new();

    for connector in &state.connectors {
        match connector.fetch_alerts(since).await {
            Ok(mut alerts) => all_alerts.append(&mut alerts),
            Err(e) => {
                // Log the error but keep going — one failing connector should
                // not suppress results from healthy ones.
                tracing::warn!(connector = connector.id(), error = %e, "fetch_alerts failed");
            }
        }
    }

    // Sort merged results newest-first.
    all_alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Json(all_alerts)
}
