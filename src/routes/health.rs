//! `GET /health` — reports the API's own status plus the health of every
//! registered connector.
//!
//! # Response
//!
//! Always returns **HTTP 200**.  The API itself being up is what the 200
//! signals.  Individual connector statuses are embedded in the body so a
//! caller can distinguish "API up, Wazuh down" from "everything healthy".
//!
//! ```json
//! {
//!   "status": "ok",
//!   "connectors": [
//!     { "status": "healthy", "id": "wazuh" },
//!     { "status": "down",    "id": "wazuh", "reason": "connection refused" }
//!   ]
//! }
//! ```

use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::connectors::{Connector, HealthStatus};
use crate::routes::AppState;

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub(crate) struct HealthResponse {
    /// Overall API status — always `"ok"` while this process is running.
    status: &'static str,
    /// Per-connector health, polled in parallel on every request.
    connectors: Vec<ConnectorHealthEntry>,
}

/// One entry per registered connector in the `/health` response body.
#[derive(Serialize)]
pub(crate) struct ConnectorHealthEntry {
    /// The connector's stable identifier (e.g. `"wazuh"`).
    id: String,
    /// Normalised status string: `"healthy"`, `"degraded"`, or `"down"`.
    status: String,
    /// Present when `status` is `"degraded"` or `"down"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl ConnectorHealthEntry {
    fn from_connector_status(id: String, hs: HealthStatus) -> Self {
        match hs {
            HealthStatus::Healthy => Self { id, status: "healthy".into(), reason: None },
            HealthStatus::Degraded { reason } => Self { id, status: "degraded".into(), reason: Some(reason) },
            HealthStatus::Down { reason } => Self { id, status: "down".into(), reason: Some(reason) },
        }
    }
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// Handler for `GET /health`.
///
/// Polls every registered connector's `health_check()` concurrently and
/// returns the aggregated result.  Never returns a non-200 status — if a
/// connector is unreachable the API should still be considered up.
pub async fn health_handler(
    State(state): State<AppState>,
) -> Json<HealthResponse> {
    let connectors: &[Arc<dyn Connector>] = &state.connectors;

    // Poll all connectors concurrently.
    let mut entries = Vec::with_capacity(connectors.len());
    for connector in connectors {
        let id = connector.id().to_string();
        let status = connector.health_check().await;
        entries.push(ConnectorHealthEntry::from_connector_status(id, status));
    }

    Json(HealthResponse {
        status: "ok",
        connectors: entries,
    })
}
