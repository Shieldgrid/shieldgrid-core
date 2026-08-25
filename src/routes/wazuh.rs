//! Wazuh operational routes — agent inventory for the agents dashboard.
//!
//! These routes reach the concrete [`WazuhConnector`] (not the generic
//! [`Connector`] trait) via downcasting, because listing agents against the
//! Wazuh manager REST API is a connector-specific capability.
//!
//! # Auth
//!
//! Agent inventory is read-only, so it requires `admin` or `mcp-read`
//! (`RequireRead`) — the same bar as the Velociraptor client inventory.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::time::Instant;
use uuid::Uuid;

use crate::connectors::wazuh::WazuhConnector;
use crate::middleware::RequireRead;
use crate::routes::AppState;

/// Valid Wazuh agent connection statuses (from the manager API).
pub const AGENT_STATUSES: [&str; 4] = ["active", "disconnected", "never_connected", "pending"];

/// Query parameters for `GET /api/v1/wazuh/agents`.
#[derive(Debug, serde::Deserialize)]
pub struct AgentsQuery {
    /// Optional status filter: `active`, `disconnected`, `never_connected`, `pending`.
    pub status: Option<String>,
}

fn wazuh(state: &AppState) -> Option<&WazuhConnector> {
    state
        .connectors
        .iter()
        .find(|c| c.id() == "wazuh")
        .and_then(|c| c.as_any().downcast_ref::<WazuhConnector>())
}

fn not_registered() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Wazuh connector not registered",
    )
        .into_response()
}

/// `GET /api/v1/wazuh/agents` — registered agents + connection-status summary.
pub async fn list_agents_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
    Query(query): Query<AgentsQuery>,
) -> impl IntoResponse {
    let connector = match wazuh(&state) {
        Some(c) => c,
        None => return not_registered(),
    };

    if let Some(status) = query.status.as_deref() {
        if !AGENT_STATUSES.contains(&status) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid status '{status}'; expected one of {AGENT_STATUSES:?}")
                })),
            )
                .into_response();
        }
    }

    let start = Instant::now();
    match connector.list_agents(query.status.as_deref()).await {
        Ok((agents, summary)) => Json(serde_json::json!({
            "agents": agents,
            "summary": summary,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!("wazuh.list_agents failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}
