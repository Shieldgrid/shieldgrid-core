//! Velociraptor operational routes — client inventory, artifact browser and a
//! free-form VQL shell.
//!
//! These routes reach the concrete [`VelociraptorConnector`] (not the generic
//! [`Connector`] trait) via downcasting, because running arbitrary VQL and
//! listing clients/artifacts are connector-specific capabilities.
//!
//! # Auth / security
//!
//! - `clients` and `artifacts` listing require `admin` or `mcp-read`.
//! - The free-form `query` endpoint requires `admin` — arbitrary VQL can read
//!   any server-side data, so it is gated the hardest. Every query is
//!   audit-logged before and after execution.
//! - Queries are capped server-side at 500 rows / 30 s by the connector.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

use crate::connectors::velociraptor::VelociraptorConnector;
use crate::middleware::{RequireAdmin, RequireRead};
use crate::routes::AppState;

/// Maximum accepted VQL length — stops a client from shipping megabytes of
/// query text into the audit log.
const MAX_VQL_LEN: usize = 8_192;

/// Request body for `POST /api/v1/velociraptor/query`.
#[derive(Debug, Deserialize)]
pub struct VqlQueryRequest {
    /// VQL to execute, in the server context.
    pub vql: String,
    /// Optional client id. When set, the VQL is scoped to that client using
    /// the documented `FROM clients(client_id=...)` pattern (artifact queries).
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Response body for `POST /api/v1/velociraptor/query`.
#[derive(Debug, Serialize)]
pub struct VqlQueryResponse {
    /// Result rows, each a JSON object.
    pub rows: Vec<serde_json::Value>,
    /// True when the row cap (500) was hit and the result set is incomplete.
    pub truncated: bool,
    /// Wall-clock time the query took, in milliseconds.
    pub elapsed_ms: u64,
}

fn velociraptor(state: &AppState) -> Option<&VelociraptorConnector> {
    state
        .connectors
        .iter()
        .find(|c| c.id() == "velociraptor")
        .and_then(|c| c.as_any().downcast_ref::<VelociraptorConnector>())
}

fn not_registered() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Velociraptor connector not registered",
    )
        .into_response()
}

async fn audit(state: &AppState, actor_id: Option<Uuid>, action: &str, target: &str) {
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        actor_id,
        action,
        target
    )
    .execute(&state.db)
    .await;
}

fn actor_id(claims: &crate::models::auth::Claims) -> Option<Uuid> {
    Uuid::parse_str(&claims.sub).ok()
}

/// `GET /api/v1/velociraptor/clients` — registered endpoints + OS info + last seen.
pub async fn list_clients_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let connector = match velociraptor(&state) {
        Some(c) => c,
        None => return not_registered(),
    };

    let start = Instant::now();
    match connector.list_clients().await {
        Ok(rows) => Json(serde_json::json!({
            "rows": rows,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!("velociraptor.list_clients failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// `GET /api/v1/velociraptor/artifacts` — artifact name/description/parameters.
pub async fn list_artifacts_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let connector = match velociraptor(&state) {
        Some(c) => c,
        None => return not_registered(),
    };

    let start = Instant::now();
    match connector.list_artifacts().await {
        Ok(rows) => Json(serde_json::json!({
            "rows": rows,
            "truncated": rows.len() >= 500,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!("velociraptor.list_artifacts failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// `POST /api/v1/velociraptor/query` — execute a free-form VQL query.
pub async fn run_query_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Json(payload): Json<VqlQueryRequest>,
) -> impl IntoResponse {
    let actor = actor_id(&auth.0);

    if payload.vql.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "vql must not be empty" })),
        )
            .into_response();
    }
    if payload.vql.len() > MAX_VQL_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "vql exceeds the 8192 char limit" })),
        )
            .into_response();
    }

    let connector = match velociraptor(&state) {
        Some(c) => c,
        None => return not_registered(),
    };

    // Client-scoped artifact queries use the documented pattern:
    //   SELECT * FROM Artifact.X() FROM clients(client_id='C.xxx')
    let vql = match payload.client_id.as_ref() {
        Some(cid) if !cid.trim().is_empty() => {
            format!(
                "{} FROM clients(client_id='{}')",
                payload.vql.trim_end(),
                cid
            )
        }
        _ => payload.vql.trim().to_string(),
    };

    // Audit BEFORE execution (Rule 7: log before + after real actions).
    let audit_target = format!(
        "velociraptor:vql:{}",
        vql.chars().take(400).collect::<String>()
    );
    audit(&state, actor, "vql_query", &audit_target).await;

    let start = Instant::now();
    let result = connector.run_query(&vql).await;

    let response = match result {
        Ok(rows) => {
            let truncated = rows.len() >= 500;
            audit(
                &state,
                actor,
                "vql_query_done",
                &format!("velociraptor:vql:{}rows", rows.len()),
            )
            .await;

            (
                StatusCode::OK,
                Json(VqlQueryResponse {
                    rows,
                    truncated,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                }),
            )
                .into_response()
        }
        Err(e) => {
            audit(
                &state,
                actor,
                "vql_query_failed",
                &format!(
                    "velociraptor:vql:{}",
                    e.to_string().chars().take(200).collect::<String>()
                ),
            )
            .await;

            tracing::warn!("velociraptor.run_query failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                })),
            )
                .into_response()
        }
    };

    response
}
