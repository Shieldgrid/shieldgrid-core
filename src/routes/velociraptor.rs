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

/// Boxed future produced by the execution-path selection below.
type ExecuteFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<Vec<serde_json::Value>>> + Send + 'a>,
>;

/// `POST /api/v1/velociraptor/query` — execute a free-form VQL query.
///
/// Server scope (no `client_id`): the VQL runs as-is on the server.
///
/// Client scope (`client_id` set): the VQL must be an artifact call in the
/// form `SELECT * FROM Artifact.<Name>(Key='value', ...)`; it is dispatched to
/// the endpoint as a real collection and its results are returned. (The plain
/// `FROM clients(...)` form silently returns nothing via the raw gRPC API.)
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

    let start = Instant::now();
    let client_id = payload.client_id.as_ref().map(|s| s.trim().to_string());
    let query_text = payload.vql.trim().to_string();

    // Decide the execution path and build the audit target.
    let (audit_target, execute): (String, ExecuteFuture<'_>) = match client_id.as_deref() {
        Some(cid) if !cid.is_empty() => match parse_artifact_call(&query_text) {
            Some(call) => {
                let params_summary = call
                    .params
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let target = format!(
                    "velociraptor:client:{}:artifact:{}:params:{}",
                    cid,
                    call.name,
                    params_summary.chars().take(200).collect::<String>()
                );
                let execute = async move {
                    connector
                        .run_artifact_on_client(&call.name, &call.params, cid)
                        .await
                };
                (target, Box::pin(execute))
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "client-scoped queries must call an artifact: SELECT * FROM Artifact.<Name>(Key='value', ...)"
                    })),
                )
                    .into_response();
            }
        },
        _ => {
            let target = format!(
                "velociraptor:server:vql:{}",
                query_text.chars().take(400).collect::<String>()
            );
            let vql = query_text.clone();
            let execute = async move { connector.run_query(&vql).await };
            (target, Box::pin(execute))
        }
    };

    // Audit BEFORE execution (Rule 7: log before + after real actions).
    audit(&state, actor, "vql_query", &audit_target).await;

    let result = execute.await;

    match result {
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

            tracing::warn!("velociraptor query failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": e.to_string(),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                })),
            )
                .into_response()
        }
    }
}

/// A parsed artifact call: `Artifact.<Name>(Key='value', Other=1)`.
#[derive(Debug, PartialEq)]
struct ArtifactCall {
    name: String,
    params: Vec<(String, String)>,
}

/// Parse a client-scoped artifact call from VQL.
///
/// Accepts the canonical form produced by the UI:
/// `SELECT * FROM Artifact.Linux.Sys.BashShell(Command='ls -l')`.
fn parse_artifact_call(vql: &str) -> Option<ArtifactCall> {
    let marker = "Artifact.";
    let idx = vql.find(marker)?;
    let rest = &vql[idx + marker.len()..];

    // Artifact name: alphanumerics, underscores and dots.
    let mut name = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_alphanumeric() || c == '_' || c == '.' {
            name.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if name.is_empty() {
        return None;
    }

    let remainder: String = chars.collect();
    let remainder = remainder.trim_start();
    if !remainder.starts_with('(') {
        return Some(ArtifactCall {
            name,
            params: Vec::new(),
        });
    }

    // Find the matching closing paren (no nested groups expected).
    let mut end = None;
    let mut depth = 0i32;
    for (i, c) in remainder.char_indices().skip(1) {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => {
                end = Some(i);
                break;
            }
            ')' => depth -= 1,
            _ => {}
        }
    }
    let end = end?;
    let args_str = &remainder[1..end];

    let mut params = Vec::new();
    for arg in split_top_level_commas(args_str) {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if let Some((k, v)) = arg.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim();
            if k.is_empty() || v.is_empty() {
                continue;
            }
            params.push((k, unquote_value(v)));
        }
    }

    Some(ArtifactCall { name, params })
}

/// Split a string on commas that are not inside single or double quotes.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_str = false;
    let mut quote = ' ';
    for (i, c) in s.char_indices() {
        if in_str {
            if c == quote {
                in_str = false;
            }
        } else if c == '\'' || c == '"' {
            in_str = true;
            quote = c;
        } else if c == ',' {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Strip matching quotes from a VQL literal; leaves numbers/bare tokens intact.
fn unquote_value(v: &str) -> String {
    if v.len() >= 2 {
        let b = v.as_bytes();
        if (b[0] == b'\'' && b[v.len() - 1] == b'\'') || (b[0] == b'"' && b[v.len() - 1] == b'"') {
            return v[1..v.len() - 1]
                .replace("\\'", "'")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_artifact_call_with_params() {
        let call =
            parse_artifact_call("SELECT * FROM Artifact.Linux.Sys.BashShell(Command='ls -l /')")
                .unwrap();
        assert_eq!(call.name, "Linux.Sys.BashShell");
        assert_eq!(
            call.params,
            vec![("Command".to_string(), "ls -l /".to_string())]
        );
    }

    #[test]
    fn parses_artifact_call_without_params() {
        let call = parse_artifact_call("SELECT * FROM Artifact.Linux.Sys.Pslist()").unwrap();
        assert_eq!(call.name, "Linux.Sys.Pslist");
        assert!(call.params.is_empty());
    }

    #[test]
    fn parses_multiple_params_and_mixed_quotes() {
        let call = parse_artifact_call(
            r#"SELECT * FROM Artifact.Linux.Sys.BashShell(Command="echo it's fine", Timeout=30)"#,
        )
        .unwrap();
        assert_eq!(call.name, "Linux.Sys.BashShell");
        assert_eq!(
            call.params,
            vec![
                ("Command".to_string(), "echo it's fine".to_string()),
                ("Timeout".to_string(), "30".to_string()),
            ]
        );
    }

    #[test]
    fn returns_none_for_non_artifact_vql() {
        assert!(parse_artifact_call("SELECT * FROM clients()").is_none());
    }

    #[test]
    fn splits_commas_outside_quotes() {
        let parts = split_top_level_commas("a=1, b='x,y', c=2");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].trim(), "b='x,y'");
    }
}
