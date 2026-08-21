//! Shieldgrid Actions API endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::models::action::{ActionExecution, ActionTemplate, ExecuteActionRequest};
use crate::routes::AppState;
use crate::services::actions;

#[derive(Debug, Deserialize)]
pub struct ListExecutionsQuery {
    pub limit: Option<i64>,
}

/// GET /api/v1/actions/templates
///
/// List all available action templates in the catalog.
pub async fn list_action_templates_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<ActionTemplate>>, (StatusCode, String)> {
    match actions::list_templates(&state.db).await {
        Ok(templates) => Ok(Json(templates)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// POST /api/v1/actions/execute
///
/// Execute a containment, remediation, or forensic action.
pub async fn execute_action_handler(
    State(state): State<AppState>,
    Json(payload): Json<ExecuteActionRequest>,
) -> Result<Json<ActionExecution>, (StatusCode, String)> {
    let initiated_by = "analyst@shieldgrid.local";

    match actions::execute_action(payload, initiated_by, &state.connectors, &state.db).await {
        Ok(execution) => Ok(Json(execution)),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// GET /api/v1/actions/executions
///
/// List historical action executions.
pub async fn list_action_executions_handler(
    State(state): State<AppState>,
    Query(query): Query<ListExecutionsQuery>,
) -> Result<Json<Vec<ActionExecution>>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50);
    match actions::list_executions(&state.db, limit).await {
        Ok(executions) => Ok(Json(executions)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/actions/executions/{id}
///
/// Retrieve details of a specific action execution.
pub async fn get_action_execution_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionExecution>, (StatusCode, String)> {
    match actions::get_execution(id, &state.db).await {
        Ok(Some(execution)) => Ok(Json(execution)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "Action execution not found".to_string(),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
