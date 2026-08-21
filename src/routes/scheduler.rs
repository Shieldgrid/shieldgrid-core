//! Scheduler API endpoints — manage scheduled actions and automation.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::AppState;
use crate::services::scheduler;

/// Request to create a new scheduled action.
#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub description: Option<String>,
    pub connector_id: String,
    pub action_type: String,
    pub target_id: Option<String>,
    pub trigger: serde_json::Value,
    pub params: Option<serde_json::Value>,
}

/// Request to update a scheduled action.
#[derive(Debug, Deserialize)]
pub struct UpdateScheduleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub trigger: Option<serde_json::Value>,
    pub params: Option<serde_json::Value>,
}

/// Response from listing scheduled actions.
#[derive(Debug, Serialize)]
pub struct ListSchedulesResponse {
    pub schedules: Vec<serde_json::Value>,
}

/// Response from getting execution history.
#[derive(Debug, Serialize)]
pub struct ExecutionHistoryResponse {
    pub executions: Vec<serde_json::Value>,
}

/// GET /api/v1/scheduler/schedules
///
/// List all scheduled actions.
pub async fn list_schedules_handler(
    State(state): State<AppState>,
) -> Result<Json<ListSchedulesResponse>, (StatusCode, String)> {
    match scheduler::list_schedules(&state.db).await {
        Ok(schedules) => {
            let schedules_json: Vec<serde_json::Value> = schedules
                .iter()
                .map(|s| serde_json::to_value(s).unwrap())
                .collect();
            Ok(Json(ListSchedulesResponse {
                schedules: schedules_json,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list schedules: {e}"),
        )),
    }
}

/// POST /api/v1/scheduler/schedules
///
/// Create a new scheduled action.
pub async fn create_schedule_handler(
    State(state): State<AppState>,
    Json(payload): Json<CreateScheduleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match scheduler::create_schedule(
        &state.db,
        &payload.name,
        &payload.description.unwrap_or_default(),
        &payload.connector_id,
        &payload.action_type,
        payload.target_id.as_deref(),
        payload.trigger,
        payload.params.unwrap_or(serde_json::json!({})),
    )
    .await
    {
        Ok(schedule) => Ok(Json(serde_json::to_value(&schedule).unwrap())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create schedule: {e}"),
        )),
    }
}

/// GET /api/v1/scheduler/schedules/{id}
///
/// Get a specific scheduled action.
pub async fn get_schedule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match scheduler::get_schedule(&state.db, id).await {
        Ok(Some(schedule)) => Ok(Json(serde_json::to_value(&schedule).unwrap())),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Schedule not found".to_string())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get schedule: {e}"),
        )),
    }
}

/// PATCH /api/v1/scheduler/schedules/{id}
///
/// Update a scheduled action.
pub async fn update_schedule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateScheduleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match scheduler::update_schedule(
        &state.db,
        id,
        payload.name.as_deref(),
        payload.description.as_deref(),
        payload.enabled,
        payload.trigger,
        payload.params,
    )
    .await
    {
        Ok(schedule) => Ok(Json(serde_json::to_value(&schedule).unwrap())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update schedule: {e}"),
        )),
    }
}

/// DELETE /api/v1/scheduler/schedules/{id}
///
/// Delete a scheduled action.
pub async fn delete_schedule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    match scheduler::delete_schedule(&state.db, id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete schedule: {e}"),
        )),
    }
}

/// GET /api/v1/scheduler/schedules/{id}/executions
///
/// Get execution history for a scheduled action.
pub async fn get_execution_history_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionHistoryResponse>, (StatusCode, String)> {
    match scheduler::get_execution_history(&state.db, id, 50).await {
        Ok(executions) => {
            let executions_json: Vec<serde_json::Value> = executions
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .collect();
            Ok(Json(ExecutionHistoryResponse {
                executions: executions_json,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get execution history: {e}"),
        )),
    }
}
