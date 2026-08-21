//! Enhanced Incident Management API routes — tasks, observables, and templates.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::routes::AppState;
use crate::services::incidents;

// ── Task Routes ──────────────────────────────────────────────────────────────

/// POST /api/v1/cases/:id/tasks
pub async fn create_task_handler(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Json(payload): Json<incidents::CreateTaskRequest>,
) -> Result<Json<incidents::CaseTask>, (StatusCode, String)> {
    let task = incidents::create_task(&state.db, case_id, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(task))
}

/// GET /api/v1/cases/:id/tasks
pub async fn list_tasks_handler(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<Vec<incidents::CaseTask>>, (StatusCode, String)> {
    let tasks = incidents::list_tasks(&state.db, case_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(tasks))
}

/// PATCH /api/v1/tasks/:id
pub async fn update_task_handler(
    State(state): State<AppState>,
    Path(task_id): Path<Uuid>,
    Json(payload): Json<incidents::UpdateTaskRequest>,
) -> Result<Json<incidents::CaseTask>, (StatusCode, String)> {
    match incidents::update_task(&state.db, task_id, payload).await {
        Ok(task) => Ok(Json(task)),
        Err(e) => {
            if e.to_string().contains("not found") {
                Err((StatusCode::NOT_FOUND, e.to_string()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }
}

/// DELETE /api/v1/tasks/:id
pub async fn delete_task_handler(
    State(state): State<AppState>,
    Path(task_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    incidents::delete_task(&state.db, task_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Observable Routes ────────────────────────────────────────────────────────

/// POST /api/v1/cases/:id/observables
pub async fn create_observable_handler(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Json(payload): Json<incidents::CreateObservableRequest>,
) -> Result<Json<incidents::Observable>, (StatusCode, String)> {
    let obs = incidents::create_observable(&state.db, case_id, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(obs))
}

/// GET /api/v1/cases/:id/observables
pub async fn list_observables_handler(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<Vec<incidents::Observable>>, (StatusCode, String)> {
    let observables = incidents::list_observables(&state.db, case_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(observables))
}

/// PATCH /api/v1/observables/:id
pub async fn update_observable_handler(
    State(state): State<AppState>,
    Path(obs_id): Path<Uuid>,
    Json(payload): Json<incidents::UpdateObservableRequest>,
) -> Result<Json<incidents::Observable>, (StatusCode, String)> {
    match incidents::update_observable(&state.db, obs_id, payload).await {
        Ok(obs) => Ok(Json(obs)),
        Err(e) => {
            if e.to_string().contains("not found") {
                Err((StatusCode::NOT_FOUND, e.to_string()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }
}

/// DELETE /api/v1/observables/:id
pub async fn delete_observable_handler(
    State(state): State<AppState>,
    Path(obs_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    incidents::delete_observable(&state.db, obs_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Template Routes ──────────────────────────────────────────────────────────

/// GET /api/v1/templates
pub async fn list_templates_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<incidents::CaseTemplate>>, (StatusCode, String)> {
    let templates = incidents::list_templates(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(templates))
}

/// GET /api/v1/templates/:id
pub async fn get_template_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<incidents::CaseTemplate>, (StatusCode, String)> {
    match incidents::get_template(&state.db, id).await {
        Ok(Some(template)) => Ok(Json(template)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Template not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// POST /api/v1/cases/:id/apply-template/:template_id
pub async fn apply_template_handler(
    State(state): State<AppState>,
    Path((case_id, template_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (task_count, obs_count) = incidents::apply_template(&state.db, template_id, case_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "tasks_created": task_count,
        "observables_created": obs_count,
    })))
}

/// GET /api/v1/cases/:id/progress
pub async fn case_progress_handler(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (completed, total) = incidents::get_case_progress(&state.db, case_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "completed": completed,
        "total": total,
        "percentage": if total > 0 { (completed as f64 / total as f64 * 100.0) as u32 } else { 0 },
    })))
}
