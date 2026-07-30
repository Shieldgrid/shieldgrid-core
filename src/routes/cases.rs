use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::middleware::RequireAdmin;
use crate::models::case::{Case, CreateCaseRequest, UpdateCaseRequest};
use crate::routes::AppState;

/// POST /api/v1/cases
pub async fn create_case_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Json(payload): Json<CreateCaseRequest>,
) -> impl IntoResponse {
    let case_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let result = sqlx::query_as!(
        Case,
        "INSERT INTO cases (id, title, status, created_at, updated_at) 
         VALUES ($1, $2, 'Open', $3, $4) 
         RETURNING id, title, status, assigned_to, created_at, updated_at",
        case_id,
        payload.title,
        now,
        now
    )
    .fetch_one(&state.db)
    .await;

    let case = match result {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create case: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'create_case', $3)",
        audit_id,
        actor_id,
        case_id.to_string()
    )
    .execute(&state.db)
    .await;

    (StatusCode::CREATED, Json(case)).into_response()
}

/// GET /api/v1/cases
pub async fn list_cases_handler(
    _auth: RequireAdmin,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let result = sqlx::query_as!(
        Case,
        "SELECT id, title, status, assigned_to, created_at, updated_at 
         FROM cases 
         ORDER BY created_at DESC 
         LIMIT 100"
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(cases) => (StatusCode::OK, Json(cases)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list cases: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api/v1/cases/:id
pub async fn get_case_handler(
    _auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query_as!(
        Case,
        "SELECT id, title, status, assigned_to, created_at, updated_at 
         FROM cases 
         WHERE id = $1",
        id
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(case)) => (StatusCode::OK, Json(case)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Failed to get case: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// PATCH /api/v1/cases/:id
pub async fn update_case_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCaseRequest>,
) -> impl IntoResponse {
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(uid) => uid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let result = sqlx::query_as!(
        Case,
        "UPDATE cases 
         SET 
            status = COALESCE($1, status),
            assigned_to = COALESCE($2, assigned_to),
            updated_at = $3
         WHERE id = $4
         RETURNING id, title, status, assigned_to, created_at, updated_at",
        payload.status,
        payload.assigned_to,
        chrono::Utc::now(),
        id
    )
    .fetch_optional(&state.db)
    .await;

    let case = match result {
        Ok(Some(c)) => c,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Failed to update case: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'update_case', $3)",
        audit_id,
        actor_id,
        id.to_string()
    )
    .execute(&state.db)
    .await;

    (StatusCode::OK, Json(case)).into_response()
}

/// POST /api/v1/cases/:id/alerts
pub async fn attach_alert_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<crate::models::case::LinkAlertRequest>,
) -> impl IntoResponse {
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(uid) => uid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let result = sqlx::query!(
        "INSERT INTO case_alerts (case_id, alert_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        id,
        payload.alert_id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        tracing::error!("Failed to attach alert to case: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'attach_alert', $3)",
        audit_id,
        actor_id,
        format!("{id}/{}", payload.alert_id)
    )
    .execute(&state.db)
    .await;

    StatusCode::CREATED.into_response()
}

/// DELETE /api/v1/cases/:id/alerts/:alert_id
pub async fn detach_alert_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Path((id, alert_id)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(uid) => uid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let result = sqlx::query!(
        "DELETE FROM case_alerts WHERE case_id = $1 AND alert_id = $2",
        id,
        alert_id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        tracing::error!("Failed to detach alert from case: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'detach_alert', $3)",
        audit_id,
        actor_id,
        format!("{id}/{alert_id}")
    )
    .execute(&state.db)
    .await;

    StatusCode::NO_CONTENT.into_response()
}

/// GET /api/v1/cases/:id/alerts
pub async fn list_case_alerts_handler(
    _auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query_scalar!("SELECT alert_id FROM case_alerts WHERE case_id = $1", id)
        .fetch_all(&state.db)
        .await;

    match result {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list case alerts: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// POST /api/v1/cases/:id/actions
pub async fn execute_action_handler(
    auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<crate::models::action::ActionRequest>,
) -> impl IntoResponse {
    let actor_id = match Uuid::parse_str(&auth.0.sub) {
        Ok(uid) => uid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let connector = match state.connectors.iter().find(|c| c.id() == payload.connector_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Connector not found").into_response(),
    };

    let target_str = format!("case:{}:target:{}:type:{}", id, payload.target_id, payload.action_type);

    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'action_request', $3)",
        audit_id,
        actor_id,
        target_str
    )
    .execute(&state.db)
    .await;

    let action_cmd = crate::models::action::ResponseAction {
        action_type: payload.action_type.clone(),
        target_id: payload.target_id.clone(),
        requested_by: actor_id,
        case_id: Some(id),
    };

    let result = connector.push_action(action_cmd).await;

    let (audit_action, detail) = match &result {
        Ok(res) => {
            if res.success {
                ("action_success", res.detail.clone())
            } else if res.is_timeout {
                ("action_timeout", res.detail.clone())
            } else {
                ("action_failure", res.detail.clone())
            }
        }
        Err(e) => ("action_error", e.to_string()),
    };

    let final_target_str = format!("{}:detail:{}", target_str, detail);
    
    let audit_id2 = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, $3, $4)",
        audit_id2,
        actor_id,
        audit_action,
        final_target_str
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/v1/cases/:id/actions
pub async fn list_case_actions_handler(
    _auth: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let target_prefix = format!("case:{}%", id);
    let result = sqlx::query_as!(
        crate::models::audit::AuditLog,
        "SELECT id, actor_id, action, target, timestamp 
         FROM audit_log 
         WHERE action LIKE 'action_%' AND target LIKE $1 
         ORDER BY timestamp DESC",
         target_prefix
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(logs) => (StatusCode::OK, Json(logs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list case actions: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
