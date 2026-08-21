//! Notification API routes — manage channels, rules, and logs.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::routes::AppState;
use crate::services::notifications;

/// GET /api/v1/notifications/channels
pub async fn list_channels_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<notifications::NotificationChannel>>, (StatusCode, String)> {
    let channels = notifications::list_channels(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(channels))
}

/// POST /api/v1/notifications/channels
pub async fn create_channel_handler(
    State(state): State<AppState>,
    Json(payload): Json<notifications::CreateChannelRequest>,
) -> Result<Json<notifications::NotificationChannel>, (StatusCode, String)> {
    let channel = notifications::create_channel(&state.db, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(channel))
}

/// PATCH /api/v1/notifications/channels/:id
pub async fn update_channel_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<notifications::UpdateChannelRequest>,
) -> Result<Json<notifications::NotificationChannel>, (StatusCode, String)> {
    match notifications::update_channel(&state.db, id, payload).await {
        Ok(channel) => Ok(Json(channel)),
        Err(e) => {
            if e.to_string().contains("not found") {
                Err((StatusCode::NOT_FOUND, e.to_string()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }
}

/// DELETE /api/v1/notifications/channels/:id
pub async fn delete_channel_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    notifications::delete_channel(&state.db, id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/notifications/rules
pub async fn list_rules_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<notifications::NotificationRule>>, (StatusCode, String)> {
    let rules = notifications::list_rules(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rules))
}

/// POST /api/v1/notifications/rules
pub async fn create_rule_handler(
    State(state): State<AppState>,
    Json(payload): Json<notifications::CreateRuleRequest>,
) -> Result<Json<notifications::NotificationRule>, (StatusCode, String)> {
    let rule = notifications::create_rule(&state.db, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rule))
}

/// DELETE /api/v1/notifications/rules/:id
pub async fn delete_rule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    notifications::delete_rule(&state.db, id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/notifications/send
pub async fn send_notification_handler(
    State(state): State<AppState>,
    Json(payload): Json<notifications::SendNotificationRequest>,
) -> Result<Json<notifications::NotificationLog>, (StatusCode, String)> {
    let log = notifications::send_notification(&state.db, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(log))
}

/// GET /api/v1/notifications/logs
pub async fn list_logs_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<notifications::NotificationLog>>, (StatusCode, String)> {
    let logs = notifications::list_notification_logs(&state.db, 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(logs))
}

/// GET /api/v1/notifications/stats
pub async fn notification_stats_handler(
    State(state): State<AppState>,
) -> Result<Json<notifications::NotificationStats>, (StatusCode, String)> {
    let stats = notifications::get_notification_stats(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(stats))
}
