//! Network Connector API routes — manage syslog-based device integrations.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::AppState;

/// Request to create a new network connector.
#[derive(Debug, Deserialize)]
pub struct CreateNetworkConnectorRequest {
    pub name: String,
    pub device_type: String,
    pub ip_address: String,
    pub syslog_port: Option<u16>,
    pub syslog_protocol: Option<String>,
    pub config: Option<serde_json::Value>,
}

/// Request to update a network connector.
#[derive(Debug, Deserialize)]
pub struct UpdateNetworkConnectorRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

/// Network connector with stats.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct NetworkConnectorWithStats {
    pub id: Uuid,
    pub name: String,
    pub device_type: String,
    pub ip_address: String,
    pub syslog_port: i32,
    pub syslog_protocol: String,
    pub enabled: bool,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub alert_count: i64,
    pub config: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Syslog message record.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SyslogMessage {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub source_ip: String,
    pub raw_message: String,
    pub parsed_format: Option<String>,
    pub parsed_success: bool,
    pub alert_id: Option<Uuid>,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// Response for network connector stats.
#[derive(Debug, Serialize)]
pub struct NetworkConnectorStats {
    pub total_connectors: i64,
    pub active_connectors: i64,
    pub total_messages: i64,
    pub parsed_messages: i64,
    pub by_device_type: Vec<(String, i64)>,
}

/// GET /api/v1/network-connectors
///
/// List all network connectors.
pub async fn list_network_connectors_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<NetworkConnectorWithStats>>, (StatusCode, String)> {
    let connectors = sqlx::query_as!(
        NetworkConnectorWithStats,
        r#"
        SELECT id, name, device_type, ip_address, syslog_port, syslog_protocol,
               enabled, last_seen_at, alert_count, config, created_at, updated_at
        FROM network_connectors
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(connectors))
}

/// POST /api/v1/network-connectors
///
/// Create a new network connector.
pub async fn create_network_connector_handler(
    State(state): State<AppState>,
    Json(payload): Json<CreateNetworkConnectorRequest>,
) -> Result<Json<NetworkConnectorWithStats>, (StatusCode, String)> {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let syslog_port = payload.syslog_port.unwrap_or(514) as i32;
    let syslog_protocol = payload.syslog_protocol.unwrap_or_else(|| "udp".to_string());
    let config = payload.config.unwrap_or(serde_json::json!({}));

    let connector = sqlx::query_as!(
        NetworkConnectorWithStats,
        r#"
        INSERT INTO network_connectors (id, name, device_type, ip_address, syslog_port, syslog_protocol, enabled, config, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, $9)
        RETURNING id, name, device_type, ip_address, syslog_port, syslog_protocol, enabled, last_seen_at, alert_count, config, created_at, updated_at
        "#,
        id,
        payload.name,
        payload.device_type,
        payload.ip_address,
        syslog_port,
        syslog_protocol,
        config,
        now,
        now,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(connector))
}

/// GET /api/v1/network-connectors/:id
///
/// Get a specific network connector.
pub async fn get_network_connector_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<NetworkConnectorWithStats>, (StatusCode, String)> {
    let connector = sqlx::query_as!(
        NetworkConnectorWithStats,
        r#"
        SELECT id, name, device_type, ip_address, syslog_port, syslog_protocol,
               enabled, last_seen_at, alert_count, config, created_at, updated_at
        FROM network_connectors
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match connector {
        Some(c) => Ok(Json(c)),
        None => Err((
            StatusCode::NOT_FOUND,
            "Network connector not found".to_string(),
        )),
    }
}

/// PATCH /api/v1/network-connectors/:id
///
/// Update a network connector.
pub async fn update_network_connector_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateNetworkConnectorRequest>,
) -> Result<Json<NetworkConnectorWithStats>, (StatusCode, String)> {
    let now = chrono::Utc::now();

    let connector = sqlx::query_as!(
        NetworkConnectorWithStats,
        r#"
        UPDATE network_connectors
        SET
            name = COALESCE($2, name),
            enabled = COALESCE($3, enabled),
            config = COALESCE($4, config),
            updated_at = $5
        WHERE id = $1
        RETURNING id, name, device_type, ip_address, syslog_port, syslog_protocol, enabled, last_seen_at, alert_count, config, created_at, updated_at
        "#,
        id,
        payload.name,
        payload.enabled,
        payload.config,
        now,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match connector {
        Some(c) => Ok(Json(c)),
        None => Err((
            StatusCode::NOT_FOUND,
            "Network connector not found".to_string(),
        )),
    }
}

/// DELETE /api/v1/network-connectors/:id
///
/// Delete a network connector.
pub async fn delete_network_connector_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query!("DELETE FROM network_connectors WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((
            StatusCode::NOT_FOUND,
            "Network connector not found".to_string(),
        ))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

/// GET /api/v1/network-connectors/stats
///
/// Get network connector statistics.
pub async fn network_connector_stats_handler(
    State(state): State<AppState>,
) -> Result<Json<NetworkConnectorStats>, (StatusCode, String)> {
    let total_connectors: (Option<i64>,) =
        sqlx::query_as("SELECT COUNT(*) FROM network_connectors")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let active_connectors: (Option<i64>,) =
        sqlx::query_as("SELECT COUNT(*) FROM network_connectors WHERE enabled = true")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_messages: (Option<i64>,) = sqlx::query_as("SELECT COUNT(*) FROM syslog_messages")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let parsed_messages: (Option<i64>,) =
        sqlx::query_as("SELECT COUNT(*) FROM syslog_messages WHERE parsed_success = true")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let by_device_type = sqlx::query_as!(
        DeviceTypeCount,
        "SELECT device_type, COUNT(*) as count FROM network_connectors GROUP BY device_type"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(NetworkConnectorStats {
        total_connectors: total_connectors.0.unwrap_or(0),
        active_connectors: active_connectors.0.unwrap_or(0),
        total_messages: total_messages.0.unwrap_or(0),
        parsed_messages: parsed_messages.0.unwrap_or(0),
        by_device_type: by_device_type
            .into_iter()
            .map(|d| (d.device_type, d.count.unwrap_or(0)))
            .collect(),
    }))
}

#[derive(sqlx::FromRow)]
struct DeviceTypeCount {
    device_type: String,
    count: Option<i64>,
}

/// GET /api/v1/network-connectors/:id/messages
///
/// Get recent syslog messages for a network connector.
pub async fn list_syslog_messages_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<SyslogMessage>>, (StatusCode, String)> {
    let messages = sqlx::query_as!(
        SyslogMessage,
        r#"
        SELECT id, connector_id, source_ip, raw_message, parsed_format, parsed_success, alert_id, received_at
        FROM syslog_messages
        WHERE connector_id = $1
        ORDER BY received_at DESC
        LIMIT 100
        "#,
        id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(messages))
}
