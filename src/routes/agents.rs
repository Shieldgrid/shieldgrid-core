use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::connectors::wazuh::WazuhConnector;
use crate::middleware::RequireRead;
use crate::routes::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UnifiedAgent {
    pub id: Uuid,
    pub hostname: String,
    pub wazuh_id: Option<String>,
    pub wazuh_status: Option<String>,
    pub wazuh_last_seen: Option<DateTime<Utc>>,
    pub wazuh_ip: Option<String>,
    pub wazuh_os: Option<String>,
    pub wazuh_version: Option<String>,
    pub velo_id: Option<String>,
    pub velo_status: Option<String>,
    pub velo_last_seen: Option<DateTime<Utc>>,
    pub velo_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn wazuh(state: &AppState) -> Option<&WazuhConnector> {
    state
        .connectors
        .iter()
        .find(|c| c.id() == "wazuh")
        .and_then(|c| c.as_any().downcast_ref::<WazuhConnector>())
}

/// `GET /api/v1/agents` — List all unified agents
pub async fn list_agents_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rows = sqlx::query_as!(
        UnifiedAgent,
        "SELECT * FROM unified_agents ORDER BY hostname ASC"
    )
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(agents) => Json(serde_json::json!({
            "agents": agents,
            "count": agents.len(),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to fetch unified agents: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// `POST /api/v1/agents/sync` — Fetch from Wazuh and Velociraptor and upsert unified_agents
pub async fn sync_agents_handler(
    _auth: RequireRead,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let connector = match wazuh(&state) {
        Some(c) => c,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Wazuh connector not registered",
            )
                .into_response()
        }
    };

    let (wazuh_agents, _) = match connector.list_agents(None).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let velo_connector = state.connectors.iter().find(|c| c.id() == "velociraptor");
    let velo_clients: Vec<serde_json::Value> = if let Some(velo) = velo_connector {
        if let Some(velo) = velo
            .as_any()
            .downcast_ref::<crate::connectors::velociraptor::VelociraptorConnector>()
        {
            match velo.list_clients().await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("velociraptor.list_clients failed: {}", e);
                    vec![]
                }
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let mut upserted_count = 0;

    // First pass: upsert all Wazuh agents
    for wa in &wazuh_agents {
        // Extract true hostname from os_uname (format: "OS |Hostname |Kernel...")
        let true_hostname = wa
            .os_uname
            .as_deref()
            .and_then(|u| {
                let parts: Vec<&str> = u.split('|').collect();
                if parts.len() >= 2 {
                    Some(parts[1].trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| wa.name.clone());

        // Parse last_seen (e.g. "2023-01-01T00:00:00Z") to DateTime<Utc>
        let w_last_seen = wa
            .last_seen
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let res = sqlx::query!(
            r#"
            INSERT INTO unified_agents (
                hostname, wazuh_id, wazuh_status, wazuh_last_seen, wazuh_ip, wazuh_os, wazuh_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (hostname) DO UPDATE SET
                wazuh_id = EXCLUDED.wazuh_id,
                wazuh_status = EXCLUDED.wazuh_status,
                wazuh_last_seen = EXCLUDED.wazuh_last_seen,
                wazuh_ip = EXCLUDED.wazuh_ip,
                wazuh_os = EXCLUDED.wazuh_os,
                wazuh_version = EXCLUDED.wazuh_version,
                updated_at = now()
            "#,
            true_hostname, // Use true OS hostname for matching
            wa.id,
            wa.status,
            w_last_seen,
            wa.ip,
            wa.os_name, // Map os_name or os_platform? os_name is better usually
            wa.version
        )
        .execute(&state.db)
        .await;

        match res {
            Ok(_) => upserted_count += 1,
            Err(e) => tracing::warn!("Failed to upsert wazuh agent {}: {}", wa.name, e),
        }
    }

    // Second pass: upsert/update all Velociraptor clients
    for vc in &velo_clients {
        let hostname = vc.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
        if hostname.is_empty() {
            continue;
        }
        let client_id = vc.get("client_id").and_then(|v| v.as_str()).unwrap_or("");
        let os = vc.get("os").and_then(|v| v.as_str()).unwrap_or("");
        let version = vc
            .get("client_version")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let last_seen_raw = vc.get("last_seen_at").and_then(|v| v.as_i64()).unwrap_or(0);
        let v_last_seen = if last_seen_raw > 0 {
            // Velociraptor timestamps are microseconds, convert to seconds, then nanoseconds
            let secs = last_seen_raw / 1_000_000;
            let nsecs = (last_seen_raw % 1_000_000) * 1000;
            DateTime::from_timestamp(secs, nsecs as u32)
        } else {
            None
        };

        let res = sqlx::query!(
            r#"
            INSERT INTO unified_agents (
                hostname, velo_id, velo_status, velo_last_seen, velo_version
            ) VALUES ($1, $2, 'active', $3, $4)
            ON CONFLICT (hostname) DO UPDATE SET
                velo_id = EXCLUDED.velo_id,
                velo_status = 'active',
                velo_last_seen = EXCLUDED.velo_last_seen,
                velo_version = EXCLUDED.velo_version,
                updated_at = now()
            "#,
            hostname,
            client_id,
            v_last_seen,
            version
        )
        .execute(&state.db)
        .await;

        if let Err(e) = res {
            tracing::warn!("Failed to upsert velociraptor agent {}: {}", hostname, e);
        }
    }

    Json(serde_json::json!({
        "success": true,
        "message": "Agents synced successfully",
        "wazuh_count": wazuh_agents.len(),
        "velo_count": velo_clients.len(),
    }))
    .into_response()
}
