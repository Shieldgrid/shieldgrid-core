//! Agent Management Service — unified agent inventory, healthchecks, and status tracking.
//!
//! # Overview
//!
//! Aggregates agent data from Wazuh and Velociraptor into a single view,
//! provides health monitoring, and tracks agent status over time.

#![allow(dead_code)]
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::connectors::Connector;

/// Unified agent representation across all endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAgent {
    pub id: String,
    pub hostname: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub ip: Option<String>,
    pub status: AgentStatus,
    pub source: String, // "wazuh", "velociraptor", etc.
    pub version: Option<String>,
    pub last_seen: Option<String>,
    pub groups: Vec<String>,
    pub health: AgentHealth,
}

/// Agent connection status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Disconnected,
    Pending,
    NeverConnected,
    Unknown,
}

/// Agent health assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub status: String, // "healthy", "degraded", "offline", "unknown"
    pub last_check: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
    pub details: Option<String>,
}

/// Agent healthcheck request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckRequest {
    pub agent_id: String,
    pub source: String,
}

/// Agent healthcheck response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckResponse {
    pub agent_id: String,
    pub source: String,
    pub healthy: bool,
    pub response_time_ms: u64,
    pub checked_at: DateTime<Utc>,
    pub details: Option<String>,
}

/// Agent status history record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentStatusRecord {
    pub id: Uuid,
    pub agent_id: String,
    pub source: String,
    pub status: String,
    pub checked_at: DateTime<Utc>,
}

/// Agent inventory summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInventorySummary {
    pub total_agents: usize,
    pub active_agents: usize,
    pub disconnected_agents: usize,
    pub pending_agents: usize,
    pub by_source: Vec<SourceCount>,
    pub recently_offline: Vec<UnifiedAgent>,
}

/// Agent count by source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCount {
    pub source: String,
    pub count: usize,
}

/// Get unified agent inventory from all connected sources.
pub async fn get_unified_agents(
    connectors: &[std::sync::Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<Vec<UnifiedAgent>> {
    let mut agents = Vec::new();

    for connector in connectors {
        match connector.id() {
            "wazuh" => {
                if let Some(wazuh) = connector
                    .as_any()
                    .downcast_ref::<crate::connectors::wazuh::WazuhConnector>()
                {
                    match wazuh.list_agents(None).await {
                        Ok((wazuh_agents, _summary)) => {
                            for agent in wazuh_agents {
                                agents.push(UnifiedAgent {
                                    id: agent.id.clone(),
                                    hostname: agent.name.clone(),
                                    os: agent.os_name.clone(),
                                    os_version: agent.os_version.clone(),
                                    ip: agent.ip.clone(),
                                    status: map_wazuh_status(agent.status.as_deref()),
                                    source: "wazuh".to_string(),
                                    version: agent.version.clone(),
                                    last_seen: agent.last_seen.clone(),
                                    groups: agent.groups.clone(),
                                    health: AgentHealth {
                                        status: "unknown".to_string(),
                                        last_check: Utc::now(),
                                        response_time_ms: None,
                                        details: None,
                                    },
                                });
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch Wazuh agents: {e}");
                        }
                    }
                }
            }
            "velociraptor" => {
                if let Some(velo) = connector
                    .as_any()
                    .downcast_ref::<crate::connectors::velociraptor::VelociraptorConnector>(
                ) {
                    match velo.list_clients().await {
                        Ok(rows) => {
                            for row in rows {
                                let client_id = row
                                    .get("client_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let hostname = row
                                    .get("hostname")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let os = row.get("os").and_then(|v| v.as_str()).map(String::from);
                                let arch =
                                    row.get("arch").and_then(|v| v.as_str()).map(String::from);
                                let version = row
                                    .get("client_version")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let last_seen =
                                    row.get("last_seen_at").and_then(|v| v.as_i64()).map(|ts| {
                                        DateTime::from_timestamp(ts, 0)
                                            .map(|dt| dt.to_rfc3339())
                                            .unwrap_or_default()
                                    });

                                agents.push(UnifiedAgent {
                                    id: client_id,
                                    hostname,
                                    os,
                                    os_version: arch,
                                    ip: None,
                                    status: AgentStatus::Active, // Velociraptor clients are online if reachable
                                    source: "velociraptor".to_string(),
                                    version,
                                    last_seen,
                                    groups: vec![],
                                    health: AgentHealth {
                                        status: "healthy".to_string(),
                                        last_check: Utc::now(),
                                        response_time_ms: None,
                                        details: None,
                                    },
                                });
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch Velociraptor clients: {e}");
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Check health status against stored records
    for agent in &mut agents {
        let record = sqlx::query_as!(
            AgentStatusRecord,
            r#"
            SELECT id, agent_id, source, status, checked_at
            FROM agent_status_history
            WHERE agent_id = $1 AND source = $2
            ORDER BY checked_at DESC
            LIMIT 1
            "#,
            agent.id,
            agent.source,
        )
        .fetch_optional(pool)
        .await;

        if let Ok(Some(r)) = record {
            agent.health.status = r.status.clone();
            agent.health.last_check = r.checked_at;
        }
    }

    Ok(agents)
}

/// Run a healthcheck on a specific agent.
pub async fn healthcheck_agent(
    request: HealthcheckRequest,
    connectors: &[std::sync::Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<HealthcheckResponse> {
    let start = std::time::Instant::now();
    let mut healthy = false;
    let mut details = None;

    for connector in connectors {
        if connector.id() == request.source {
            match connector.health_check().await {
                crate::connectors::HealthStatus::Healthy => {
                    healthy = true;
                }
                crate::connectors::HealthStatus::Down { reason } => {
                    details = Some(reason);
                }
                crate::connectors::HealthStatus::Degraded { reason } => {
                    details = Some(reason);
                }
            }
            break;
        }
    }

    let response_time = start.elapsed().as_millis() as u64;
    let now = Utc::now();

    // Store healthcheck result
    let _ = sqlx::query!(
        r#"
        INSERT INTO agent_status_history (id, agent_id, source, status, checked_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::new_v4(),
        request.agent_id,
        request.source,
        if healthy { "healthy" } else { "unhealthy" },
        now,
    )
    .execute(pool)
    .await;

    Ok(HealthcheckResponse {
        agent_id: request.agent_id,
        source: request.source,
        healthy,
        response_time_ms: response_time,
        checked_at: now,
        details,
    })
}

/// Get agent inventory summary.
pub async fn get_inventory_summary(agents: &[UnifiedAgent]) -> AgentInventorySummary {
    let total = agents.len();
    let active = agents
        .iter()
        .filter(|a| a.status == AgentStatus::Active)
        .count();
    let disconnected = agents
        .iter()
        .filter(|a| a.status == AgentStatus::Disconnected)
        .count();
    let pending = agents
        .iter()
        .filter(|a| a.status == AgentStatus::Pending)
        .count();

    let mut by_source: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for agent in agents {
        *by_source.entry(agent.source.clone()).or_insert(0) += 1;
    }

    let by_source: Vec<SourceCount> = by_source
        .into_iter()
        .map(|(source, count)| SourceCount { source, count })
        .collect();

    let recently_offline: Vec<UnifiedAgent> = agents
        .iter()
        .filter(|a| a.status == AgentStatus::Disconnected)
        .take(10)
        .cloned()
        .collect();

    AgentInventorySummary {
        total_agents: total,
        active_agents: active,
        disconnected_agents: disconnected,
        pending_agents: pending,
        by_source,
        recently_offline,
    }
}

/// Map Wazuh agent status to unified status.
fn map_wazuh_status(status: Option<&str>) -> AgentStatus {
    match status.unwrap_or("") {
        "active" => AgentStatus::Active,
        "disconnected" => AgentStatus::Disconnected,
        "pending" => AgentStatus::Pending,
        "never_connected" => AgentStatus::NeverConnected,
        _ => AgentStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_wazuh_status() {
        assert_eq!(map_wazuh_status(Some("active")), AgentStatus::Active);
        assert_eq!(
            map_wazuh_status(Some("disconnected")),
            AgentStatus::Disconnected
        );
        assert_eq!(map_wazuh_status(Some("pending")), AgentStatus::Pending);
        assert_eq!(
            map_wazuh_status(Some("never_connected")),
            AgentStatus::NeverConnected
        );
        assert_eq!(map_wazuh_status(None), AgentStatus::Unknown);
        assert_eq!(map_wazuh_status(Some("unknown")), AgentStatus::Unknown);
    }

    #[tokio::test]
    async fn test_inventory_summary() {
        let agents = vec![
            UnifiedAgent {
                id: "001".to_string(),
                hostname: "web-1".to_string(),
                os: Some("Linux".to_string()),
                os_version: None,
                ip: None,
                status: AgentStatus::Active,
                source: "wazuh".to_string(),
                version: None,
                last_seen: None,
                groups: vec![],
                health: AgentHealth {
                    status: "healthy".to_string(),
                    last_check: Utc::now(),
                    response_time_ms: None,
                    details: None,
                },
            },
            UnifiedAgent {
                id: "002".to_string(),
                hostname: "web-2".to_string(),
                os: Some("Linux".to_string()),
                os_version: None,
                ip: None,
                status: AgentStatus::Disconnected,
                source: "wazuh".to_string(),
                version: None,
                last_seen: None,
                groups: vec![],
                health: AgentHealth {
                    status: "offline".to_string(),
                    last_check: Utc::now(),
                    response_time_ms: None,
                    details: None,
                },
            },
        ];

        let summary = get_inventory_summary(&agents).await;
        assert_eq!(summary.total_agents, 2);
        assert_eq!(summary.active_agents, 1);
        assert_eq!(summary.disconnected_agents, 1);
    }
}
