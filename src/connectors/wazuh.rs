//! Wazuh connector — queries the OpenSearch index that backs a Wazuh
//! installation and maps native alert documents into [`NormalizedAlert`].
//!
//! # Data flow
//!
//! ```text
//! WazuhConnector::fetch_alerts(since)
//!   └─ POST {opensearch_url}/wazuh-alerts-*/_search  (range query on @timestamp)
//!      └─ parse hits
//!         └─ map_hit()  →  NormalizedAlert
//! ```
//!
//! # Field mapping
//!
//! | NormalizedAlert field | OpenSearch source |
//! |---|---|
//! | `id` | UUID generated at ingestion time |
//! | `source_id` | `_id` of the hit document (stable dedupe key) |
//! | `connector_id` | `"wazuh"` (static) |
//! | `severity` | `_source.rule.level` → [`map_severity`] |
//! | `source` | `_source.agent.name` (falls back to `_source.agent.id`) |
//! | `timestamp` | `_source.@timestamp` |
//! | `raw_payload` | entire `_source` value |
//! | `status` | `AlertStatus::Open` (initial state) |

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::connectors::{Connector, HealthStatus};
use crate::models::action::{ActionResult, ActionStatus, ResponseAction};
use crate::models::alert::{AlertStatus, NormalizedAlert, Severity};
use crate::models::wazuh::{WazuhAgent, WazuhAgentsSummary};

// ── WazuhConnector ────────────────────────────────────────────────────────────

/// Connector implementation for Wazuh via its underlying OpenSearch index.
pub struct WazuhConnector {
    /// Shared HTTP client — `reqwest::Client` is internally `Arc`-backed and
    /// cheap to clone.
    client: Client,
    /// OpenSearch base URL, no trailing slash (e.g. `http://localhost:9200`).
    base_url: String,
    /// Basic-auth username for OpenSearch.
    username: String,
    /// Basic-auth password for OpenSearch.
    password: String,
    /// Wazuh manager REST API base URL (e.g. `https://wazuh.example.com:55000`).
    manager_url: String,
    /// Basic-auth username for the manager API token exchange.
    manager_username: String,
    /// Basic-auth password for the manager API token exchange.
    manager_password: String,
}

impl WazuhConnector {
    /// Construct a new connector from the given credentials.
    ///
    /// No network call is made during construction — the connector is
    /// lazily connected on first use.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: String,
        username: String,
        password: String,
        manager_url: String,
        manager_username: String,
        manager_password: String,
    ) -> Self {
        let insecure_tls = std::env::var("WAZUH_INSECURE_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        if insecure_tls {
            tracing::warn!(
                "WAZUH_INSECURE_TLS is true. The Wazuh connector will accept invalid certificates."
            );
        }

        let client = Client::builder()
            .danger_accept_invalid_certs(insecure_tls)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            base_url,
            username,
            password,
            manager_url,
            manager_username,
            manager_password,
        }
    }

    /// Exchange the manager basic-auth credentials for a short-lived JWT.
    ///
    /// Wazuh's REST API (4.x) requires a bearer token obtained from
    /// `POST /security/user/authenticate`; a fresh token is requested on each
    /// call so no token cache can go stale.
    async fn manager_token(&self) -> Result<String> {
        let url = format!("{}/security/user/authenticate", self.manager_url);
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.manager_username, Some(&self.manager_password))
            .send()
            .await
            .map_err(|e| anyhow!("Wazuh manager auth request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Wazuh manager authentication returned {status}: {body}"
            ));
        }

        let body: Value = resp
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse Wazuh auth response: {e}"))?;

        body.pointer("/data/token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("Wazuh auth response missing data.token"))
    }

    /// List registered agents plus aggregate connection-status counts.
    ///
    /// Wraps `GET /agents` and `GET /agents/summary` on the manager REST API.
    /// `status` optionally filters the list (`active`, `disconnected`,
    /// `never_connected`, `pending`) — the summary is always global.
    pub async fn list_agents(
        &self,
        status: Option<&str>,
    ) -> Result<(Vec<WazuhAgent>, WazuhAgentsSummary)> {
        let token = self.manager_token().await?;

        let mut url = format!("{}/agents", self.manager_url);
        let mut params: Vec<String> = vec![
            "select=id,name,ip,status,os.name,os.version,os.platform,os.uname,version,lastKeepAlive,group"
                .into(),
        ];
        if let Some(s) = status {
            params.push(format!("q=status={s}"));
        }
        url.push('?');
        url.push_str(&params.join("&"));

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow!("Wazuh manager agents request failed: {e}"))?;

        if !resp.status().is_success() {
            let status_code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Wazuh manager returned {status_code}: {body}"));
        }

        let agents = parse_agents_response(&resp.text().await.unwrap_or_default())?;

        let summary_url = format!("{}/agents/summary", self.manager_url);
        let summary_resp = self
            .client
            .get(&summary_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow!("Wazuh manager summary request failed: {e}"))?;

        if !summary_resp.status().is_success() {
            let status_code = summary_resp.status();
            let body = summary_resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Wazuh manager summary returned {status_code}: {body}"
            ));
        }

        let summary = parse_summary_response(&summary_resp.text().await.unwrap_or_default())?;

        Ok((agents, summary))
    }
}

impl WazuhConnector {
    /// Send an active response command to a Wazuh agent.
    ///
    /// Uses the Wazuh manager REST API to dispatch AR commands.
    /// The command is sent to the agent via the manager, which then
    /// executes the corresponding active response script on the endpoint.
    async fn send_active_response(
        &self,
        agent_id: &str,
        command: &str,
        _action: &ResponseAction,
    ) -> Result<ActionResult> {
        let token = self.manager_token().await?;

        // Build the AR request payload
        // Wazuh AR API expects: {"command": "command_name", "agents": ["agent_id"]}
        let payload = serde_json::json!({
            "command": command,
            "agents": [agent_id],
            "arguments": {}
        });

        let url = format!("{}/active-response", self.manager_url);

        tracing::info!(
            "Sending Wazuh active response '{}' to agent '{}'",
            command,
            agent_id
        );

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow!("Wazuh active response request failed: {e}"))?;

        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status_code.is_success() {
            tracing::info!(
                "Wazuh active response '{}' dispatched to agent '{}' successfully",
                command,
                agent_id
            );
            Ok(ActionResult {
                status: ActionStatus::Success,
                detail: format!(
                    "Active response '{}' dispatched to agent '{}'",
                    command, agent_id
                ),
                timestamp: Utc::now(),
            })
        } else {
            tracing::warn!("Wazuh active response failed: {} - {}", status_code, body);
            Ok(ActionResult {
                status: ActionStatus::Failure,
                detail: format!("Wazuh AR failed ({}): {}", status_code, body),
                timestamp: Utc::now(),
            })
        }
    }
}

#[async_trait]
impl Connector for WazuhConnector {
    fn id(&self) -> &str {
        "wazuh"
    }

    /// Ping the OpenSearch cluster-health endpoint.
    ///
    /// Returns [`HealthStatus::Healthy`] on green/yellow, [`HealthStatus::Down`]
    /// if the request fails or the cluster reports red.
    async fn health_check(&self) -> HealthStatus {
        let url = format!("{}/_cluster/health", self.base_url);
        match self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
        {
            Err(e) => HealthStatus::Down {
                reason: format!("request failed: {e}"),
            },
            Ok(resp) => {
                let body: Value = match resp.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        return HealthStatus::Down {
                            reason: format!("invalid JSON from /_cluster/health: {e}"),
                        }
                    }
                };
                match body.get("status").and_then(Value::as_str) {
                    Some("green") | Some("yellow") => HealthStatus::Healthy,
                    Some(s) => HealthStatus::Down {
                        reason: format!("cluster status is {s}"),
                    },
                    None => HealthStatus::Down {
                        reason: "missing 'status' field in cluster health response".into(),
                    },
                }
            }
        }
    }

    /// Fetch all Wazuh alerts with `@timestamp >= since`.
    ///
    /// Queries the `wazuh-alerts-*` index pattern, sorted newest-first,
    /// capped at 500 results (known Phase 0 limitation — pagination deferred
    /// to Phase 1).
    async fn fetch_alerts(&self, since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>> {
        let url = format!("{}/wazuh-alerts-*/_search", self.base_url);
        let query = json!({
            "size": 500,
            "sort": [{ "@timestamp": "desc" }],
            "query": {
                "range": {
                    "@timestamp": { "gte": since.to_rfc3339() }
                }
            }
        });

        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&query)
            .send()
            .await
            .map_err(|e| anyhow!("OpenSearch request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("OpenSearch returned {status}: {body}"));
        }

        let body: Value = resp
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse OpenSearch response: {e}"))?;

        let hits = body
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("unexpected OpenSearch response shape: missing /hits/hits"))?;

        let alerts = hits.iter().filter_map(map_hit).collect();
        Ok(alerts)
    }

    /// Push an active response command to a Wazuh agent via the manager API.
    ///
    /// Supported action types:
    /// - `firewall-drop`: Block an IP address on the target agent's firewall
    /// - `netsh-command`: Run a netsh command on Windows agents
    /// - `custom-script`: Execute a custom active response script
    ///
    /// The target_id should be the Wazuh agent ID (e.g. "004").
    async fn push_action(&self, action: ResponseAction) -> Result<ActionResult> {
        let command = action.action_type.as_str();

        match command {
            "firewall-drop" | "netsh-command" | "custom-script" => {
                self.send_active_response(&action.target_id, command, &action).await
            }
            _ => {
                Ok(ActionResult {
                    status: ActionStatus::Failure,
                    detail: format!("Unsupported Wazuh action type: {}. Supported: firewall-drop, netsh-command, custom-script", command),
                    timestamp: Utc::now(),
                })
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

/// Map a single OpenSearch hit (`{ "_id": "...", "_source": {...} }`) into a
/// [`NormalizedAlert`].
///
/// Returns `None` if the hit is missing fields required to produce a valid
/// alert (e.g. no `@timestamp`).  Such hits are silently skipped so one bad
/// document does not break the whole batch.
///
/// This function is `pub(crate)` so the unit tests below can call it directly
/// without spinning up an HTTP server.
pub(crate) fn map_hit(hit: &Value) -> Option<NormalizedAlert> {
    let source_id = hit.get("_id").and_then(Value::as_str)?;
    let source = hit.get("_source")?;

    let timestamp_str = source.pointer("/@timestamp").and_then(Value::as_str)?;
    let timestamp = timestamp_str.parse::<DateTime<Utc>>().ok()?;

    let rule_level = source
        .pointer("/rule/level")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let source_name = source
        .pointer("/agent/name")
        .or_else(|| source.pointer("/agent/id"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    Some(NormalizedAlert {
        id: Uuid::new_v4(),
        source_id: source_id.to_string(),
        connector_id: "wazuh".into(),
        severity: map_severity(rule_level),
        source: source_name,
        timestamp,
        raw_payload: source.clone(),
        status: AlertStatus::Open,
    })
}

/// Map a Wazuh rule level (1–15) to a normalised [`Severity`] bucket.
///
/// | Wazuh level | Severity |
/// |---|---|
/// | 0–3   | Info     |
/// | 4–6   | Low      |
/// | 7–10  | Medium   |
/// | 11–13 | High     |
/// | 14–15 | Critical |
pub(crate) fn map_severity(level: u64) -> Severity {
    match level {
        0..=3 => Severity::Info,
        4..=6 => Severity::Low,
        7..=10 => Severity::Medium,
        11..=13 => Severity::High,
        _ => Severity::Critical,
    }
}

// ── Wazuh manager API parsing ────────────────────────────────────────────────

/// Parse the `GET /agents` response body into [`WazuhAgent`] rows.
///
/// Tolerates agents missing optional fields (`group`, `os`, …) — each agent
/// is mapped independently so one malformed row does not fail the batch.
pub(crate) fn parse_agents_response(body: &str) -> Result<Vec<WazuhAgent>> {
    let raw: Value = serde_json::from_str(body)
        .map_err(|e| anyhow!("failed to parse Wazuh agents response: {e}"))?;

    let items = raw
        .pointer("/data/affected_items")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("unexpected Wazuh agents response shape: missing data.affected_items")
        })?;

    Ok(items
        .iter()
        .map(|agent| WazuhAgent {
            id: agent
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            name: agent
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            ip: agent.get("ip").and_then(Value::as_str).map(str::to_string),
            status: agent
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string),
            os_name: agent
                .pointer("/os/name")
                .and_then(Value::as_str)
                .map(str::to_string),
            os_version: agent
                .pointer("/os/version")
                .and_then(Value::as_str)
                .map(str::to_string),
            os_platform: agent
                .pointer("/os/platform")
                .and_then(Value::as_str)
                .map(str::to_string),
            os_uname: agent
                .pointer("/os/uname")
                .and_then(Value::as_str)
                .map(str::to_string),
            version: agent
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string),
            last_seen: agent
                .get("lastKeepAlive")
                .and_then(Value::as_str)
                .map(str::to_string),
            groups: agent
                .get("group")
                .and_then(Value::as_array)
                .map(|g| {
                    g.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// Parse the `GET /agents/summary` response body into [`WazuhAgentsSummary`].
pub(crate) fn parse_summary_response(body: &str) -> Result<WazuhAgentsSummary> {
    let raw: Value = serde_json::from_str(body)
        .map_err(|e| anyhow!("failed to parse Wazuh summary response: {e}"))?;

    let counts = raw
        .pointer("/data/status")
        .ok_or_else(|| anyhow!("unexpected Wazuh summary response shape: missing data.status"))?;

    Ok(WazuhAgentsSummary {
        active: counts.get("active").and_then(Value::as_u64).unwrap_or(0),
        disconnected: counts
            .get("disconnected")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        never_connected: counts
            .get("never_connected")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        pending: counts.get("pending").and_then(Value::as_u64).unwrap_or(0),
        total: [
            counts.get("active").and_then(Value::as_u64).unwrap_or(0),
            counts
                .get("disconnected")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            counts
                .get("never_connected")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            counts.get("pending").and_then(Value::as_u64).unwrap_or(0),
        ]
        .iter()
        .sum(),
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A representative mocked OpenSearch hit, shaped like a real Wazuh alert.
    fn mock_hit() -> Value {
        json!({
            "_index": "wazuh-alerts-4.x-2026.07.29",
            "_id": "abc123",
            "_source": {
                "@timestamp": "2026-07-29T09:00:00.000Z",
                "rule": {
                    "level": 12,
                    "description": "Suspicious process created",
                    "id": "550"
                },
                "agent": {
                    "id": "001",
                    "name": "web-server-1"
                },
                "full_log": "Jul 29 09:00:00 web-server-1 kernel: suspicious activity"
            }
        })
    }

    #[test]
    fn map_hit_returns_normalized_alert() {
        let hit = mock_hit();
        let alert = map_hit(&hit).expect("should produce an alert from a valid hit");

        assert_eq!(alert.source_id, "abc123");
        assert_eq!(alert.connector_id, "wazuh");
        assert_eq!(alert.source, "web-server-1");
        assert_eq!(alert.severity, Severity::High); // level 12 → High
        assert_eq!(alert.status, AlertStatus::Open);
        assert_eq!(alert.timestamp.to_rfc3339(), "2026-07-29T09:00:00+00:00");
    }

    #[test]
    fn map_hit_missing_timestamp_returns_none() {
        let mut hit = mock_hit();
        // Remove @timestamp — hit should be skipped.
        hit["_source"].as_object_mut().unwrap().remove("@timestamp");
        assert!(map_hit(&hit).is_none());
    }

    #[test]
    fn map_hit_missing_id_returns_none() {
        let mut hit = mock_hit();
        // Remove _id — without a stable source key the hit cannot be deduped,
        // so it is skipped rather than producing an un-keyed alert.
        hit.as_object_mut().unwrap().remove("_id");
        assert!(map_hit(&hit).is_none());
    }

    #[test]
    fn map_hit_falls_back_to_agent_id_when_name_absent() {
        let mut hit = mock_hit();
        hit["_source"]["agent"]
            .as_object_mut()
            .unwrap()
            .remove("name");
        let alert = map_hit(&hit).expect("should still produce an alert");
        assert_eq!(alert.source, "001"); // falls back to agent.id
    }

    #[test]
    fn severity_mapping_covers_all_buckets() {
        assert_eq!(map_severity(0), Severity::Info);
        assert_eq!(map_severity(3), Severity::Info);
        assert_eq!(map_severity(4), Severity::Low);
        assert_eq!(map_severity(6), Severity::Low);
        assert_eq!(map_severity(7), Severity::Medium);
        assert_eq!(map_severity(10), Severity::Medium);
        assert_eq!(map_severity(11), Severity::High);
        assert_eq!(map_severity(13), Severity::High);
        assert_eq!(map_severity(14), Severity::Critical);
        assert_eq!(map_severity(15), Severity::Critical);
    }

    #[test]
    fn raw_payload_is_preserved() {
        let hit = mock_hit();
        let alert = map_hit(&hit).unwrap();
        // The full _source must be present for audit purposes.
        assert_eq!(alert.raw_payload["rule"]["level"], 12);
        assert_eq!(
            alert.raw_payload["full_log"],
            "Jul 29 09:00:00 web-server-1 kernel: suspicious activity"
        );
    }

    /// A representative `GET /agents` response, shaped like the live 4.x API.
    fn mock_agents_body() -> String {
        serde_json::to_string(&json!({
            "data": {
                "affected_items": [
                    {
                        "os": { "name": "Amazon Linux", "platform": "amzn", "version": "2023", "uname": "Linux |manager-master-0 |6.8.0-136-generic" },
                        "ip": "127.0.0.1",
                        "id": "000",
                        "status": "active",
                        "lastKeepAlive": "9999-12-31T23:59:59+00:00",
                        "name": "manager-master-0",
                        "version": "Wazuh v4.14.4"
                    },
                    {
                        "os": { "name": "Ubuntu", "platform": "ubuntu", "version": "24.04.4 LTS", "uname": "Linux |web-server-01 |6.8.0-136-generic" },
                        "ip": "10.0.0.4",
                        "id": "004",
                        "status": "active",
                        "lastKeepAlive": "2026-07-31T15:18:08+00:00",
                        "name": "web-server-01-agent",
                        "version": "Wazuh v4.14.5",
                        "group": ["docker"]
                    }
                ],
                "total_affected_items": 2
            },
            "error": 0
        }))
        .unwrap()
    }

    #[test]
    fn parse_agents_response_maps_rows_and_optional_fields() {
        let agents = parse_agents_response(&mock_agents_body()).unwrap();
        assert_eq!(agents.len(), 2);

        let manager = &agents[0];
        assert_eq!(manager.id, "000");
        assert_eq!(manager.name, "manager-master-0");
        assert_eq!(manager.status.as_deref(), Some("active"));
        assert_eq!(manager.os_name.as_deref(), Some("Amazon Linux"));
        assert_eq!(manager.os_version.as_deref(), Some("2023"));
        assert_eq!(manager.os_uname.as_deref(), Some("Linux |manager-master-0 |6.8.0-136-generic"));
        // Group is absent on the manager row → empty vec, not an error.
        assert!(manager.groups.is_empty());

        let agent = &agents[1];
        assert_eq!(agent.id, "004");
        assert_eq!(agent.name, "web-server-01-agent");
        assert_eq!(agent.ip.as_deref(), Some("10.0.0.4"));
        assert_eq!(agent.os_platform.as_deref(), Some("ubuntu"));
        assert_eq!(agent.os_uname.as_deref(), Some("Linux |web-server-01 |6.8.0-136-generic"));
        assert_eq!(agent.version.as_deref(), Some("Wazuh v4.14.5"));
        assert_eq!(agent.groups, vec!["docker".to_string()]);
        assert_eq!(
            agent.last_seen.as_deref(),
            Some("2026-07-31T15:18:08+00:00")
        );
    }

    #[test]
    fn parse_agents_response_missing_data_is_error() {
        assert!(parse_agents_response(r#"{"message":"no"}"#).is_err());
        assert!(parse_agents_response("not json").is_err());
    }

    #[test]
    fn parse_summary_response_sums_status_buckets() {
        let body = serde_json::to_string(&json!({
            "data": {
                "status": { "active": 1, "disconnected": 2, "never_connected": 0, "pending": 3 }
            },
            "error": 0
        }))
        .unwrap();
        let summary = parse_summary_response(&body).unwrap();
        assert_eq!(summary.active, 1);
        assert_eq!(summary.disconnected, 2);
        assert_eq!(summary.never_connected, 0);
        assert_eq!(summary.pending, 3);
        assert_eq!(summary.total, 6);
    }
}
