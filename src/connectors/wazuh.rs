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
use crate::models::alert::{AlertStatus, NormalizedAlert, Severity};

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
}

impl WazuhConnector {
    /// Construct a new connector from the given credentials.
    ///
    /// No network call is made during construction — the connector is
    /// lazily connected on first use.
    pub fn new(base_url: String, username: String, password: String) -> Self {
        let insecure_tls = std::env::var("WAZUH_INSECURE_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        if insecure_tls {
            tracing::warn!("WAZUH_INSECURE_TLS is true. The Wazuh connector will accept invalid certificates.");
        }

        let client = Client::builder()
            .danger_accept_invalid_certs(insecure_tls)
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            base_url,
            username,
            password,
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

        assert_eq!(alert.connector_id, "wazuh");
        assert_eq!(alert.source, "web-server-1");
        assert_eq!(alert.severity, Severity::High); // level 12 → High
        assert_eq!(alert.status, AlertStatus::Open);
        assert_eq!(
            alert.timestamp.to_rfc3339(),
            "2026-07-29T09:00:00+00:00"
        );
    }

    #[test]
    fn map_hit_missing_timestamp_returns_none() {
        let mut hit = mock_hit();
        // Remove @timestamp — hit should be skipped.
        hit["_source"].as_object_mut().unwrap().remove("@timestamp");
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
        assert_eq!(alert.raw_payload["full_log"], "Jul 29 09:00:00 web-server-1 kernel: suspicious activity");
    }
}
