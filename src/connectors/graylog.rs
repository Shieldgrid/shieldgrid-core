#![allow(dead_code)]
//! Graylog connector — queries the Graylog GELF API for alert correlation.
//!
//! # Data flow
//!
//! ```text
//! GraylogConnector::fetch_alerts(since)
//!   └─ POST {graylog_url}/api/search/universal/relative
//!      └─ parse GELF messages
//!         └─ map_message() → NormalizedAlert
//! ```
//!
//! # Authentication
//!
//! Uses API key authentication via the `X-Graylog-Token` header.
//! The API key should be set in the `GRAYLOG_API_KEY` environment variable.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::connectors::{Connector, HealthStatus};
use crate::models::action::{ActionResult, ActionStatus, ResponseAction};
use crate::models::alert::{AlertStatus, NormalizedAlert, Severity};

/// Configuration for the Graylog connector.
#[derive(Debug, Clone)]
pub struct GraylogConfig {
    /// Graylog API base URL (e.g. `http://localhost:9000`)
    pub api_url: String,
    /// API key for authentication
    pub api_key: String,
}

/// A Graylog search result.
#[derive(Debug, Deserialize)]
struct SearchResponse {
    total_results: Option<u64>,
    messages: Option<Vec<GelfMessage>>,
}

/// A single GELF message from Graylog.
#[derive(Debug, Deserialize)]
struct GelfMessage {
    message: Option<Value>,
}

/// Graylog connector implementation.
pub struct GraylogConnector {
    client: Client,
    config: GraylogConfig,
}

impl GraylogConnector {
    /// Create a new Graylog connector from configuration.
    pub fn new(config: GraylogConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {e}"))?;

        Ok(Self { client, config })
    }

    /// Search Graylog for messages matching a query.
    pub async fn search(
        &self,
        query: &str,
        timerange: u64, // seconds
        limit: u64,
    ) -> Result<Vec<Value>> {
        let url = format!("{}/api/search/universal/relative", self.config.api_url);

        let _params = serde_json::json!({
            "query": query,
            "range": timerange,
            "limit": limit,
        });

        let resp = self
            .client
            .get(&url)
            .header("X-Graylog-Token", &self.config.api_key)
            .query(&[
                ("query", query),
                ("range", &timerange.to_string()),
                ("limit", &limit.to_string()),
            ])
            .send()
            .await
            .map_err(|e| anyhow!("Graylog API request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("Graylog API error {}: {}", status, body));
        }

        let json: Value = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse Graylog response: {e}"))?;

        let messages = json
            .get("messages")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(messages)
    }

    /// Get Graylog stream information.
    pub async fn list_streams(&self) -> Result<Vec<Value>> {
        let url = format!("{}/api/streams", self.config.api_url);

        let resp = self
            .client
            .get(&url)
            .header("X-Graylog-Token", &self.config.api_key)
            .send()
            .await
            .map_err(|e| anyhow!("Graylog API request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("Graylog API error {}: {}", status, body));
        }

        let json: Value = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse Graylog response: {e}"))?;

        json.get("streams")
            .and_then(|s| s.as_array())
            .cloned()
            .ok_or_else(|| anyhow!("Invalid Graylog streams response"))
    }

    /// Get Graylog system health.
    pub async fn get_system_health(&self) -> Result<Value> {
        let url = format!("{}/api/system", self.config.api_url);

        let resp = self
            .client
            .get(&url)
            .header("X-Graylog-Token", &self.config.api_key)
            .send()
            .await
            .map_err(|e| anyhow!("Graylog API request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("Graylog API error {}: {}", status, body));
        }

        serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse Graylog response: {e}"))
    }
}

#[async_trait]
impl Connector for GraylogConnector {
    fn id(&self) -> &'static str {
        "graylog"
    }

    async fn health_check(&self) -> HealthStatus {
        match self.get_system_health().await {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Down {
                reason: format!("Graylog API unreachable: {e}"),
            },
        }
    }

    async fn fetch_alerts(&self, since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>> {
        let seconds_ago = Utc::now().signed_duration_since(since).num_seconds() as u64;
        let messages = self.search("*", seconds_ago, 500).await?;

        let mut alerts = Vec::new();
        for msg in messages {
            if let Some(gelf) = msg.get("message") {
                if let Some(alert) = map_gelf_message(gelf) {
                    alerts.push(alert);
                }
            }
        }

        Ok(alerts)
    }

    async fn push_action(&self, _action: ResponseAction) -> Result<ActionResult> {
        Ok(ActionResult {
            status: ActionStatus::Failure,
            detail: "Graylog connector does not support push actions".to_string(),
            timestamp: Utc::now(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Map a GELF message to a NormalizedAlert.
fn map_gelf_message(message: &Value) -> Option<NormalizedAlert> {
    let timestamp_str = message.get("timestamp").and_then(|t| t.as_f64())?;
    let timestamp = DateTime::from_timestamp(timestamp_str as i64, 0)?;

    let severity_str = message.get("level").and_then(|l| l.as_u64()).unwrap_or(5);

    let severity = match severity_str {
        0..=2 => Severity::Low,
        3..=4 => Severity::Medium,
        5..=6 => Severity::High,
        _ => Severity::Critical,
    };

    let source = message
        .get("source")
        .and_then(|s| s.as_str())
        .unwrap_or("graylog")
        .to_string();

    Some(NormalizedAlert {
        id: Uuid::new_v4(),
        source_id: Uuid::new_v4().to_string(),
        connector_id: "graylog".to_string(),
        severity,
        source,
        timestamp,
        raw_payload: message.clone(),
        status: AlertStatus::Open,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_map_gelf_message() {
        let msg = json!({
            "timestamp": 1692633600.0,
            "level": 4,
            "source": "web-server-1",
            "message": "Suspicious activity detected"
        });

        let alert = map_gelf_message(&msg).unwrap();
        assert_eq!(alert.connector_id, "graylog");
        assert_eq!(alert.source, "web-server-1");
        assert_eq!(alert.severity, Severity::Medium);
    }

    #[test]
    fn test_map_gelf_message_missing_timestamp() {
        let msg = json!({
            "level": 4,
            "source": "web-server-1"
        });

        assert!(map_gelf_message(&msg).is_none());
    }
}
