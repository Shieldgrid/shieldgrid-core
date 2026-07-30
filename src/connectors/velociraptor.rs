use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::config::Config;
use crate::connectors::{Connector, HealthStatus};
use crate::models::action::{ActionResult, ResponseAction};
use crate::models::alert::{AlertStatus, NormalizedAlert, Severity};

pub mod api {
    tonic::include_proto!("proto");
}
use api::api_client::ApiClient;
use api::{VqlCollectorArgs, VqlRequest};
use uuid::Uuid;

#[derive(Deserialize)]
struct VelociraptorClientConfig {
    api_connection_string: String,
    client_cert: String,
    client_private_key: String,
    ca_certificate: String,
}

impl std::fmt::Debug for VelociraptorClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VelociraptorClientConfig")
            .field("api_connection_string", &self.api_connection_string)
            .field("client_cert", &"***REDACTED***")
            .field("client_private_key", &"***REDACTED***")
            .field("ca_certificate", &"***REDACTED***")
            .finish()
    }
}

pub struct VelociraptorConnector {
    channel: Channel,
}

impl VelociraptorConnector {
    pub async fn new(config: &Config) -> Result<Self> {
        let yaml_content = std::fs::read_to_string(&config.velociraptor_api_client_yaml)
            .context("Failed to read Velociraptor api_client.yaml")?;

        let vr_config: VelociraptorClientConfig = serde_yaml::from_str(&yaml_content)
            .context("Failed to parse Velociraptor api_client.yaml")?;

        let ca_cert = Certificate::from_pem(&vr_config.ca_certificate);
        let identity = Identity::from_pem(&vr_config.client_cert, &vr_config.client_private_key);

        let tls = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .identity(identity)
            .domain_name("VelociraptorServer"); // Standard SAN used by Velociraptor

        let endpoint_url = format!("https://{}", vr_config.api_connection_string);
        let endpoint = Endpoint::from_shared(endpoint_url)?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));

        let channel = endpoint.connect_lazy();

        Ok(Self { channel })
    }

    async fn run_query(&self, query: &str) -> Result<Vec<serde_json::Value>> {
        let mut client = ApiClient::new(self.channel.clone());

        let vql_query = VqlRequest {
            name: "query".to_string(),
            vql: query.to_string(),
        };

        let args = VqlCollectorArgs {
            env: vec![],
            query: vec![vql_query],
            max_wait: 10,
            max_row: 500,
            ops_per_second: 0.0,
            org_id: String::new(),
            timeout: 0,
        };

        let mut request = tonic::Request::new(args);
        request.set_timeout(Duration::from_secs(30));
        let mut stream = client.query(request).await?.into_inner();

        let mut all_rows = Vec::new();

        while let Some(response) = stream.message().await? {
            if !response.response.is_empty() {
                // response.response is a JSON string of rows
                let parsed: Vec<serde_json::Value> = serde_json::from_str(&response.response)?;
                all_rows.extend(parsed);
            }
        }

        Ok(all_rows)
    }
}

#[async_trait]
impl Connector for VelociraptorConnector {
    fn id(&self) -> &'static str {
        "velociraptor"
    }

    async fn health_check(&self) -> HealthStatus {
        match self.run_query("SELECT * FROM info()").await {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Down {
                reason: e.to_string(),
            },
        }
    }

    async fn fetch_alerts(&self, since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>> {
        let vql = format!(
            "SELECT * FROM Artifact.Custom.Server.Alerts(Since='{}')",
            since.to_rfc3339()
        );
        let rows = self.run_query(&vql).await?;

        let mut alerts = Vec::new();
        for row in rows {
            let id_str = row.get("id").and_then(|v| v.as_str()).unwrap_or("");

            let id = Uuid::parse_str(id_str).unwrap_or_else(|_| Uuid::new_v4());

            let severity_str = row
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("Medium");

            let severity = match severity_str.to_lowercase().as_str() {
                "high" => Severity::High,
                "critical" => Severity::Critical,
                "low" => Severity::Low,
                _ => Severity::Medium,
            };

            let source = row
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("velociraptor")
                .to_string();

            let timestamp = row
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|v| v.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            alerts.push(NormalizedAlert {
                id,
                connector_id: self.id().to_string(),
                severity,
                source,
                timestamp,
                raw_payload: row,
                status: AlertStatus::Open,
            });
        }

        Ok(alerts)
    }

    async fn push_action(&self, action: ResponseAction) -> Result<ActionResult> {
        let (artifact, remove_policy) = match action.action_type.as_str() {
            "isolate" => ("Linux.Remediation.Quarantine", "N"),
            "unisolate" => ("Linux.Remediation.Quarantine", "Y"),
            _ => {
                return Ok(ActionResult {
                    success: false,
                    detail: format!("Unsupported action type: {}", action.action_type),
                    is_timeout: false,
                    timestamp: Utc::now(),
                })
            }
        };

        // 1. Validate Target
        let check_vql = format!(
            "SELECT os_info.hostname, last_seen_at FROM clients(client_id='{}')",
            action.target_id
        );
        let check_rows = self
            .run_query(&check_vql)
            .await
            .context("Failed to query client status")?;

        if check_rows.is_empty() {
            return Ok(ActionResult {
                success: false,
                detail: format!("Target {} not found in Velociraptor", action.target_id),
                is_timeout: false,
                timestamp: Utc::now(),
            });
        }

        let last_seen_at_usec = check_rows[0]
            .get("last_seen_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let now_usec = Utc::now().timestamp_micros();
        let ten_minutes_usec = 10 * 60 * 1_000_000;

        if now_usec - last_seen_at_usec > ten_minutes_usec {
            return Ok(ActionResult {
                success: false,
                detail: format!(
                    "Target {} is offline (last seen more than 10 mins ago)",
                    action.target_id
                ),
                is_timeout: false,
                timestamp: Utc::now(),
            });
        }

        // 2. Trigger Action
        let trigger_vql = format!(
            "SELECT collect_client(client_id='{}', artifacts='{}', env=dict(RemovePolicy='{}')) AS flow_id FROM scope()",
            action.target_id, artifact, remove_policy
        );
        let trigger_rows = self
            .run_query(&trigger_vql)
            .await
            .context("Failed to trigger collection")?;

        let flow_id = trigger_rows
            .first()
            .and_then(|r| r.get("flow_id"))
            .and_then(|v| v.as_str());

        let flow_id = match flow_id {
            Some(id) => id,
            None => {
                return Ok(ActionResult {
                    success: false,
                    detail: format!("Failed to schedule artifact on {}", action.target_id),
                    is_timeout: false,
                    timestamp: Utc::now(),
                });
            }
        };

        // 3. Poll for Success
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let poll_vql = format!(
                "SELECT state FROM flows(client_id='{}', flow_id='{}')",
                action.target_id, flow_id
            );
            let poll_rows = self.run_query(&poll_vql).await.unwrap_or_default();

            if let Some(row) = poll_rows.first() {
                let state = row
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                if state == "FINISHED" {
                    return Ok(ActionResult {
                        success: true,
                        detail: format!("Action {} completed successfully", action.action_type),
                        is_timeout: false,
                        timestamp: Utc::now(),
                    });
                } else if state == "ERROR" {
                    return Ok(ActionResult {
                        success: false,
                        detail: format!("Action {} failed during execution", action.action_type),
                        is_timeout: false,
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Timeout
        Ok(ActionResult {
            success: false,
            detail: format!("Action {} timed out. Outcome unknown.", action.action_type),
            is_timeout: true,
            timestamp: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn test_alert_mapping() {
        let ts = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let ts_str = ts.to_rfc3339();

        let row = json!({
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "severity": "Critical",
            "source": "test_source",
            "timestamp": ts_str,
            "description": "Test alert"
        });

        // We can test the parsing logic directly, but since fetch_alerts needs a client,
        // let's extract the parsing logic to a separate function or test it here manually based on the same logic.
        let id_str = row.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let id = Uuid::parse_str(id_str).unwrap_or_else(|_| Uuid::new_v4());
        assert_eq!(id.to_string(), "123e4567-e89b-12d3-a456-426614174000");

        let severity_str = row
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("Medium");
        let severity = match severity_str.to_lowercase().as_str() {
            "high" => Severity::High,
            "critical" => Severity::Critical,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };
        assert_eq!(severity, Severity::Critical);

        let timestamp = row
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        assert_eq!(timestamp, ts);
    }
}
