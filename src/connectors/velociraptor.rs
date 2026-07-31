use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::config::Config;
use crate::connectors::{Connector, HealthStatus};
use crate::models::action::{ActionResult, ActionStatus, ResponseAction};
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

    /// Run an arbitrary VQL query against the Velociraptor server and stream
    /// the result rows back as JSON values.
    ///
    /// Server-side only: the gRPC `query` API executes in the server context.
    /// Queries are capped at 500 rows and 30 s execution time.
    pub async fn run_query(&self, query: &str) -> Result<Vec<serde_json::Value>> {
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

    /// List the clients registered with the server (hostname, OS, version, last seen).
    pub async fn list_clients(&self) -> Result<Vec<serde_json::Value>> {
        self.run_query(
            "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, os_info.architecture AS arch, client_version, last_seen_at FROM clients()",
        )
        .await
    }

    /// List the artifacts available on the server (name, description).
    ///
    /// Uses `artifact_definitions()` — the server-scope plugin in Velociraptor
    /// 0.77 (the older `artifact_list()` plugin no longer exists).
    pub async fn list_artifacts(&self) -> Result<Vec<serde_json::Value>> {
        self.run_query("SELECT name, description FROM artifact_definitions()")
            .await
    }

    /// Run a client artifact on a specific endpoint and return its results.
    ///    /// This is the *correct* client-scoping path: the plain
    /// `SELECT * FROM Artifact.X() FROM clients(client_id=...)` form silently
    /// returns nothing through the raw gRPC `query` API, so we dispatch a real
    /// collection (`collect_client`), then read the stored results via
    /// `flow_results()`.
    ///
    /// `params` are passed as the artifact's env (e.g. `Command` for shell
    /// artifacts). Note that shell artifacts (`Linux.Sys.BashShell` and
    /// friends) open an interactive session: results are produced within
    /// seconds while the flow itself stays `IN_PROGRESS` until the session
    /// timeout, so we return as soon as `flow_results()` yields rows rather
    /// than waiting for the flow to reach `FINISHED`.
    ///
    /// Polls for up to 60 s; returns an error if the flow ends in an error
    /// state or produces no results in time.
    pub async fn run_artifact_on_client(
        &self,
        artifact: &str,
        params: &[(String, String)],
        client_id: &str,
    ) -> Result<Vec<serde_json::Value>> {
        // 1. Dispatch the collection.
        let env_parts: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, vql_quote(v)))
            .collect();
        let env_clause = if env_parts.is_empty() {
            String::new()
        } else {
            format!(", env=dict({})", env_parts.join(", "))
        };

        let dispatch_vql = format!(
            "SELECT collect_client(client_id='{}', artifacts='{}'{}) AS flow_id FROM scope()",
            client_id, artifact, env_clause
        );

        let dispatch_rows = self.run_query(&dispatch_vql).await?;
        let flow_id = extract_flow_id(dispatch_rows.first())?;

        // 2. Poll for results (return as soon as any appear) and watch for
        //    error states.
        let mut final_state: Option<String> = None;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let poll_vql = format!(
                "SELECT state FROM flows(client_id='{}', flow_id='{}')",
                client_id, flow_id
            );
            if let Ok(rows) = self.run_query(&poll_vql).await {
                if let Some(state) = rows
                    .first()
                    .and_then(|r| r.get("state"))
                    .and_then(Value::as_str)
                {
                    final_state = Some(state.to_string());
                    if state == "ERROR" {
                        return Err(anyhow::anyhow!(
                            "artifact {artifact} failed on client {client_id} (flow {flow_id})"
                        ));
                    }
                }
            }

            let results_vql = format!(
                "SELECT * FROM flow_results(client_id='{}', flow_id='{}')",
                client_id, flow_id
            );
            if let Ok(rows) = self.run_query(&results_vql).await {
                if !rows.is_empty() {
                    return Ok(rows);
                }
                if final_state.as_deref() == Some("FINISHED") {
                    return Ok(rows);
                }
            }
        }

        Err(anyhow::anyhow!(
            "artifact {artifact} on client {client_id} produced no results within 60s (flow {flow_id}, last state {})",
            final_state.unwrap_or_else(|| "unknown".into())
        ))
    }
}

/// Quote a value as a VQL string literal, escaping backslashes and quotes.
fn vql_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{}'", escaped)
}

/// Extract a flow id from the `collect_client` result row.
///
/// The row is `{"flow_id": {"flow_id": "F.xxx", "request": {...}}}` — the
/// value is itself an object containing the id.
fn extract_flow_id(row: Option<&serde_json::Value>) -> Result<String> {
    let row = row.ok_or_else(|| anyhow::anyhow!("collect_client returned no flow id"))?;
    let flow_id = row
        .get("flow_id")
        .and_then(|v| {
            v.as_str().map(|s| s.to_string()).or_else(|| {
                v.get("flow_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
        })
        .ok_or_else(|| anyhow::anyhow!("collect_client response missing flow_id: {}", row))?;
    Ok(flow_id)
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
                    status: ActionStatus::Failure,
                    detail: format!("Unsupported action type: {}", action.action_type),
                    timestamp: Utc::now(),
                })
            }
        };

        // 1. Validate Target
        let check_vql = format!(
            "SELECT os_info.hostname, last_seen_at FROM clients(client_id='{}')",
            action.target_id
        );
        let check_rows = match self.run_query(&check_vql).await {
            Ok(rows) => rows,
            Err(e) => {
                return Ok(ActionResult {
                    status: ActionStatus::Failure,
                    detail: format!("Pre-flight check failed due to connection error: {e}"),
                    timestamp: Utc::now(),
                });
            }
        };

        if check_rows.is_empty() {
            return Ok(ActionResult {
                status: ActionStatus::Failure,
                detail: format!("Target {} not found in Velociraptor", action.target_id),
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
                status: ActionStatus::Failure,
                detail: format!(
                    "Target {} is offline (last seen more than 10 mins ago)",
                    action.target_id
                ),
                timestamp: Utc::now(),
            });
        }

        // 2. Trigger Action
        let trigger_vql = format!(
            "SELECT collect_client(client_id='{}', artifacts='{}', env=dict(RemovePolicy='{}')) AS flow_id FROM scope()",
            action.target_id, artifact, remove_policy
        );
        let trigger_rows = match self.run_query(&trigger_vql).await {
            Ok(rows) => rows,
            Err(e) => {
                // If the dispatch query fails, we lost connection BEFORE or DURING dispatch.
                // It is ambiguous if Velociraptor received it.
                return Ok(ActionResult {
                    status: ActionStatus::Timeout,
                    detail: format!("Connection dropped during dispatch: {e}. Outcome unknown."),
                    timestamp: Utc::now(),
                });
            }
        };

        let flow_id = trigger_rows
            .first()
            .and_then(|r| r.get("flow_id"))
            .and_then(|v| v.as_str());

        let flow_id = match flow_id {
            Some(id) => id,
            None => {
                // The query succeeded, but returned no flow_id.
                // The action was definitively not scheduled.
                return Ok(ActionResult {
                    status: ActionStatus::Failure,
                    detail: format!(
                        "Failed to schedule artifact on {} (no flow_id returned)",
                        action.target_id
                    ),
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

            let poll_rows = match self.run_query(&poll_vql).await {
                Ok(rows) => rows,
                Err(_) => {
                    // We ignore intermediate poll errors (just continue the loop).
                    // If it drops entirely, we will just time out.
                    continue;
                }
            };

            if let Some(row) = poll_rows.first() {
                let state = row
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                if state == "FINISHED" {
                    return Ok(ActionResult {
                        status: ActionStatus::Success,
                        detail: format!("Action {} completed successfully", action.action_type),
                        timestamp: Utc::now(),
                    });
                } else if state == "ERROR" {
                    return Ok(ActionResult {
                        status: ActionStatus::Failure,
                        detail: format!("Action {} failed during execution", action.action_type),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Timeout (either connection dropped repeatedly mid-poll, or just took too long)
        Ok(ActionResult {
            status: ActionStatus::Timeout,
            detail: format!("Action {} timed out. Outcome unknown.", action.action_type),
            timestamp: Utc::now(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
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
