//! Shuffle SOAR connector — triggers and monitors Shuffle workflows.
//!
//! # Data flow
//!
//! ```text
//! ShuffleConnector::trigger_workflow(workflow_id, payload)
//!   └─ POST {shuffle_url}/api/v1/workflows/{workflow_id}/execution
//!      └─ parse execution ID
//!         └─ poll for completion
//! ```
//!
//! # Authentication
//!
//! Uses API key authentication via the `Authorization: Bearer {api_key}` header.
//! The API key should be set in the `SHUFFLE_API_KEY` environment variable.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connectors::{Connector, HealthStatus};
use crate::models::action::{ActionResult, ActionStatus, ResponseAction};
use crate::models::alert::NormalizedAlert;

/// Configuration for the Shuffle connector.
#[derive(Debug, Clone)]
pub struct ShuffleConfig {
    /// Shuffle API base URL (e.g. `http://localhost:3001`)
    pub api_url: String,
    /// API key for authentication
    pub api_key: String,
}

/// Shuffle workflow execution status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    Started,
    Running,
    Waiting,
    Completed,
    Error,
    Aborted,
}

/// A Shuffle workflow execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: String,
    pub workflow_id: String,
    pub status: ExecutionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

/// Request to trigger a Shuffle workflow.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct TriggerWorkflowRequest {
    /// Workflow ID to execute
    pub workflow_id: String,
    /// Input data for the workflow
    pub data: Value,
    /// Optional originating alert ID for tracking
    pub alert_id: Option<String>,
    /// Optional originating case ID for tracking
    pub case_id: Option<String>,
}

/// Response from triggering a workflow.
#[derive(Debug, Deserialize)]
pub struct TriggerWorkflowResponse {
    pub success: bool,
    pub execution_id: Option<String>,
    pub message: Option<String>,
}

/// Shuffle connector implementation.
pub struct ShuffleConnector {
    client: Client,
    config: ShuffleConfig,
}

impl ShuffleConnector {
    /// Create a new Shuffle connector from configuration.
    pub fn new(config: ShuffleConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {e}"))?;

        Ok(Self { client, config })
    }

    /// Trigger a Shuffle workflow execution.
    pub async fn trigger_workflow(
        &self,
        workflow_id: &str,
        data: Value,
        alert_id: Option<String>,
        case_id: Option<String>,
    ) -> Result<WorkflowExecution> {
        let url = format!(
            "{}/api/v1/workflows/{}/execution",
            self.config.api_url, workflow_id
        );

        let payload = serde_json::json!({
            "data": data,
            "alert_id": alert_id,
            "case_id": case_id,
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.config.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow!("Shuffle API request failed: {e}"))?;

        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status_code.is_success() {
            return Err(anyhow!("Shuffle API returned {}: {}", status_code, body));
        }

        let response: TriggerWorkflowResponse = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse Shuffle response: {e}"))?;

        if !response.success {
            return Err(anyhow!(
                "Shuffle workflow trigger failed: {}",
                response
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        let execution_id = response
            .execution_id
            .ok_or_else(|| anyhow!("Shuffle response missing execution_id"))?;

        tracing::info!(
            "Shuffle workflow '{}' triggered, execution: {}",
            workflow_id,
            execution_id
        );

        Ok(WorkflowExecution {
            id: execution_id,
            workflow_id: workflow_id.to_string(),
            status: ExecutionStatus::Started,
            started_at: Some(Utc::now()),
            completed_at: None,
            result: None,
            error: None,
        })
    }

    /// Poll workflow execution status.
    pub async fn get_execution_status(&self, execution_id: &str) -> Result<WorkflowExecution> {
        let url = format!(
            "{}/api/v1/workflows/executions/{}",
            self.config.api_url, execution_id
        );

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.config.api_key)
            .send()
            .await
            .map_err(|e| anyhow!("Shuffle API request failed: {e}"))?;

        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status_code.is_success() {
            return Err(anyhow!("Shuffle API returned {}: {}", status_code, body));
        }

        let json: Value = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse Shuffle response: {e}"))?;

        // Parse the execution status from the response
        let status_str = json
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        let status = match status_str {
            "started" => ExecutionStatus::Started,
            "running" => ExecutionStatus::Running,
            "waiting" => ExecutionStatus::Waiting,
            "completed" => ExecutionStatus::Completed,
            "error" => ExecutionStatus::Error,
            "aborted" => ExecutionStatus::Aborted,
            _ => ExecutionStatus::Running,
        };

        Ok(WorkflowExecution {
            id: execution_id.to_string(),
            workflow_id: json
                .get("workflow_id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            status,
            started_at: json
                .get("started_at")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok()),
            completed_at: json
                .get("completed_at")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok()),
            result: json.get("result").cloned(),
            error: json.get("error").and_then(|s| s.as_str()).map(String::from),
        })
    }

    /// Wait for a workflow execution to complete (polls until done).
    #[allow(dead_code)]
    pub async fn wait_for_completion(
        &self,
        execution_id: &str,
        timeout_secs: u64,
    ) -> Result<WorkflowExecution> {
        let start = Utc::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            let execution = self.get_execution_status(execution_id).await?;

            match execution.status {
                ExecutionStatus::Completed | ExecutionStatus::Error | ExecutionStatus::Aborted => {
                    return Ok(execution);
                }
                _ => {
                    if Utc::now() - start
                        > chrono::Duration::from_std(timeout)
                            .map_err(|e| anyhow!("Time error: {e}"))?
                    {
                        return Err(anyhow!(
                            "Workflow execution {} timed out after {}s",
                            execution_id,
                            timeout_secs
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// List available workflows in Shuffle.
    pub async fn list_workflows(&self) -> Result<Vec<Value>> {
        let url = format!("{}/api/v1/workflows", self.config.api_url);

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.config.api_key)
            .send()
            .await
            .map_err(|e| anyhow!("Shuffle API request failed: {e}"))?;

        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status_code.is_success() {
            return Err(anyhow!("Shuffle API returned {}: {}", status_code, body));
        }

        let json: Value = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse Shuffle response: {e}"))?;

        json.get("workflows")
            .and_then(|w| w.as_array())
            .cloned()
            .ok_or_else(|| anyhow!("Invalid Shuffle workflows response"))
    }
}

#[async_trait]
impl Connector for ShuffleConnector {
    fn id(&self) -> &'static str {
        "shuffle"
    }

    async fn health_check(&self) -> HealthStatus {
        let url = format!("{}/api/v1/workflows", self.config.api_url);

        match self
            .client
            .get(&url)
            .bearer_auth(&self.config.api_key)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Down {
                        reason: format!("Shuffle API returned {}", resp.status()),
                    }
                }
            }
            Err(e) => HealthStatus::Down {
                reason: format!("Shuffle API unreachable: {e}"),
            },
        }
    }

    async fn fetch_alerts(&self, _since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>> {
        // Shuffle is an automation platform, not an alert source.
        // It doesn't produce alerts in the traditional sense.
        // Webhook results from workflows are handled separately via the webhook endpoint.
        Ok(Vec::new())
    }

    async fn push_action(&self, action: ResponseAction) -> Result<ActionResult> {
        // The Shuffle connector's "action" is triggering a workflow.
        // The action_type should be the workflow_id to trigger.
        let workflow_id = &action.action_type;

        match self
            .trigger_workflow(
                workflow_id,
                serde_json::json!({
                    "target_id": action.target_id,
                    "requested_by": action.requested_by,
                    "case_id": action.case_id,
                }),
                None,
                action.case_id.map(|id| id.to_string()),
            )
            .await
        {
            Ok(execution) => Ok(ActionResult {
                status: ActionStatus::Success,
                detail: format!(
                    "Shuffle workflow '{}' triggered, execution: {}",
                    workflow_id, execution.id
                ),
                timestamp: Utc::now(),
            }),
            Err(e) => Ok(ActionResult {
                status: ActionStatus::Failure,
                detail: format!("Failed to trigger Shuffle workflow: {e}"),
                timestamp: Utc::now(),
            }),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_execution_status_serialization() {
        let status = ExecutionStatus::Completed;
        let serialized = serde_json::to_string(&status).unwrap();
        assert_eq!(serialized, "\"completed\"");

        let deserialized: ExecutionStatus = serde_json::from_str("\"running\"").unwrap();
        assert_eq!(deserialized, ExecutionStatus::Running);
    }

    #[test]
    fn test_trigger_workflow_request() {
        let request = TriggerWorkflowRequest {
            workflow_id: "test-workflow-123".to_string(),
            data: json!({"ip": "192.168.1.100"}),
            alert_id: Some("alert-123".to_string()),
            case_id: Some("case-456".to_string()),
        };

        let serialized = serde_json::to_value(&request).unwrap();
        assert_eq!(serialized["workflow_id"], "test-workflow-123");
        assert_eq!(serialized["data"]["ip"], "192.168.1.100");
    }
}
