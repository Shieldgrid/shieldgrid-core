//! Shuffle webhook endpoints — receives workflow execution results.
//!
//! # Endpoints
//!
//! - `POST /api/v1/shuffle/webhook` — Receive workflow completion results
//! - `POST /api/v1/shuffle/trigger` — Manually trigger a workflow
//! - `GET /api/v1/shuffle/workflows` — List available workflows
//! - `GET /api/v1/shuffle/status/{execution_id}` — Get workflow execution status

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::connectors::shuffle::ShuffleConnector;
use crate::routes::AppState;

/// Webhook payload from Shuffle workflow completion.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ShuffleWebhookPayload {
    /// Workflow execution ID
    pub execution_id: String,
    /// Workflow ID
    pub workflow_id: Option<String>,
    /// Execution status
    pub status: Option<String>,
    /// Workflow result data
    pub result: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp of completion
    pub completed_at: Option<String>,
    /// Associated alert ID
    pub alert_id: Option<String>,
    /// Associated case ID
    pub case_id: Option<String>,
}

/// Response from webhook processing.
#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub success: bool,
    pub message: String,
    pub execution_id: String,
}

/// Request to manually trigger a workflow.
#[derive(Debug, Deserialize)]
pub struct TriggerWorkflowRequest {
    pub workflow_id: String,
    pub data: Option<serde_json::Value>,
    pub case_id: Option<String>,
    pub alert_id: Option<String>,
}

/// Response from workflow trigger.
#[derive(Debug, Serialize)]
pub struct TriggerWorkflowResponse {
    pub success: bool,
    pub execution_id: Option<String>,
    pub message: String,
}

/// List of workflows response.
#[derive(Debug, Serialize)]
pub struct ListWorkflowsResponse {
    pub workflows: Vec<serde_json::Value>,
}

/// GET /api/v1/shuffle/workflows
///
/// List available Shuffle workflows.
pub async fn list_workflows_handler(
    State(state): State<AppState>,
) -> Result<Json<ListWorkflowsResponse>, (StatusCode, String)> {
    let shuffle = find_shuffle_connector(&state)?;

    match shuffle.list_workflows().await {
        Ok(workflows) => Ok(Json(ListWorkflowsResponse { workflows })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list Shuffle workflows: {e}"),
        )),
    }
}

/// POST /api/v1/shuffle/trigger
///
/// Manually trigger a Shuffle workflow.
pub async fn trigger_workflow_handler(
    State(state): State<AppState>,
    Json(payload): Json<TriggerWorkflowRequest>,
) -> Result<Json<TriggerWorkflowResponse>, (StatusCode, String)> {
    let shuffle = find_shuffle_connector(&state)?;

    let data = payload.data.unwrap_or(serde_json::json!({}));

    match shuffle
        .trigger_workflow(
            &payload.workflow_id,
            data,
            payload.alert_id,
            payload.case_id,
        )
        .await
    {
        Ok(execution) => Ok(Json(TriggerWorkflowResponse {
            success: true,
            execution_id: Some(execution.id),
            message: "Workflow triggered successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to trigger workflow: {e}"),
        )),
    }
}

/// POST /api/v1/shuffle/webhook
///
/// Receive webhook from Shuffle when a workflow completes.
pub async fn webhook_handler(
    State(_state): State<AppState>,
    Json(payload): Json<ShuffleWebhookPayload>,
) -> Result<Json<WebhookResponse>, (StatusCode, String)> {
    tracing::info!(
        "Received Shuffle webhook for execution: {}",
        payload.execution_id
    );

    // TODO: Store webhook result in database
    // TODO: Update associated case/alert if case_id/alert_id provided
    // TODO: Trigger any follow-up actions based on workflow result

    Ok(Json(WebhookResponse {
        success: true,
        message: format!("Webhook received for execution {}", payload.execution_id),
        execution_id: payload.execution_id,
    }))
}

/// GET /api/v1/shuffle/status/{execution_id}
///
/// Get workflow execution status.
pub async fn get_execution_status_handler(
    State(state): State<AppState>,
    axum::extract::Path(execution_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let shuffle = find_shuffle_connector(&state)?;

    match shuffle.get_execution_status(&execution_id).await {
        Ok(execution) => Ok(Json(serde_json::to_value(&execution).unwrap())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get execution status: {e}"),
        )),
    }
}

/// Helper to find the Shuffle connector from state.
fn find_shuffle_connector(state: &AppState) -> Result<&ShuffleConnector, (StatusCode, String)> {
    for connector in &state.connectors {
        if connector.id() == "shuffle" {
            return connector
                .as_any()
                .downcast_ref::<ShuffleConnector>()
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to downcast Shuffle connector".to_string(),
                    )
                });
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        "Shuffle connector not configured".to_string(),
    ))
}
