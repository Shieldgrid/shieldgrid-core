use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An action requested against an endpoint through a Connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// The type of action to perform, e.g., "isolate", "unisolate"
    pub action_type: String,
    /// The target identifier, e.g., "C.12345" for Velociraptor
    pub target_id: String,
    /// The user ID of the analyst who requested the action
    pub requested_by: Uuid,
    /// Optional context such as the Case ID this action relates to
    pub case_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Success,
    Failure,
    Timeout,
}

/// The outcome of an attempted ResponseAction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The normalized outcome state.
    pub status: ActionStatus,
    /// Detailed message explaining the success or failure cause.
    pub detail: String,
    /// The time the result was finalized.
    pub timestamp: DateTime<Utc>,
}

/// API payload for requesting an action on a connector.
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    pub connector_id: String,
    pub action_type: String,
    pub target_id: String,
}

/// Predefined active response action template.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ActionTemplate {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub provider: String,
    pub risk_level: String,
    pub params_schema: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Audit record of an action execution.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ActionExecution {
    pub id: Uuid,
    pub template_id: Option<Uuid>,
    pub template_name: String,
    pub target_id: String,
    pub target_type: String,
    pub initiated_by: String,
    pub status: String,
    pub params: serde_json::Value,
    pub output: Option<String>,
    pub error: Option<String>,
    pub case_id: Option<Uuid>,
    pub alert_id: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// API payload to trigger a Shieldgrid action execution.
#[derive(Debug, Deserialize)]
pub struct ExecuteActionRequest {
    pub template_name: String,
    pub target_id: String,
    pub target_type: Option<String>,
    pub params: Option<serde_json::Value>,
    pub case_id: Option<Uuid>,
    pub alert_id: Option<Uuid>,
}
