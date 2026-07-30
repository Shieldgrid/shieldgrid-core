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

/// The outcome of an attempted ResponseAction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// True if the action completed successfully, false otherwise.
    pub success: bool,
    /// Detailed message explaining the success or failure cause.
    pub detail: String,
    /// Whether the action reached a timeout/ambiguous state (if true, success is false).
    pub is_timeout: bool,
    /// The time the result was finalized.
    pub timestamp: DateTime<Utc>,
}

/// API payload for requesting an action.
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    pub connector_id: String,
    pub action_type: String,
    pub target_id: String,
}
