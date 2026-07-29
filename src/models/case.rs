use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Representation of a Case in the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct Case {
    pub id: Uuid,
    pub title: String,
    pub status: String,
    pub assigned_to: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for creating a case.
#[derive(Debug, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
}

/// Request body for partially updating a case.
#[derive(Debug, Deserialize)]
pub struct UpdateCaseRequest {
    pub status: Option<String>,
    pub assigned_to: Option<Uuid>,
}

/// Request body for linking an alert to a case.
#[derive(Debug, Deserialize)]
pub struct LinkAlertRequest {
    pub alert_id: String,
}
