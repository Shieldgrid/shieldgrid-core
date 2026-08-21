use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MitreTactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic_id: String,
    pub description: String,
    pub detection_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DetectionRule {
    pub id: Uuid,
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub category: String,
    pub connector_id: String,
    pub query_or_vql: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDetectionRuleRequest {
    pub enabled: Option<bool>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTacticMatrixColumn {
    pub tactic: MitreTactic,
    pub techniques: Vec<MitreTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMatrixResponse {
    pub columns: Vec<MitreTacticMatrixColumn>,
    pub total_techniques: usize,
    pub total_active_detections: i64,
}
