//! Detection Rules and MITRE ATT&CK routes.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::models::detection::{
    DetectionRule, MitreMatrixResponse, MitreTactic, UpdateDetectionRuleRequest,
};
use crate::routes::AppState;
use crate::services::detection;

/// GET /api/v1/rules
///
/// List all detection rules.
pub async fn list_detection_rules_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<DetectionRule>>, (StatusCode, String)> {
    match detection::list_detection_rules(&state.db).await {
        Ok(rules) => Ok(Json(rules)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/rules/{id}
///
/// Retrieve a single detection rule.
pub async fn get_detection_rule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DetectionRule>, (StatusCode, String)> {
    match detection::get_detection_rule(id, &state.db).await {
        Ok(Some(rule)) => Ok(Json(rule)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "Detection rule not found".to_string(),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// PATCH /api/v1/rules/{id}
///
/// Update detection rule (enable/disable or severity).
pub async fn update_detection_rule_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateDetectionRuleRequest>,
) -> Result<Json<DetectionRule>, (StatusCode, String)> {
    match detection::update_detection_rule(id, payload, &state.db).await {
        Ok(updated) => Ok(Json(updated)),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// GET /api/v1/mitre/tactics
///
/// List all 14 Enterprise MITRE ATT&CK Tactics.
pub async fn list_mitre_tactics_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<MitreTactic>>, (StatusCode, String)> {
    match detection::list_mitre_tactics(&state.db).await {
        Ok(tactics) => Ok(Json(tactics)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/mitre/matrix
///
/// Retrieve full MITRE ATT&CK Matrix with technique detections.
pub async fn get_mitre_matrix_handler(
    State(state): State<AppState>,
) -> Result<Json<MitreMatrixResponse>, (StatusCode, String)> {
    match detection::get_mitre_matrix(&state.db).await {
        Ok(matrix) => Ok(Json(matrix)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
