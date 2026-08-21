//! Threat intelligence API endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::models::threat_intel::{EnrichIocsRequest, EnrichIocsResponse, ThreatIntelResult};
use crate::routes::AppState;
use crate::services::threat_intel;

#[derive(Debug, Deserialize)]
pub struct LookupQuery {
    pub ioc: String,
}

/// GET /api/v1/threat-intel/lookup?ioc=...
///
/// Look up threat intelligence for a single indicator of compromise.
pub async fn lookup_ioc_handler(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> Result<Json<ThreatIntelResult>, (StatusCode, String)> {
    if query.ioc.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing 'ioc' query parameter".to_string(),
        ));
    }

    match threat_intel::enrich_ioc(&query.ioc, &state.config, &state.db).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// POST /api/v1/threat-intel/enrich
///
/// Batch enrich a list of indicators of compromise.
pub async fn enrich_iocs_handler(
    State(state): State<AppState>,
    Json(payload): Json<EnrichIocsRequest>,
) -> Json<EnrichIocsResponse> {
    let response = threat_intel::enrich_batch(&payload.iocs, &state.config, &state.db).await;
    Json(response)
}

/// GET /api/v1/threat-intel/epss/{cve}
///
/// Look up EPSS exploit probability score for a given CVE.
pub async fn lookup_epss_handler(
    State(state): State<AppState>,
    Path(cve): Path<String>,
) -> Result<Json<ThreatIntelResult>, (StatusCode, String)> {
    match threat_intel::lookup_epss(&cve, &state.db).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
