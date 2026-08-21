//! Detection Rules & MITRE ATT&CK Catalog Service.

use anyhow::{anyhow, Result};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::detection::{
    DetectionRule, MitreMatrixResponse, MitreTactic, MitreTacticMatrixColumn, MitreTechnique,
    UpdateDetectionRuleRequest,
};

/// List all detection rules.
pub async fn list_detection_rules(pool: &PgPool) -> Result<Vec<DetectionRule>> {
    let rules = sqlx::query_as!(
        DetectionRule,
        r#"
        SELECT id, rule_id, name, description, severity, enabled, category, connector_id, query_or_vql, mitre_tactics, mitre_techniques, created_at, updated_at
        FROM detection_rules
        ORDER BY severity DESC, name ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rules)
}

/// Retrieve a single detection rule by ID.
pub async fn get_detection_rule(id: Uuid, pool: &PgPool) -> Result<Option<DetectionRule>> {
    let rule = sqlx::query_as!(
        DetectionRule,
        r#"
        SELECT id, rule_id, name, description, severity, enabled, category, connector_id, query_or_vql, mitre_tactics, mitre_techniques, created_at, updated_at
        FROM detection_rules
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    Ok(rule)
}

/// Update detection rule status (e.g. enable/disable or change severity).
pub async fn update_detection_rule(
    id: Uuid,
    req: UpdateDetectionRuleRequest,
    pool: &PgPool,
) -> Result<DetectionRule> {
    let existing = get_detection_rule(id, pool)
        .await?
        .ok_or_else(|| anyhow!("Detection rule not found"))?;

    let enabled = req.enabled.unwrap_or(existing.enabled);
    let severity = req.severity.unwrap_or(existing.severity);

    let updated = sqlx::query_as!(
        DetectionRule,
        r#"
        UPDATE detection_rules
        SET enabled = $1, severity = $2, updated_at = NOW()
        WHERE id = $3
        RETURNING id, rule_id, name, description, severity, enabled, category, connector_id, query_or_vql, mitre_tactics, mitre_techniques, created_at, updated_at
        "#,
        enabled,
        severity,
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// List all MITRE Tactics ordered by kill chain sequence.
pub async fn list_mitre_tactics(pool: &PgPool) -> Result<Vec<MitreTactic>> {
    let tactics = sqlx::query_as!(
        MitreTactic,
        r#"
        SELECT id, name, description, sort_order
        FROM mitre_tactics
        ORDER BY sort_order ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(tactics)
}

/// Construct the full Enterprise MITRE ATT&CK Matrix.
pub async fn get_mitre_matrix(pool: &PgPool) -> Result<MitreMatrixResponse> {
    let tactics = list_mitre_tactics(pool).await?;

    let all_techniques = sqlx::query_as!(
        MitreTechnique,
        r#"
        SELECT id, name, tactic_id, description, detection_count
        FROM mitre_techniques
        ORDER BY id ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    let mut columns = Vec::new();
    let mut total_active_detections: i64 = 0;

    for tactic in tactics {
        let matching_techniques: Vec<MitreTechnique> = all_techniques
            .iter()
            .filter(|t| t.tactic_id == tactic.id)
            .cloned()
            .collect();

        for tech in &matching_techniques {
            total_active_detections += tech.detection_count as i64;
        }

        columns.push(MitreTacticMatrixColumn {
            tactic,
            techniques: matching_techniques,
        });
    }

    Ok(MitreMatrixResponse {
        total_techniques: all_techniques.len(),
        total_active_detections,
        columns,
    })
}
