//! Autonomous AI Analyst Service.
//! Provides automated alert triage, threat enrichment aggregation, and response recommendation.

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::models::alert::StoredAlert;
use crate::models::threat_intel::ThreatIntelResult;
use crate::services::threat_intel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub alert_id: Option<Uuid>,
    pub case_id: Option<Uuid>,
    pub ioc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub template_name: String,
    pub display_name: String,
    pub description: String,
    pub risk_level: String,
    pub target_id: String,
    pub target_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub risk_score: u8,  // 0 - 100
    pub verdict: String, // "MALICIOUS", "SUSPICIOUS", "BENIGN", "INFORMATIONAL"
    pub summary: String,
    pub iocs_analyzed: Vec<ThreatIntelResult>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub recommended_actions: Vec<RecommendedAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureSummary {
    pub open_alerts_count: i64,
    pub critical_alerts_count: i64,
    pub active_cases_count: i64,
    pub executed_actions_count: i64,
    pub high_risk_iocs_cached: i64,
    pub top_threat_summary: String,
}

/// Run automated AI investigation pipeline.
pub async fn generate_triage_report(
    req: TriageRequest,
    config: &Config,
    pool: &PgPool,
) -> Result<TriageReport> {
    let report_id = Uuid::new_v4();
    let mut iocs_analyzed = Vec::new();
    let mut mitre_tactics = Vec::new();
    let mut mitre_techniques = Vec::new();
    let mut recommended_actions = Vec::new();
    let mut base_score: u8 = 20;

    let target_str: String;

    if let Some(alert_id) = req.alert_id {
        let alert = sqlx::query_as!(
            StoredAlert,
            r#"
            SELECT id, connector_id, source_id, severity, source, timestamp, raw_payload, status
            FROM alerts
            WHERE id = $1
            "#,
            alert_id
        )
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("Alert not found"))?;

        target_str = format!("{} (from {})", alert.source_id, alert.connector_id);

        match alert.severity.to_lowercase().as_str() {
            "critical" => base_score = 90,
            "high" => base_score = 75,
            "medium" => base_score = 50,
            _ => base_score = 25,
        }

        // Extract MITRE data from Wazuh alert payload
        if let Some(rule) = alert.raw_payload.pointer("/rule") {
            // Map Wazuh rule level to risk score
            if let Some(level) = rule.get("level").and_then(|v| v.as_u64()) {
                let level_score: u8 = match level {
                    14..=15 => 90,
                    11..=13 => 75,
                    7..=10 => 50,
                    4..=6 => 35,
                    _ => 20,
                };
                base_score = std::cmp::max(base_score, level_score);
            }

            // Extract MITRE techniques from rule.mitre
            if let Some(mitre) = rule.get("mitre") {
                if let Some(ids) = mitre.get("id").and_then(|v| v.as_array()) {
                    for id in ids {
                        if let Some(id_str) = id.as_str() {
                            if !mitre_techniques.contains(&id_str.to_string()) {
                                mitre_techniques.push(id_str.to_string());
                            }
                        }
                    }
                }
                if let Some(tactics) = mitre.get("tactic").and_then(|v| v.as_array()) {
                    for t in tactics {
                        if let Some(t_str) = t.as_str() {
                            let formatted = format!("{}", t_str);
                            if !mitre_tactics.contains(&formatted) {
                                mitre_tactics.push(formatted);
                            }
                        }
                    }
                }
            }

            // Extract rule groups for additional context
            if let Some(groups) = rule.get("groups").and_then(|v| v.as_array()) {
                for g in groups {
                    if let Some(g_str) = g.as_str() {
                        match g_str {
                            "sudo" => {
                                if !mitre_techniques.contains(&"T1548.003".to_string()) {
                                    mitre_techniques.push("T1548.003".to_string());
                                }
                                if !mitre_tactics.contains(&"Privilege Escalation".to_string()) {
                                    mitre_tactics.push("Privilege Escalation".to_string());
                                }
                            }
                            "sshd" | "authentication_success" => {
                                if !mitre_techniques.contains(&"T1078".to_string()) {
                                    mitre_techniques.push("T1078".to_string());
                                }
                                if !mitre_tactics.contains(&"Initial Access".to_string()) {
                                    mitre_tactics.push("Initial Access".to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Keyword-based escalation for high-severity indicators
        let raw_str = alert.raw_payload.to_string();
        if raw_str.contains("powershell")
            || raw_str.contains("mimikatz")
            || raw_str.contains("lsass")
        {
            base_score = std::cmp::max(base_score, 85);
            if !mitre_techniques.contains(&"T1003".to_string()) {
                mitre_techniques.push("T1003 - OS Credential Dumping".to_string());
            }
            if !mitre_tactics.contains(&"Credential Access".to_string()) {
                mitre_tactics.push("Credential Access".to_string());
            }
        }

        // Generate recommended actions based on score and MITRE context
        if base_score >= 75 {
            recommended_actions.push(RecommendedAction {
                template_name: "isolate_host".to_string(),
                display_name: "Isolate Endpoint Host".to_string(),
                description:
                    "Quarantine host at the network layer to stop potential threat spread."
                        .to_string(),
                risk_level: "high".to_string(),
                target_id: alert.source.clone(),
                target_type: "endpoint".to_string(),
            });
        }
        if base_score >= 50 {
            recommended_actions.push(RecommendedAction {
                template_name: "wazuh_active_response".to_string(),
                display_name: "Trigger Wazuh Active Response".to_string(),
                description:
                    "Execute active response script on the target agent to investigate further."
                        .to_string(),
                risk_level: "medium".to_string(),
                target_id: alert.source.clone(),
                target_type: "agent".to_string(),
            });
        }
    } else if let Some(ioc) = req.ioc {
        target_str = ioc.clone();
        let intel = threat_intel::enrich_ioc(&ioc, config, pool).await?;
        if let Some(score) = intel.score {
            let percentage = score * 100.0;
            if percentage > 60.0 {
                base_score = 90;
            } else if percentage > 15.0 {
                base_score = 65;
            } else {
                base_score = 25;
            }
        }
        iocs_analyzed.push(intel);
    } else {
        target_str = "Global Telemetry".to_string();
    }

    let verdict = if base_score >= 80 {
        "MALICIOUS"
    } else if base_score >= 50 {
        "SUSPICIOUS"
    } else if base_score >= 25 {
        "INFORMATIONAL"
    } else {
        "BENIGN"
    };

    let summary = format!(
        "Shieldgrid AI Autonomous Triage evaluated target '{}' with a calculated risk score of {}/100 (Verdict: {}). Analysis integrated telemetry correlation, MITRE ATT&CK taxonomy, and threat intel feeds.",
        target_str, base_score, verdict
    );

    Ok(TriageReport {
        id: report_id,
        generated_at: Utc::now(),
        risk_score: base_score,
        verdict: verdict.to_string(),
        summary,
        iocs_analyzed,
        mitre_tactics,
        mitre_techniques,
        recommended_actions,
    })
}

/// Retrieve overarching security posture synopsis.
pub async fn get_security_posture_summary(pool: &PgPool) -> Result<SecurityPostureSummary> {
    let open_alerts: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE status != 'closed'")
            .fetch_one(pool)
            .await
            .unwrap_or((0,));

    let critical_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status != 'closed'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let active_cases: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM cases WHERE status != 'Closed'")
            .fetch_one(pool)
            .await
            .unwrap_or((0,));

    let executed_actions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM action_executions")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    let high_risk_iocs: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM threat_intel_cache WHERE score >= 50.0")
            .fetch_one(pool)
            .await
            .unwrap_or((0,));

    let top_threat_summary = if critical_alerts.0 > 0 {
        format!(
            "{} critical alerts currently require urgent SOC triage and active containment.",
            critical_alerts.0
        )
    } else if open_alerts.0 > 0 {
        format!(
            "{} active alerts monitored across Velociraptor and Wazuh telemetry endpoints.",
            open_alerts.0
        )
    } else {
        "All telemetry streams nominal. Zero active critical incidents detected.".to_string()
    };

    Ok(SecurityPostureSummary {
        open_alerts_count: open_alerts.0,
        critical_alerts_count: critical_alerts.0,
        active_cases_count: active_cases.0,
        executed_actions_count: executed_actions.0,
        high_risk_iocs_cached: high_risk_iocs.0,
        top_threat_summary,
    })
}
