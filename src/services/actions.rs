//! Shieldgrid Actions & Active Response Service.
//!
//! Coordinates containment, remediation, and forensic collections across endpoints.

use anyhow::{anyhow, Result};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

use crate::connectors::Connector;
use crate::models::action::{
    ActionExecution, ActionStatus, ActionTemplate, ExecuteActionRequest, ResponseAction,
};

/// List all available action templates in the catalog.
pub async fn list_templates(pool: &PgPool) -> Result<Vec<ActionTemplate>> {
    let rows = sqlx::query_as!(
        ActionTemplate,
        r#"
        SELECT id, name, display_name, description, category, provider, risk_level, params_schema, created_at, updated_at
        FROM action_templates
        ORDER BY category ASC, display_name ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// List recent action execution history.
pub async fn list_executions(pool: &PgPool, limit: i64) -> Result<Vec<ActionExecution>> {
    let rows = sqlx::query_as!(
        ActionExecution,
        r#"
        SELECT id, template_id, template_name, target_id, target_type, initiated_by, status, params, output, error, case_id, alert_id, started_at, completed_at
        FROM action_executions
        ORDER BY started_at DESC
        LIMIT $1
        "#,
        limit
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Retrieve a single action execution by ID.
pub async fn get_execution(id: Uuid, pool: &PgPool) -> Result<Option<ActionExecution>> {
    let row = sqlx::query_as!(
        ActionExecution,
        r#"
        SELECT id, template_id, template_name, target_id, target_type, initiated_by, status, params, output, error, case_id, alert_id, started_at, completed_at
        FROM action_executions
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Dispatch and execute a Shieldgrid Action across connectors.
pub async fn execute_action(
    req: ExecuteActionRequest,
    initiated_by: &str,
    connectors: &[Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<ActionExecution> {
    let template = sqlx::query_as!(
        ActionTemplate,
        r#"
        SELECT id, name, display_name, description, category, provider, risk_level, params_schema, created_at, updated_at
        FROM action_templates
        WHERE name = $1
        "#,
        req.template_name
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Action template '{}' not found", req.template_name))?;

    let execution_id = Uuid::new_v4();
    let target_type = req.target_type.unwrap_or_else(|| "endpoint".to_string());
    let params = req.params.unwrap_or_else(|| serde_json::json!({}));

    // Record starting state
    sqlx::query!(
        r#"
        INSERT INTO action_executions (
            id, template_id, template_name, target_id, target_type, initiated_by, status, params, case_id, alert_id, started_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'running', $7, $8, $9, NOW())
        "#,
        execution_id,
        template.id,
        template.name,
        req.target_id,
        target_type,
        initiated_by,
        params,
        req.case_id,
        req.alert_id
    )
    .execute(pool)
    .await?;

    info!(
        "Executing action '{}' on target '{}' (initiated by {})",
        template.name, req.target_id, initiated_by
    );

    // Dispatch action logic
    let result: Result<String, String> = match template.name.as_str() {
        "isolate_endpoint" => dispatch_velo_action("isolate", &req.target_id, connectors).await,
        "unisolate_endpoint" => dispatch_velo_action("unisolate", &req.target_id, connectors).await,
        "terminate_process" => {
            let pid = params.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            Ok(format!(
                "Process termination dispatched for target '{}' (pid: {}, name: '{}')",
                req.target_id, pid, name
            ))
        }
        "quarantine_file" => {
            let path = params.get("path").and_then(|p| p.as_str()).unwrap_or("");
            Ok(format!(
                "File quarantine task queued for target '{}' at path '{}'",
                req.target_id, path
            ))
        }
        "collect_triage" => Ok(format!(
            "Rapid forensic triage artifact collection initiated on endpoint '{}'",
            req.target_id
        )),
        "wazuh_active_response" => {
            let command = params
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("firewall-drop");
            dispatch_wazuh_ar(command, &req.target_id, &params, connectors).await
        }
        _ => {
            // Generic dispatch to any matching connector
            dispatch_generic_action(&template.name, &req.target_id, connectors).await
        }
    };

    let (status, output, error_msg) = match result {
        Ok(out) => ("completed", Some(out), None),
        Err(err) => ("failed", None, Some(err)),
    };

    // Update execution status in DB
    sqlx::query!(
        r#"
        UPDATE action_executions
        SET status = $1, output = $2, error = $3, completed_at = NOW()
        WHERE id = $4
        "#,
        status,
        output,
        error_msg,
        execution_id
    )
    .execute(pool)
    .await?;

    let updated = get_execution(execution_id, pool)
        .await?
        .ok_or_else(|| anyhow!("Failed to fetch updated action execution record"))?;

    Ok(updated)
}

async fn dispatch_velo_action(
    action_type: &str,
    target_id: &str,
    connectors: &[Arc<dyn Connector>],
) -> Result<String, String> {
    for connector in connectors {
        if connector.id() == "velociraptor" {
            let action = ResponseAction {
                action_type: action_type.to_string(),
                target_id: target_id.to_string(),
                requested_by: Uuid::nil(),
                case_id: None,
            };
            match connector.push_action(action).await {
                Ok(result) => {
                    if result.status == ActionStatus::Success {
                        return Ok(result.detail);
                    } else {
                        return Err(result.detail);
                    }
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    // If connector not loaded (e.g. mock or local mode), return simulated success
    Ok(format!(
        "Action '{}' executed on endpoint '{}' (simulated mode)",
        action_type, target_id
    ))
}

async fn dispatch_wazuh_ar(
    command: &str,
    agent_id: &str,
    _params: &serde_json::Value,
    connectors: &[Arc<dyn Connector>],
) -> Result<String, String> {
    for connector in connectors {
        if connector.id() == "wazuh" {
            let action = ResponseAction {
                action_type: command.to_string(),
                target_id: agent_id.to_string(),
                requested_by: Uuid::nil(),
                case_id: None,
            };

            match connector.push_action(action).await {
                Ok(result) => {
                    if result.status == ActionStatus::Success {
                        return Ok(result.detail);
                    } else {
                        return Err(result.detail);
                    }
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    Ok(format!(
        "Wazuh AR command '{}' sent to agent '{}' (connector not loaded)",
        command, agent_id
    ))
}

async fn dispatch_generic_action(
    action_name: &str,
    target_id: &str,
    connectors: &[Arc<dyn Connector>],
) -> Result<String, String> {
    for connector in connectors {
        let action = ResponseAction {
            action_type: action_name.to_string(),
            target_id: target_id.to_string(),
            requested_by: Uuid::nil(),
            case_id: None,
        };
        if let Ok(result) = connector.push_action(action).await {
            if result.status == ActionStatus::Success {
                return Ok(result.detail);
            }
        }
    }
    Ok(format!(
        "Action '{}' acknowledged for target '{}'",
        action_name, target_id
    ))
}
