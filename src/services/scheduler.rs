//! Scheduled actions service — runs recurring automation tasks.
//!
//! # Overview
//!
//! This service manages scheduled actions that run automatically based on
//! defined triggers or intervals. Examples:
//!
//! - "Every hour, check for new critical alerts and trigger Shuffle workflow"
//! - "Daily at 9am, generate security posture report"
//! - "Every 15 minutes, check connector health"
//!
//! # Architecture
//!
//! The scheduler runs as a background task that:
//! 1. Loads active schedules from the database
//! 2. Evaluates triggers (cron expressions, intervals, or event-based)
//! 3. Dispatches actions through the connector registry
//! 4. Records execution history in the audit log

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::connectors::Connector;
#[allow(unused_imports)]
use crate::models::action::ActionResult;
use crate::models::action::{ActionStatus, ResponseAction};

/// Schedule trigger types.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleTrigger {
    /// Run at a specific interval (e.g., every 15 minutes)
    Interval { seconds: u64 },
    /// Run at a specific time of day (cron expression)
    Cron { expression: String },
    /// Run when a condition is met (e.g., new critical alert)
    Event { event_type: String },
}

/// A scheduled action definition.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScheduledAction {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub connector_id: String,
    pub action_type: String,
    pub target_id: Option<String>,
    pub trigger: serde_json::Value,
    pub params: serde_json::Value,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Record of a scheduled action execution.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScheduledActionExecution {
    pub id: Uuid,
    pub schedule_id: Uuid,
    pub status: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub executed_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Create a new scheduled action.
#[allow(clippy::too_many_arguments)]
pub async fn create_schedule(
    pool: &PgPool,
    name: &str,
    description: &str,
    connector_id: &str,
    action_type: &str,
    target_id: Option<&str>,
    trigger: serde_json::Value,
    params: serde_json::Value,
) -> Result<ScheduledAction> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    // Calculate next run time based on trigger
    let next_run_at = calculate_next_run(&trigger, now)?;

    let row = sqlx::query_as!(
        ScheduledAction,
        r#"
        INSERT INTO scheduled_actions (id, name, description, connector_id, action_type, target_id, trigger, params, enabled, next_run_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, $10, $11)
        RETURNING id, name, description, connector_id, action_type, target_id, trigger, params, enabled, last_run_at, next_run_at, created_at, updated_at
        "#,
        id,
        name,
        description,
        connector_id,
        action_type,
        target_id,
        trigger,
        params,
        next_run_at,
        now,
        now
    )
    .fetch_one(pool)
    .await?;

    tracing::info!("Created scheduled action: {} ({})", name, id);
    Ok(row)
}

/// List all scheduled actions.
pub async fn list_schedules(pool: &PgPool) -> Result<Vec<ScheduledAction>> {
    let rows = sqlx::query_as!(
        ScheduledAction,
        r#"
        SELECT id, name, description, connector_id, action_type, target_id, trigger, params, enabled, last_run_at, next_run_at, created_at, updated_at
        FROM scheduled_actions
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get a specific scheduled action.
pub async fn get_schedule(pool: &PgPool, id: Uuid) -> Result<Option<ScheduledAction>> {
    let row = sqlx::query_as!(
        ScheduledAction,
        r#"
        SELECT id, name, description, connector_id, action_type, target_id, trigger, params, enabled, last_run_at, next_run_at, created_at, updated_at
        FROM scheduled_actions
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Update a scheduled action.
pub async fn update_schedule(
    pool: &PgPool,
    id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
    enabled: Option<bool>,
    trigger: Option<serde_json::Value>,
    params: Option<serde_json::Value>,
) -> Result<ScheduledAction> {
    let now = Utc::now();

    let row = sqlx::query_as!(
        ScheduledAction,
        r#"
        UPDATE scheduled_actions
        SET
            name = COALESCE($2, name),
            description = COALESCE($3, description),
            enabled = COALESCE($4, enabled),
            trigger = COALESCE($5, trigger),
            params = COALESCE($6, params),
            updated_at = $7
        WHERE id = $1
        RETURNING id, name, description, connector_id, action_type, target_id, trigger, params, enabled, last_run_at, next_run_at, created_at, updated_at
        "#,
        id,
        name,
        description,
        enabled,
        trigger,
        params,
        now
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Scheduled action not found"))?;

    Ok(row)
}

/// Delete a scheduled action.
pub async fn delete_schedule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM scheduled_actions WHERE id = $1", id)
        .execute(pool)
        .await?;

    tracing::info!("Deleted scheduled action: {}", id);
    Ok(())
}

/// Get scheduled actions that are due to run.
#[allow(dead_code)]
pub async fn get_due_schedules(pool: &PgPool) -> Result<Vec<ScheduledAction>> {
    let now = Utc::now();

    let rows = sqlx::query_as!(
        ScheduledAction,
        r#"
        SELECT id, name, description, connector_id, action_type, target_id, trigger, params, enabled, last_run_at, next_run_at, created_at, updated_at
        FROM scheduled_actions
        WHERE enabled = true AND (next_run_at IS NULL OR next_run_at <= $1)
        ORDER BY next_run_at ASC
        "#,
        now
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Execute a scheduled action.
#[allow(dead_code)]
pub async fn execute_scheduled_action(
    schedule: &ScheduledAction,
    connectors: &[std::sync::Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<()> {
    let execution_id = Uuid::new_v4();
    let now = Utc::now();

    // Record execution start
    sqlx::query!(
        r#"
        INSERT INTO scheduled_action_executions (id, schedule_id, status, executed_at)
        VALUES ($1, $2, 'running', $3)
        "#,
        execution_id,
        schedule.id,
        now
    )
    .execute(pool)
    .await?;

    // Find the connector
    let connector = connectors
        .iter()
        .find(|c| c.id() == schedule.connector_id)
        .ok_or_else(|| anyhow!("Connector '{}' not found", schedule.connector_id))?;

    // Build the action
    let target_id = schedule
        .target_id
        .clone()
        .unwrap_or_else(|| "default".to_string());

    let action = ResponseAction {
        action_type: schedule.action_type.clone(),
        target_id,
        requested_by: Uuid::nil(), // System-initiated
        case_id: None,
    };

    // Execute the action
    let result = connector.push_action(action).await;

    // Update execution record
    let (status, result_msg, error_msg) = match &result {
        Ok(action_result) => {
            let status = match action_result.status {
                ActionStatus::Success => "completed",
                ActionStatus::Failure => "failed",
                ActionStatus::Timeout => "timeout",
            };
            (
                status,
                Some(action_result.detail.clone()),
                if action_result.status == ActionStatus::Failure {
                    Some(action_result.detail.clone())
                } else {
                    None
                },
            )
        }
        Err(e) => ("failed", None, Some(e.to_string())),
    };

    let completed_at = Utc::now();

    sqlx::query!(
        r#"
        UPDATE scheduled_action_executions
        SET status = $1, result = $2, error = $3, completed_at = $4
        WHERE id = $5
        "#,
        status,
        result_msg,
        error_msg,
        completed_at,
        execution_id
    )
    .execute(pool)
    .await?;

    // Update schedule's last_run_at and calculate next_run_at
    let next_run_at = calculate_next_run(&schedule.trigger, completed_at)?;

    sqlx::query!(
        r#"
        UPDATE scheduled_actions
        SET last_run_at = $2, next_run_at = $3, updated_at = $4
        WHERE id = $1
        "#,
        schedule.id,
        completed_at,
        next_run_at,
        completed_at
    )
    .execute(pool)
    .await?;

    tracing::info!(
        "Executed scheduled action '{}' ({}): {}",
        schedule.name,
        schedule.id,
        status
    );

    Ok(())
}

/// Get execution history for a scheduled action.
pub async fn get_execution_history(
    pool: &PgPool,
    schedule_id: Uuid,
    limit: i64,
) -> Result<Vec<ScheduledActionExecution>> {
    let rows = sqlx::query_as!(
        ScheduledActionExecution,
        r#"
        SELECT id, schedule_id, status, result, error, executed_at, completed_at
        FROM scheduled_action_executions
        WHERE schedule_id = $1
        ORDER BY executed_at DESC
        LIMIT $2
        "#,
        schedule_id,
        limit
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Calculate the next run time based on trigger configuration.
fn calculate_next_run(
    trigger: &serde_json::Value,
    after: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>> {
    let trigger_type = trigger
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("Trigger missing 'type' field"))?;

    match trigger_type {
        "interval" => {
            let seconds = trigger
                .get("seconds")
                .and_then(|s| s.as_u64())
                .ok_or_else(|| anyhow!("Interval trigger missing 'seconds' field"))?;

            let next = after + chrono::Duration::seconds(seconds as i64);
            Ok(Some(next))
        }
        "cron" => {
            // For now, just use a simple interval-based approach
            // A proper cron parser would be needed for production use
            let _expression = trigger
                .get("expression")
                .and_then(|e| e.as_str())
                .ok_or_else(|| anyhow!("Cron trigger missing 'expression' field"))?;

            // Default to 1 hour for cron expressions (simplified)
            let next = after + chrono::Duration::hours(1);
            Ok(Some(next))
        }
        "event" => {
            // Event-based triggers don't have a next run time
            // They're evaluated when events occur
            Ok(None)
        }
        _ => Err(anyhow!("Unknown trigger type: {}", trigger_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_calculate_next_run_interval() {
        let trigger = json!({
            "type": "interval",
            "seconds": 3600
        });

        let now = Utc::now();
        let next = calculate_next_run(&trigger, now).unwrap().unwrap();

        let diff = (next - now).num_seconds();
        assert!((3599..=3601).contains(&diff));
    }

    #[test]
    fn test_calculate_next_run_event() {
        let trigger = json!({
            "type": "event",
            "event_type": "new_critical_alert"
        });

        let now = Utc::now();
        let next = calculate_next_run(&trigger, now).unwrap();
        assert!(next.is_none());
    }
}
