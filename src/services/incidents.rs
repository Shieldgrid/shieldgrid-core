//! Enhanced Incident Management — tasks, observables, and templates.
//!
//! # Overview
//!
//! Extends basic case management with:
//! - **Tasks**: Break cases into discrete, assignable checklist items
//! - **Observables**: Structured IOCs (IPs, hashes, domains) attached to cases
//! - **Templates**: Starting task/observable checklists for common incident types

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// ── Tasks ────────────────────────────────────────────────────────────────────

/// A task within a case.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseTask {
    pub id: Uuid,
    pub case_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: String,
    pub assigned_to: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a task.
#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    pub assigned_to: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Request to update a task.
#[derive(Debug, Deserialize)]
pub struct UpdateTaskRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub assigned_to: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Create a new task for a case.
pub async fn create_task(pool: &PgPool, case_id: Uuid, req: CreateTaskRequest) -> Result<CaseTask> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    let task = sqlx::query_as!(
        CaseTask,
        r#"
        INSERT INTO case_tasks (id, case_id, title, description, status, assigned_to, due_date, created_at, updated_at)
        VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8)
        RETURNING id, case_id, title, description, status, assigned_to, due_date, completed_at, created_at, updated_at
        "#,
        id,
        case_id,
        req.title,
        req.description.unwrap_or_default(),
        req.assigned_to,
        req.due_date,
        now,
        now,
    )
    .fetch_one(pool)
    .await?;

    Ok(task)
}

/// List all tasks for a case.
pub async fn list_tasks(pool: &PgPool, case_id: Uuid) -> Result<Vec<CaseTask>> {
    let tasks = sqlx::query_as!(
        CaseTask,
        r#"
        SELECT id, case_id, title, description, status, assigned_to, due_date, completed_at, created_at, updated_at
        FROM case_tasks
        WHERE case_id = $1
        ORDER BY created_at ASC
        "#,
        case_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

/// Update a task.
pub async fn update_task(pool: &PgPool, task_id: Uuid, req: UpdateTaskRequest) -> Result<CaseTask> {
    let now = Utc::now();
    let completed_at = if req.status.as_deref() == Some("completed") {
        Some(now)
    } else {
        None
    };

    let task = sqlx::query_as!(
        CaseTask,
        r#"
        UPDATE case_tasks
        SET
            title = COALESCE($2, title),
            description = COALESCE($3, description),
            status = COALESCE($4, status),
            assigned_to = COALESCE($5, assigned_to),
            due_date = COALESCE($6, due_date),
            completed_at = COALESCE($7, completed_at),
            updated_at = $8
        WHERE id = $1
        RETURNING id, case_id, title, description, status, assigned_to, due_date, completed_at, created_at, updated_at
        "#,
        task_id,
        req.title,
        req.description,
        req.status,
        req.assigned_to,
        req.due_date,
        completed_at,
        now,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Task not found"))?;

    Ok(task)
}

/// Delete a task.
pub async fn delete_task(pool: &PgPool, task_id: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM case_tasks WHERE id = $1", task_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── Observables ──────────────────────────────────────────────────────────────

/// An observable (IOC) attached to a case.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Observable {
    pub id: Uuid,
    pub case_id: Uuid,
    #[sqlx(rename = "type")]
    pub observable_type: String,
    pub value: String,
    pub description: String,
    pub confidence: String,
    pub source: String,
    pub tlp: String,
    pub enriched: bool,
    pub enrichment_data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an observable.
#[derive(Debug, Deserialize)]
pub struct CreateObservableRequest {
    #[serde(rename = "type")]
    pub observable_type: String,
    pub value: String,
    pub description: Option<String>,
    pub confidence: Option<String>,
    pub source: Option<String>,
    pub tlp: Option<String>,
}

/// Request to update an observable.
#[derive(Debug, Deserialize)]
pub struct UpdateObservableRequest {
    pub description: Option<String>,
    pub confidence: Option<String>,
    pub tlp: Option<String>,
    pub enriched: Option<bool>,
    pub enrichment_data: Option<serde_json::Value>,
}

/// Create a new observable for a case.
pub async fn create_observable(
    pool: &PgPool,
    case_id: Uuid,
    req: CreateObservableRequest,
) -> Result<Observable> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    let obs = sqlx::query_as!(
        Observable,
        r#"
        INSERT INTO observables (id, case_id, type, value, description, confidence, source, tlp, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, case_id, type as "observable_type", value, description, confidence, source, tlp, enriched, enrichment_data, created_at, updated_at
        "#,
        id,
        case_id,
        req.observable_type,
        req.value,
        req.description.unwrap_or_default(),
        req.confidence.unwrap_or_else(|| "low".to_string()),
        req.source.unwrap_or_else(|| "manual".to_string()),
        req.tlp.unwrap_or_else(|| "white".to_string()),
        now,
        now,
    )
    .fetch_one(pool)
    .await?;

    Ok(obs)
}

/// List all observables for a case.
pub async fn list_observables(pool: &PgPool, case_id: Uuid) -> Result<Vec<Observable>> {
    let obs = sqlx::query_as!(
        Observable,
        r#"
        SELECT id, case_id, type as "observable_type", value, description, confidence, source, tlp, enriched, enrichment_data, created_at, updated_at
        FROM observables
        WHERE case_id = $1
        ORDER BY created_at ASC
        "#,
        case_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(obs)
}

/// Update an observable.
pub async fn update_observable(
    pool: &PgPool,
    obs_id: Uuid,
    req: UpdateObservableRequest,
) -> Result<Observable> {
    let now = Utc::now();

    let obs = sqlx::query_as!(
        Observable,
        r#"
        UPDATE observables
        SET
            description = COALESCE($2, description),
            confidence = COALESCE($3, confidence),
            tlp = COALESCE($4, tlp),
            enriched = COALESCE($5, enriched),
            enrichment_data = COALESCE($6, enrichment_data),
            updated_at = $7
        WHERE id = $1
        RETURNING id, case_id, type as "observable_type", value, description, confidence, source, tlp, enriched, enrichment_data, created_at, updated_at
        "#,
        obs_id,
        req.description,
        req.confidence,
        req.tlp,
        req.enriched,
        req.enrichment_data,
        now,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Observable not found"))?;

    Ok(obs)
}

/// Delete an observable.
pub async fn delete_observable(pool: &PgPool, obs_id: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM observables WHERE id = $1", obs_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── Templates ────────────────────────────────────────────────────────────────

/// A case template with predefined tasks and observables.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseTemplate {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub category: String,
    pub tasks: serde_json::Value,
    pub observables: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// List all case templates.
pub async fn list_templates(pool: &PgPool) -> Result<Vec<CaseTemplate>> {
    let templates = sqlx::query_as!(
        CaseTemplate,
        r#"
        SELECT id, name, description, category, tasks, observables, created_at, updated_at
        FROM case_templates
        ORDER BY category, name
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get a specific case template.
pub async fn get_template(pool: &PgPool, id: Uuid) -> Result<Option<CaseTemplate>> {
    let template = sqlx::query_as!(
        CaseTemplate,
        r#"
        SELECT id, name, description, category, tasks, observables, created_at, updated_at
        FROM case_templates
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(template)
}

/// Apply a case template to create tasks and observables for a case.
pub async fn apply_template(
    pool: &PgPool,
    template_id: Uuid,
    case_id: Uuid,
) -> Result<(usize, usize)> {
    let template = get_template(pool, template_id)
        .await?
        .ok_or_else(|| anyhow!("Template not found"))?;

    let mut task_count = 0;
    let mut obs_count = 0;

    // Create tasks from template
    if let Some(tasks) = template.tasks.as_array() {
        for task_def in tasks {
            let title = task_def
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("Untitled task");
            let description = task_def
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let req = CreateTaskRequest {
                title: title.to_string(),
                description: Some(description.to_string()),
                assigned_to: None,
                due_date: None,
            };

            create_task(pool, case_id, req).await?;
            task_count += 1;
        }
    }

    // Create observables from template
    if let Some(obs_list) = template.observables.as_array() {
        for obs_def in obs_list {
            let obs_type = obs_def
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            let description = obs_def
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let req = CreateObservableRequest {
                observable_type: obs_type.to_string(),
                value: String::new(), // Placeholder - analyst fills in
                description: Some(description.to_string()),
                confidence: Some("low".to_string()),
                source: Some("template".to_string()),
                tlp: None,
            };

            create_observable(pool, case_id, req).await?;
            obs_count += 1;
        }
    }

    Ok((task_count, obs_count))
}

/// Get case progress (completed tasks / total tasks).
pub async fn get_case_progress(pool: &PgPool, case_id: Uuid) -> Result<(usize, usize)> {
    let total: (Option<i64>,) =
        sqlx::query_as("SELECT COUNT(*) FROM case_tasks WHERE case_id = $1")
            .bind(case_id)
            .fetch_one(pool)
            .await
            .map_err(|e| anyhow!("{e}"))?;

    let completed: (Option<i64>,) = sqlx::query_as(
        "SELECT COUNT(*) FROM case_tasks WHERE case_id = $1 AND status = 'completed'",
    )
    .bind(case_id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow!("{e}"))?;

    Ok((
        completed.0.unwrap_or(0) as usize,
        total.0.unwrap_or(0) as usize,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_observable_types() {
        let valid_types = [
            "ip",
            "domain",
            "hash_md5",
            "hash_sha256",
            "url",
            "email",
            "file_path",
            "user_agent",
        ];
        assert!(valid_types.contains(&"ip"));
        assert!(valid_types.contains(&"hash_sha256"));
    }
}
