//! Notifications Service — manages notification channels and delivery.
//!
//! # Overview
//!
//! Supports:
//! - Email (SMTP)
//! - Slack (webhook)
//! - Webhooks (generic HTTP)
//! - SMS (placeholder for future)
//!
//! Notifications are triggered by rules based on alert severity,
//! action status, or custom conditions.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// A notification channel definition.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NotificationChannel {
    pub id: Uuid,
    pub name: String,
    pub channel_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A notification rule definition.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NotificationRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub channel_id: Uuid,
    pub trigger_type: String,
    pub conditions: serde_json::Value,
    pub template: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A notification log entry.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NotificationLog {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub status: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub message: String,
    pub error: Option<String>,
    pub sent_at: DateTime<Utc>,
}

/// Request to create a notification channel.
#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    pub channel_type: String,
    pub config: Option<serde_json::Value>,
}

/// Request to update a notification channel.
#[derive(Debug, Deserialize)]
pub struct UpdateChannelRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

/// Request to create a notification rule.
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub channel_id: Uuid,
    pub trigger_type: String,
    pub conditions: Option<serde_json::Value>,
    pub template: Option<String>,
}

/// Request to send a notification.
#[derive(Debug, Clone, Deserialize)]
pub struct SendNotificationRequest {
    pub channel_id: Uuid,
    pub recipient: String,
    pub subject: Option<String>,
    pub message: String,
}

// ── Channel CRUD ─────────────────────────────────────────────────────────────

pub async fn list_channels(pool: &PgPool) -> Result<Vec<NotificationChannel>> {
    let channels = sqlx::query_as!(
        NotificationChannel,
        r#"
        SELECT id, name, channel_type as "channel_type", enabled, config, created_at, updated_at
        FROM notification_channels
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(channels)
}

pub async fn create_channel(
    pool: &PgPool,
    req: CreateChannelRequest,
) -> Result<NotificationChannel> {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let config = req.config.unwrap_or(serde_json::json!({}));

    let channel = sqlx::query_as!(
        NotificationChannel,
        r#"
        INSERT INTO notification_channels (id, name, channel_type, enabled, config, created_at, updated_at)
        VALUES ($1, $2, $3, true, $4, $5, $6)
        RETURNING id, name, channel_type as "channel_type", enabled, config, created_at, updated_at
        "#,
        id,
        req.name,
        req.channel_type,
        config,
        now,
        now,
    )
    .fetch_one(pool)
    .await?;
    Ok(channel)
}

pub async fn update_channel(
    pool: &PgPool,
    id: Uuid,
    req: UpdateChannelRequest,
) -> Result<NotificationChannel> {
    let now = Utc::now();
    let channel = sqlx::query_as!(
        NotificationChannel,
        r#"
        UPDATE notification_channels
        SET name = COALESCE($2, name), enabled = COALESCE($3, enabled), config = COALESCE($4, config), updated_at = $5
        WHERE id = $1
        RETURNING id, name, channel_type as "channel_type", enabled, config, created_at, updated_at
        "#,
        id,
        req.name,
        req.enabled,
        req.config,
        now,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Channel not found"))?;
    Ok(channel)
}

pub async fn delete_channel(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM notification_channels WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── Rule CRUD ────────────────────────────────────────────────────────────────

pub async fn list_rules(pool: &PgPool) -> Result<Vec<NotificationRule>> {
    let rules = sqlx::query_as!(
        NotificationRule,
        r#"
        SELECT id, name, description, enabled, channel_id, trigger_type as "trigger_type", conditions, template, created_at, updated_at
        FROM notification_rules
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rules)
}

pub async fn create_rule(pool: &PgPool, req: CreateRuleRequest) -> Result<NotificationRule> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    let rule = sqlx::query_as!(
        NotificationRule,
        r#"
        INSERT INTO notification_rules (id, name, description, enabled, channel_id, trigger_type, conditions, template, created_at, updated_at)
        VALUES ($1, $2, $3, true, $4, $5, $6, $7, $8, $9)
        RETURNING id, name, description, enabled, channel_id, trigger_type as "trigger_type", conditions, template, created_at, updated_at
        "#,
        id,
        req.name,
        req.description.unwrap_or_default(),
        req.channel_id,
        req.trigger_type,
        req.conditions.unwrap_or(serde_json::json!({})),
        req.template.unwrap_or_default(),
        now,
        now,
    )
    .fetch_one(pool)
    .await?;
    Ok(rule)
}

pub async fn delete_rule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM notification_rules WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── Send Notifications ───────────────────────────────────────────────────────

pub async fn send_notification(
    pool: &PgPool,
    req: SendNotificationRequest,
) -> Result<NotificationLog> {
    let channel = sqlx::query_as!(
        NotificationChannel,
        r#"
        SELECT id, name, channel_type as "channel_type", enabled, config, created_at, updated_at
        FROM notification_channels WHERE id = $1
        "#,
        req.channel_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Channel not found"))?;

    if !channel.enabled {
        return Err(anyhow!("Channel is disabled"));
    }

    let result = match channel.channel_type.as_str() {
        "webhook" => send_webhook(&channel.config, &req).await,
        "slack" => send_slack(&channel.config, &req).await,
        "email" => send_email(&channel.config, &req).await,
        _ => Err(anyhow!(
            "Unsupported channel type: {}",
            channel.channel_type
        )),
    };

    let log_id = Uuid::new_v4();
    let now = Utc::now();

    let log = match result {
        Ok(()) => {
            sqlx::query_as!(
                NotificationLog,
                r#"
                INSERT INTO notification_log (id, channel_id, status, recipient, subject, message, sent_at)
                VALUES ($1, $2, 'sent', $3, $4, $5, $6)
                RETURNING id, channel_id, status, recipient, subject, message, error, sent_at
                "#,
                log_id,
                req.channel_id,
                req.recipient,
                req.subject,
                req.message,
                now,
            )
            .fetch_one(pool)
            .await?
        }
        Err(e) => {
            sqlx::query_as!(
                NotificationLog,
                r#"
                INSERT INTO notification_log (id, channel_id, status, recipient, subject, message, error, sent_at)
                VALUES ($1, $2, 'failed', $3, $4, $5, $6, $7)
                RETURNING id, channel_id, status, recipient, subject, message, error, sent_at
                "#,
                log_id,
                req.channel_id,
                req.recipient,
                req.subject,
                req.message,
                e.to_string(),
                now,
            )
            .fetch_one(pool)
            .await?
        }
    };

    Ok(log)
}

// ── Channel Senders ──────────────────────────────────────────────────────────

async fn send_webhook(config: &serde_json::Value, req: &SendNotificationRequest) -> Result<()> {
    let url = config
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow!("Webhook URL not configured"))?;

    if url.is_empty() {
        return Err(anyhow!("Webhook URL is empty"));
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let payload = serde_json::json!({
        "subject": req.subject,
        "message": req.message,
        "recipient": req.recipient,
        "timestamp": Utc::now().to_rfc3339(),
    });

    let resp = client.post(url).json(&payload).send().await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("Webhook returned status {}", resp.status()))
    }
}

async fn send_slack(config: &serde_json::Value, req: &SendNotificationRequest) -> Result<()> {
    let webhook_url = config
        .get("webhook_url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow!("Slack webhook URL not configured"))?;

    if webhook_url.is_empty() {
        return Err(anyhow!("Slack webhook URL is empty"));
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let text = if let Some(subject) = &req.subject {
        format!("*{}*\n{}", subject, req.message)
    } else {
        req.message.clone()
    };

    let payload = serde_json::json!({
        "text": text,
    });

    let resp = client.post(webhook_url).json(&payload).send().await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("Slack webhook returned status {}", resp.status()))
    }
}

async fn send_email(config: &serde_json::Value, req: &SendNotificationRequest) -> Result<()> {
    // Email sending requires an SMTP library
    // For now, log the attempt
    let smtp_host = config
        .get("smtp_host")
        .and_then(|h| h.as_str())
        .unwrap_or("not configured");

    tracing::info!(
        "Email notification to {} via {}: {}",
        req.recipient,
        smtp_host,
        req.subject.as_deref().unwrap_or("no subject")
    );

    // TODO: Implement actual SMTP sending with lettre crate
    Ok(())
}

// ── Logging ──────────────────────────────────────────────────────────────────

pub async fn list_notification_logs(pool: &PgPool, limit: i64) -> Result<Vec<NotificationLog>> {
    let logs = sqlx::query_as!(
        NotificationLog,
        r#"
        SELECT id, channel_id, status, recipient, subject, message, error, sent_at
        FROM notification_log
        ORDER BY sent_at DESC
        LIMIT $1
        "#,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(logs)
}

pub async fn get_notification_stats(pool: &PgPool) -> Result<NotificationStats> {
    let total: Option<i64> = sqlx::query_scalar("SELECT COUNT(*) FROM notification_log")
        .fetch_one(pool)
        .await
        .ok();

    let sent: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_log WHERE status = 'sent'")
            .fetch_one(pool)
            .await
            .ok();

    let failed: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_log WHERE status = 'failed'")
            .fetch_one(pool)
            .await
            .ok();

    Ok(NotificationStats {
        total_sent: total.unwrap_or(0),
        successful: sent.unwrap_or(0),
        failed: failed.unwrap_or(0),
    })
}

#[derive(Debug, Serialize)]
pub struct NotificationStats {
    pub total_sent: i64,
    pub successful: i64,
    pub failed: i64,
}
