//! Alert persistence — the durable store behind the alert API.
//!
//! Connectors produce [`NormalizedAlert`] values (with a fresh `id` each
//! fetch); the platform persists them keyed on the stable `(connector_id,
//! source_id)` pair so re-fetching the same upstream event upserts rather than
//! duplicates.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::alert::{AlertStatus, NormalizedAlert, Severity, StoredAlert};

/// Insert or update a batch of alerts.
///
/// Idempotent per `(connector_id, source_id)` — a row that already exists has
/// its mutable fields refreshed (`severity`, `source`, `timestamp`,
/// `raw_payload`, `updated_at`) while its `id`, `status`, and `created_at`
/// are left untouched.
///
/// Returns the number of rows upserted (i.e. the batch size).
pub async fn upsert_alerts(db: &PgPool, alerts: &[NormalizedAlert]) -> Result<usize> {
    for alert in alerts {
        sqlx::query!(
            "INSERT INTO alerts (id, connector_id, source_id, severity, source, timestamp, raw_payload, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
             ON CONFLICT (connector_id, source_id) DO UPDATE SET
                 severity = EXCLUDED.severity,
                 source = EXCLUDED.source,
                 timestamp = EXCLUDED.timestamp,
                 raw_payload = EXCLUDED.raw_payload,
                 updated_at = NOW()",
            alert.id,
            alert.connector_id,
            alert.source_id,
            alert.severity.as_str(),
            alert.source,
            alert.timestamp,
            alert.raw_payload,
            alert.status.as_str(),
        )
        .execute(db)
        .await?;
    }

    Ok(alerts.len())
}

/// Filters for `list_alerts`. Every field is optional; `None` means "no
/// constraint".
#[derive(Debug, Default)]
pub struct ListAlertFilters {
    /// Only alerts strictly newer than this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Only alerts from this connector.
    pub connector_id: Option<String>,
    /// Only alerts with this severity (`info`–`critical`).
    pub severity: Option<Severity>,
    /// Only alerts in this lifecycle state (`open`, `acknowledged`, `closed`).
    pub status: Option<AlertStatus>,
    /// Maximum number of rows (default 200, callers cap at 1000).
    pub limit: Option<i64>,
    /// Rows to skip for pagination.
    pub offset: Option<i64>,
}

/// List persisted alerts, newest first.
pub async fn list_alerts(db: &PgPool, filters: &ListAlertFilters) -> Result<Vec<NormalizedAlert>> {
    let limit = filters.limit.unwrap_or(200);
    let offset = filters.offset.unwrap_or(0);

    let rows = sqlx::query_as!(
        StoredAlert,
        "SELECT id, connector_id, source_id, severity, source, timestamp, raw_payload, status
         FROM alerts
         WHERE ($1::timestamptz IS NULL OR timestamp > $1)
           AND ($2::text IS NULL OR connector_id = $2)
           AND ($3::text IS NULL OR severity = $3)
           AND ($4::text IS NULL OR status = $4)
         ORDER BY timestamp DESC
         LIMIT $5 OFFSET $6",
        filters.since,
        filters.connector_id,
        filters.severity.as_ref().map(|s| s.as_str()),
        filters.status.as_ref().map(|s| s.as_str()),
        limit,
        offset,
    )
    .fetch_all(db)
    .await?;

    let mut alerts = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(alert) = row.into_normalized() {
            alerts.push(alert);
        }
    }
    Ok(alerts)
}

/// Set the lifecycle status of a persisted alert.
///
/// Returns the updated alert, or `None` if no alert with that id exists.
pub async fn update_alert_status(
    db: &PgPool,
    id: Uuid,
    status: AlertStatus,
) -> Result<Option<NormalizedAlert>> {
    let row = sqlx::query_as!(
        StoredAlert,
        "UPDATE alerts
         SET status = $2, updated_at = NOW()
         WHERE id = $1
         RETURNING id, connector_id, source_id, severity, source, timestamp, raw_payload, status",
        id,
        status.as_str(),
    )
    .fetch_optional(db)
    .await?;

    Ok(row.and_then(StoredAlert::into_normalized))
}
