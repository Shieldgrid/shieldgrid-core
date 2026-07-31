//! Background ingest scheduler.
//!
//! One `jobs` row per connector is seeded at startup. A tokio loop wakes every
//! few seconds and runs any enabled job whose `next_run_at` has passed: it
//! fetches alerts from the connector since the job's watermark (or the last
//! hour on first run), upserts them into `alerts`, and advances the watermark
//! to the newest ingested timestamp. Connector failures are recorded on the
//! job row (`last_status = 'error'`) and never crash the loop.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::connectors::Connector;
use crate::services::alerts::upsert_alerts;

/// Default interval between scheduled runs of a job.
const DEFAULT_INTERVAL_MINUTES: i64 = 1;

/// How wide the initial fetch window is for a job with no watermark yet.
///
/// Matches the historical default of the alerts API ("since 24 h ago") so the
/// first ingest populates the queue with a meaningful backlog instead of just
/// the last hour.
const INITIAL_WINDOW_HOURS: i64 = 24;

/// How often the scheduler checks the `jobs` table for due work.
const SCHEDULER_TICK_SECONDS: u64 = 15;

/// A due job loaded from the `jobs` table by [`run_due_jobs`].
#[derive(sqlx::FromRow)]
struct DueJob {
    id: uuid::Uuid,
    connector_id: String,
    interval_minutes: i32,
    last_watermark: Option<DateTime<Utc>>,
}

/// Seed one job row per registered connector.
///
/// Idempotent — rows are keyed on `connector_id` and existing rows (including
/// their schedule and watermark) are left untouched across restarts.
pub async fn seed_jobs(db: &PgPool, connectors: &[Arc<dyn Connector>]) -> Result<usize> {
    let mut seeded = 0;
    for connector in connectors {
        sqlx::query!(
            "INSERT INTO jobs (id, connector_id, name, interval_minutes)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (connector_id) DO NOTHING",
            uuid::Uuid::new_v4(),
            connector.id(),
            connector.id(),
            DEFAULT_INTERVAL_MINUTES as i32,
        )
        .execute(db)
        .await
        .context("failed to seed ingest job")?;
        seeded += 1;
    }
    Ok(seeded)
}

/// Run the ingest scheduler forever.
///
/// Spawned as a background tokio task from `main`. The first tick fires
/// immediately, so jobs with `next_run_at IS NULL` run right after startup.
pub async fn run_ingest_loop(db: PgPool, connectors: Vec<Arc<dyn Connector>>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(SCHEDULER_TICK_SECONDS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        if let Err(e) = run_due_jobs(&db, &connectors).await {
            error!(error = %e, "ingest cycle failed");
        }
    }
}

/// Execute every due job in a single pass.
async fn run_due_jobs(db: &PgPool, connectors: &[Arc<dyn Connector>]) -> Result<()> {
    let due = sqlx::query_as!(
        DueJob,
        "SELECT id, connector_id, interval_minutes, last_watermark
         FROM jobs
         WHERE enabled = TRUE
           AND (next_run_at IS NULL OR next_run_at <= NOW())"
    )
    .fetch_all(db)
    .await
    .context("failed to query due jobs")?;

    for job in due {
        if let Err(e) = run_job(db, connectors, &job).await {
            warn!(connector = job.connector_id, error = %e, "ingest job failed");
            record_job_error(db, &job, &e).await;
        }
    }

    Ok(())
}

/// Execute a single job: fetch → upsert → advance watermark.
async fn run_job(db: &PgPool, connectors: &[Arc<dyn Connector>], job: &DueJob) -> Result<()> {
    let connector = connectors
        .iter()
        .find(|c| c.id() == job.connector_id)
        .with_context(|| format!("no connector registered for id '{}'", job.connector_id))?;

    let since = job
        .last_watermark
        .unwrap_or_else(|| Utc::now() - Duration::hours(INITIAL_WINDOW_HOURS));

    let alerts = connector
        .fetch_alerts(since)
        .await
        .with_context(|| format!("fetch_alerts failed for '{}'", job.connector_id))?;

    let count = upsert_alerts(db, &alerts).await?;

    // Advance the watermark to the newest alert timestamp in this batch. On an
    // empty batch the watermark is left where it was (next run re-scans the
    // same window — harmless and idempotent).
    let new_watermark = alerts.iter().map(|a| a.timestamp).max();

    let next_run = Utc::now() + Duration::minutes(job.interval_minutes.max(1) as i64);

    sqlx::query!(
        "UPDATE jobs SET
            last_run_at = NOW(),
            last_status = 'success',
            last_error = NULL,
            last_watermark = COALESCE($2, last_watermark),
            next_run_at = $3,
            updated_at = NOW()
         WHERE id = $1",
        job.id,
        new_watermark,
        next_run,
    )
    .execute(db)
    .await
    .context("failed to update job row after success")?;

    if count > 0 {
        info!(connector = job.connector_id, count, "ingested alerts");
    }

    Ok(())
}

/// Record a failed ingest attempt on the job row. The watermark is left
/// untouched so the next run retries from the same position.
async fn record_job_error(db: &PgPool, job: &DueJob, err: &anyhow::Error) {
    let next_run = Utc::now() + Duration::minutes(job.interval_minutes.max(1) as i64);

    let result = sqlx::query!(
        "UPDATE jobs SET
            last_run_at = NOW(),
            last_status = 'error',
            last_error = $2,
            next_run_at = $3,
            updated_at = NOW()
         WHERE id = $1",
        job.id,
        err.to_string(),
        next_run,
    )
    .execute(db)
    .await;

    if let Err(e) = result {
        error!(connector = job.connector_id, error = %e, "failed to record ingest job error");
    }
}
