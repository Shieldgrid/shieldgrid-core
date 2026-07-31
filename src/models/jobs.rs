use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A row from the `jobs` table — the ingest scheduler registry.
///
/// One row per connector, seeded at startup. The background ingest loop reads
/// due jobs, executes a connector fetch, and records the outcome here so
/// ingestion status is observable via `GET /api/v1/jobs`.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Job {
    pub id: Uuid,
    pub connector_id: String,
    pub name: String,
    pub interval_minutes: i32,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_watermark: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
