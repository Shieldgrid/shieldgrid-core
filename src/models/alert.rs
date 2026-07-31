//! `NormalizedAlert` — the canonical alert representation used throughout
//! Shieldgrid Core.
//!
//! Every connector maps its native alert format into this struct, so the rest
//! of the platform (API routes, case management, frontend) never needs to know
//! anything about the source tool's data shape.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Severity ─────────────────────────────────────────────────────────────────

/// Normalised severity level for an alert.
///
/// Connectors map their native severity scale (e.g. Wazuh rule levels 1–15)
/// into one of these five buckets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — no immediate action required.
    Info,
    /// Low severity — worth noting but unlikely to require urgent response.
    Low,
    /// Medium severity — investigate in a timely manner.
    Medium,
    /// High severity — investigate promptly; likely a real incident.
    High,
    /// Critical severity — immediate response required.
    Critical,
}

impl Severity {
    /// Stable lowercase string form, matching `serde(rename_all = "lowercase")`
    /// and the values stored in the `alerts.severity` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a lowercase severity string back into a [`Severity`].
    pub fn from_str(s: &str) -> Option<Severity> {
        match s {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

// ── AlertStatus ──────────────────────────────────────────────────────────────

/// Lifecycle state of a normalised alert within Shieldgrid.
///
/// Transitions (Open → Acknowledged → Closed) will be driven by the case
/// management layer introduced in Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    /// Newly ingested; no analyst has acted on it yet.
    Open,
    /// An analyst has acknowledged the alert and is investigating.
    Acknowledged,
    /// Investigation complete; alert is resolved or dismissed.
    Closed,
}

impl AlertStatus {
    /// Stable lowercase string form, matching `serde(rename_all = "lowercase")`
    /// and the values stored in the `alerts.status` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertStatus::Open => "open",
            AlertStatus::Acknowledged => "acknowledged",
            AlertStatus::Closed => "closed",
        }
    }

    /// Parse a lowercase status string back into an [`AlertStatus`].
    pub fn from_str(s: &str) -> Option<AlertStatus> {
        match s {
            "open" => Some(AlertStatus::Open),
            "acknowledged" => Some(AlertStatus::Acknowledged),
            "closed" => Some(AlertStatus::Closed),
            _ => None,
        }
    }
}

/// Request body for `PATCH /api/v1/alerts/{id}` — set the lifecycle state of a
/// persisted alert.
#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    /// The status to move the alert to (`open`, `acknowledged`, or `closed`).
    pub status: AlertStatus,
}

// ── NormalizedAlert ───────────────────────────────────────────────────────────

/// A connector-agnostic alert, produced by mapping each source tool's native
/// format into this common schema.
///
/// # Field documentation
///
/// | Field | Description |
/// |---|---|
/// | `id` | Shieldgrid UUID, assigned at ingestion time. The identity used by case links and the API. |
/// | `source_id` | Stable identifier from the upstream tool (OpenSearch `_id` for Wazuh, the source UUID for Velociraptor). Used as the dedupe key when persisting. |
/// | `connector_id` | ID of the connector that produced this alert (e.g. `"wazuh"`). |
/// | `severity` | Normalised severity bucket. |
/// | `source` | Human-readable origin within the connector (e.g. agent hostname). |
/// | `timestamp` | Original event timestamp from the source tool, in UTC. |
/// | `raw_payload` | Complete raw alert JSON from the source, preserved for audit. |
/// | `status` | Current lifecycle state of the alert within Shieldgrid. |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedAlert {
    /// Shieldgrid UUID, assigned at ingestion time.
    pub id: Uuid,

    /// Stable identifier from the upstream tool, used as the dedupe key.
    pub source_id: String,

    /// ID of the connector that produced this alert (e.g. `"wazuh"`).
    pub connector_id: String,

    /// Normalised severity bucket.
    pub severity: Severity,

    /// Human-readable origin within the connector (e.g. agent hostname,
    /// IP address, or device name).
    pub source: String,

    /// Original event timestamp from the source tool, in UTC.
    pub timestamp: DateTime<Utc>,

    /// Complete raw alert JSON from the source, preserved for audit and
    /// future re-parsing without data loss.
    pub raw_payload: serde_json::Value,

    /// Current lifecycle state of the alert within Shieldgrid.
    pub status: AlertStatus,
}

// ── StoredAlert ────────────────────────────────────────────────────────────────

/// A row from the `alerts` table, before mapping back into a
/// [`NormalizedAlert`].
///
/// `severity` and `status` are stored as lowercase text and converted to their
/// enum forms via [`StoredAlert::into_normalized`].
#[derive(Debug, sqlx::FromRow)]
pub struct StoredAlert {
    pub id: Uuid,
    pub connector_id: String,
    pub source_id: String,
    pub severity: String,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub raw_payload: serde_json::Value,
    pub status: String,
}

impl StoredAlert {
    /// Convert a stored row back into a [`NormalizedAlert`].
    ///
    /// Returns `None` if the stored `severity`/`status` strings are not valid
    /// enum values (defensive — the DB is written by this codebase, but a
    /// manually edited row should not crash a request).
    pub fn into_normalized(self) -> Option<NormalizedAlert> {
        Some(NormalizedAlert {
            id: self.id,
            source_id: self.source_id,
            connector_id: self.connector_id,
            severity: Severity::from_str(&self.severity)?,
            source: self.source,
            timestamp: self.timestamp,
            raw_payload: self.raw_payload,
            status: AlertStatus::from_str(&self.status)?,
        })
    }
}
