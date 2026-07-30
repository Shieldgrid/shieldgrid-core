//! Connector abstraction — the core interface every integration implements.
//!
//! Adding support for a new security tool means writing one new type that
//! implements [`Connector`].  The rest of the platform (API routes, case
//! management, frontend) never needs tool-specific logic.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::models::action::{ActionResult, ResponseAction};
use crate::models::alert::NormalizedAlert;

pub mod velociraptor;
pub mod wazuh;

// ── HealthStatus ─────────────────────────────────────────────────────────────

/// The operational health of a connector at query time.
///
/// Returned by [`Connector::health_check`] and surfaced in the `/health`
/// endpoint response.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HealthStatus {
    /// The connector can reach its upstream data source without errors.
    Healthy,

    /// The connector is reachable but operating in a degraded state
    /// (e.g. elevated latency, partial index availability).
    #[allow(dead_code)]
    Degraded {
        /// Human-readable explanation of the degraded condition.
        reason: String,
    },

    /// The connector cannot reach its upstream data source.
    Down {
        /// Human-readable explanation of why the connector is down.
        reason: String,
    },
}

// ── Connector trait ───────────────────────────────────────────────────────────

/// The common interface every security-tool integration must implement.
///
/// # Contract
///
/// - Implementations **must** be `Send + Sync` so they can be held in shared
///   state across Axum request handlers.
/// - `fetch_alerts` returns alerts *newer than* `since` (exclusive lower
///   bound), sorted however is natural for the upstream source.
/// - `health_check` must **never panic** — if the upstream is unreachable it
///   returns [`HealthStatus::Down`], not an error.
#[async_trait]
pub trait Connector: Send + Sync {
    /// A short, stable identifier for this connector (e.g. `"wazuh"`).
    ///
    /// Used as the `connector_id` field in every [`NormalizedAlert`] this
    /// connector produces, and as the key in `/health` responses.
    fn id(&self) -> &str;

    /// Query the upstream source for its operational health.
    ///
    /// Always returns a [`HealthStatus`] — never returns an error.  If the
    /// source is unreachable, return [`HealthStatus::Down`] with a reason.
    async fn health_check(&self) -> HealthStatus;

    /// Fetch all alerts newer than `since` from the upstream source and map
    /// them into [`NormalizedAlert`] objects.
    ///
    /// `since` is an exclusive lower bound on the alert's original timestamp.
    /// Implementations should cap the result set at a reasonable maximum
    /// (e.g. 500) and document any such limit.
    async fn fetch_alerts(&self, since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>>;

    /// Push an action (like isolation or unisolation) to an endpoint via this connector.
    ///
    /// Implementations that do not support actions should return a clear "not supported" error.
    async fn push_action(&self, action: ResponseAction) -> Result<ActionResult>;
}
