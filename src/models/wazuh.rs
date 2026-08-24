//! `WazuhAgent` / `WazuhAgentsSummary` — public DTOs for the Wazuh agents
//! feature, produced by the Wazuh connector from the manager REST API.
//!
//! These are deliberately flat, serializable shapes (no nested Wazuh API
//! structure leaks into the frontend contract). The raw Wazuh API wire
//! structs live privately in `src/connectors/wazuh.rs`.

use serde::{Deserialize, Serialize};

/// A single agent registered with the Wazuh manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhAgent {
    /// Wazuh agent id (e.g. `"004"`).
    pub id: String,
    /// Agent hostname as reported to the manager.
    pub name: String,
    /// Reported IP address.
    #[serde(default)]
    pub ip: Option<String>,
    /// Connection status: `active`, `disconnected`, `never_connected`, `pending`.
    #[serde(default)]
    pub status: Option<String>,
    /// Operating system name (e.g. `"Ubuntu"`, `"Amazon Linux"`).
    #[serde(default)]
    pub os_name: Option<String>,
    /// Operating system version (e.g. `"24.04.4 LTS"`).
    #[serde(default)]
    pub os_version: Option<String>,
    /// Operating system platform (e.g. `"ubuntu"`, `"amzn"`).
    #[serde(default)]
    pub os_platform: Option<String>,
    /// Operating system uname (e.g. `"Linux |Mx9 |6.8.0-136-generic |#136-Ubuntu SMP PREEMPT_DYNAMIC... |x86_64"`).
    #[serde(default)]
    pub os_uname: Option<String>,
    /// Wazuh agent version (e.g. `"Wazuh v4.14.5"`).
    #[serde(default)]
    pub version: Option<String>,
    /// Last keep-alive timestamp as reported by the manager (raw RFC3339).
    #[serde(default)]
    pub last_seen: Option<String>,
    /// Assigned agent groups.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Aggregate connection-status counts across all registered agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhAgentsSummary {
    /// Agents currently reporting to the manager.
    pub active: u64,
    /// Agents previously connected but currently silent.
    pub disconnected: u64,
    /// Agents registered but never connected.
    pub never_connected: u64,
    /// Agents awaiting first connection.
    pub pending: u64,
    /// Sum of all status buckets.
    pub total: u64,
}
