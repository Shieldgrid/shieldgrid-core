//! Threat intelligence models and data structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported IOC (Indicator of Compromise) types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Ip,
    Domain,
    Hash,
    Cve,
    Url,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::Ip => "ip",
            IocType::Domain => "domain",
            IocType::Hash => "hash",
            IocType::Cve => "cve",
            IocType::Url => "url",
        }
    }

    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ip" | "ipv4" | "ipv6" => Some(IocType::Ip),
            "domain" | "fqdn" | "hostname" => Some(IocType::Domain),
            "hash" | "md5" | "sha1" | "sha256" => Some(IocType::Hash),
            "cve" => Some(IocType::Cve),
            "url" | "uri" => Some(IocType::Url),
            _ => None,
        }
    }

    /// Automatically infer IOC type from a raw string.
    pub fn infer(ioc: &str) -> Self {
        let trimmed = ioc.trim();
        if trimmed.to_uppercase().starts_with("CVE-") {
            return IocType::Cve;
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return IocType::Url;
        }
        // Check if IP
        if trimmed.parse::<std::net::IpAddr>().is_ok() {
            return IocType::Ip;
        }
        // Check if MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
        let is_hex = trimmed.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex && (trimmed.len() == 32 || trimmed.len() == 40 || trimmed.len() == 64) {
            return IocType::Hash;
        }
        // Default to domain
        IocType::Domain
    }
}

/// Normalized threat verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatVerdict {
    Benign,
    Suspicious,
    Malicious,
    Unknown,
}

impl ThreatVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatVerdict::Benign => "benign",
            ThreatVerdict::Suspicious => "suspicious",
            ThreatVerdict::Malicious => "malicious",
            ThreatVerdict::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "benign" => ThreatVerdict::Benign,
            "suspicious" => ThreatVerdict::Suspicious,
            "malicious" => ThreatVerdict::Malicious,
            _ => ThreatVerdict::Unknown,
        }
    }
}

/// Result of an IOC threat intelligence lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    pub id: Option<Uuid>,
    pub ioc_type: IocType,
    pub ioc_value: String,
    pub provider: String,
    pub verdict: ThreatVerdict,
    pub score: Option<f64>,
    pub details: serde_json::Value,
    pub cached: bool,
    pub checked_at: DateTime<Utc>,
}

/// EPSS score item from FIRST.org.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssItem {
    pub cve: String,
    pub epss: String,
    pub percentile: String,
    pub date: Option<String>,
}

/// Request for batch IOC enrichment.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrichIocsRequest {
    pub iocs: Vec<String>,
}

/// Response for IOC enrichment.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichIocsResponse {
    pub count: usize,
    pub results: Vec<ThreatIntelResult>,
}
