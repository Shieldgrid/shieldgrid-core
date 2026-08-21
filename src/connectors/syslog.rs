#![allow(dead_code)]
//! Syslog receiver — ingests CEF/LEEF syslog from network devices.
//!
//! # Supported Formats
//!
//! - **CEF (Common Event Format)**: Fortinet, Palo Alto, Cisco ASA
//! - **LEEF (Log Event Extended Format)**: IBM QRadar-style
//! - **Plain syslog**: RFC 3164 / RFC 5424
//!
//! # Architecture
//!
//! ```text
//! Network Device (Fortinet/PaloAlto/Cisco)
//!        │ UDP/TCP syslog
//!        ▼
//! SyslogReceiver (listens on port 514/1514)
//!        │ parse CEF/LEEF
//!        ▼
//! DeviceParser (FortinetParser, PaloAltoParser, CiscoParser)
//!        │ normalize
//!        ▼
//! NormalizedAlert → PostgreSQL
//! ```

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::alert::{AlertStatus, NormalizedAlert, Severity};

/// Syslog message format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogFormat {
    Cef,
    Leef,
    Plain,
}

/// Parsed syslog message before normalization.
#[derive(Debug, Clone)]
pub struct ParsedSyslogMessage {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub source_name: String,
    pub facility: Option<u8>,
    pub severity: Option<u8>,
    pub raw_message: String,
    pub format: SyslogFormat,
}

/// Network device types we can parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDeviceType {
    Fortinet,
    PaloAlto,
    CiscoAsa,
    CiscoFtd,
    Generic,
}

impl NetworkDeviceType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "fortinet" | "fortigate" | "forti" => NetworkDeviceType::Fortinet,
            "paloalto" | "pan-os" | "panos" => NetworkDeviceType::PaloAlto,
            "cisco-asa" | "asa" => NetworkDeviceType::CiscoAsa,
            "cisco-ftd" | "ftd" => NetworkDeviceType::CiscoFtd,
            _ => NetworkDeviceType::Generic,
        }
    }
}

/// A network connector definition.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkConnector {
    pub id: Uuid,
    pub name: String,
    pub device_type: String,
    pub ip_address: String,
    pub syslog_port: u16,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── CEF Parser ──────────────────────────────────────────────────────────────

/// Parse a CEF (Common Event Format) syslog message.
///
/// CEF format: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`
pub fn parse_cef(message: &str) -> Result<ParsedSyslogMessage> {
    // Strip syslog header if present (e.g., "<134>Aug 21 2026 10:00:00 firewall1 CEF:...")
    let cef_start = message.find("CEF:").unwrap_or(0);
    let cef_body = &message[cef_start..];

    let parts: Vec<&str> = cef_body.splitn(8, '|').collect();
    if parts.len() < 8 {
        return Err(anyhow!(
            "Invalid CEF message: expected 8 pipe-separated fields"
        ));
    }

    let _version = parts[0].trim_start_matches("CEF:");
    let _vendor = parts[1];
    let _product = parts[2];
    let _device_version = parts[3];
    let _signature_id = parts[4];
    let name = parts[5];
    let severity_str = parts[6];
    let extension = parts[7];

    // Parse severity (CEF uses 0-10 scale)
    let sev_num: u8 = severity_str.parse().unwrap_or(5);
    let _severity = match sev_num {
        0..=3 => Severity::Low,
        4..=6 => Severity::Medium,
        7..=8 => Severity::High,
        _ => Severity::Critical,
    };

    // Parse extension fields (key=value pairs)
    let ext_fields = parse_cef_extension(extension);

    let source_ip = ext_fields
        .get("src")
        .or_else(|| ext_fields.get("dvc"))
        .map(|s| s.to_string())
        .unwrap_or_default();

    let timestamp = ext_fields
        .get("rt")
        .and_then(|t| parse_timestamp(t))
        .unwrap_or_else(Utc::now);

    Ok(ParsedSyslogMessage {
        timestamp,
        source_ip,
        source_name: name.to_string(),
        facility: None,
        severity: Some(sev_num),
        raw_message: message.to_string(),
        format: SyslogFormat::Cef,
    })
}

/// Parse CEF extension field (key=value pairs separated by spaces).
fn parse_cef_extension(extension: &str) -> std::collections::HashMap<String, String> {
    let mut fields = std::collections::HashMap::new();
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut in_value = false;

    for ch in extension.chars() {
        match ch {
            '=' if !in_value => {
                in_value = true;
                current_value.clear();
            }
            ' ' if in_value => {
                fields.insert(current_key.clone(), current_value.trim().to_string());
                current_key.clear();
                current_value.clear();
                in_value = false;
            }
            _ if in_value => current_value.push(ch),
            _ => current_key.push(ch),
        }
    }

    if in_value && !current_key.is_empty() {
        fields.insert(current_key, current_value.trim().to_string());
    }

    fields
}

// ── Fortinet Parser ──────────────────────────────────────────────────────────

/// Parse Fortinet FortiGate syslog messages.
///
/// FortiGate uses CEF with vendor="Fortinet" and product="FortiGate".
pub fn parse_fortinet(message: &str) -> Result<NormalizedAlert> {
    let parsed = parse_cef(message)?;
    let ext_fields = parse_cef_extension(&extract_extension(message));

    let action = ext_fields
        .get("act")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let dst_ip = ext_fields.get("dst").map(|s| s.to_string());
    let dst_port = ext_fields.get("dpt").and_then(|p| p.parse::<u16>().ok());
    let src_port = ext_fields.get("spt").and_then(|p| p.parse::<u16>().ok());
    let proto = ext_fields.get("proto").map(|s| s.to_string());
    let rule_id = ext_fields.get("flexString1").map(|s| s.to_string());

    let severity = match parsed.severity.unwrap_or(5) {
        0..=3 => Severity::Low,
        4..=6 => Severity::Medium,
        7..=8 => Severity::High,
        _ => Severity::Critical,
    };

    let raw_payload = serde_json::json!({
        "device_type": "fortinet",
        "source_ip": parsed.source_ip,
        "action": action,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "src_port": src_port,
        "protocol": proto,
        "rule_id": rule_id,
        "signature_id": ext_fields.get("signatureId").map(|s| s.to_string()),
        "raw_cef": parsed.raw_message,
    });

    Ok(NormalizedAlert {
        id: Uuid::new_v4(),
        source_id: Uuid::new_v4().to_string(),
        connector_id: "fortinet".to_string(),
        severity,
        source: parsed.source_name,
        timestamp: parsed.timestamp,
        raw_payload,
        status: AlertStatus::Open,
    })
}

// ── Palo Alto Parser ─────────────────────────────────────────────────────────

/// Parse Palo Alto PAN-OS syslog messages.
///
/// PAN-OS uses CEF with vendor="Palo Alto Networks" and product="PAN-OS".
pub fn parse_palo_alto(message: &str) -> Result<NormalizedAlert> {
    let parsed = parse_cef(message)?;
    let ext_fields = parse_cef_extension(&extract_extension(message));

    let action = ext_fields
        .get("act")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let dst_ip = ext_fields.get("dst").map(|s| s.to_string());
    let dst_port = ext_fields.get("dpt").and_then(|p| p.parse::<u16>().ok());
    let src_port = ext_fields.get("spt").and_then(|p| p.parse::<u16>().ok());
    let proto = ext_fields.get("proto").map(|s| s.to_string());
    let rule_name = ext_fields.get("cn1Label").map(|s| s.to_string());
    let threat_name = ext_fields.get("cs1").map(|s| s.to_string());
    let category = ext_fields.get("cat").map(|s| s.to_string());

    let severity = match parsed.severity.unwrap_or(5) {
        0..=3 => Severity::Low,
        4..=6 => Severity::Medium,
        7..=8 => Severity::High,
        _ => Severity::Critical,
    };

    let raw_payload = serde_json::json!({
        "device_type": "paloalto",
        "source_ip": parsed.source_ip,
        "action": action,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "src_port": src_port,
        "protocol": proto,
        "rule_name": rule_name,
        "threat_name": threat_name,
        "category": category,
        "raw_cef": parsed.raw_message,
    });

    Ok(NormalizedAlert {
        id: Uuid::new_v4(),
        source_id: Uuid::new_v4().to_string(),
        connector_id: "paloalto".to_string(),
        severity,
        source: parsed.source_name,
        timestamp: parsed.timestamp,
        raw_payload,
        status: AlertStatus::Open,
    })
}

// ── Cisco ASA Parser ─────────────────────────────────────────────────────────

/// Parse Cisco ASA syslog messages.
///
/// Cisco ASA uses format: `%ASA-LEVEL-MSGID: message`
pub fn parse_cisco_asa(message: &str) -> Result<NormalizedAlert> {
    // Cisco format: %ASA-4-106023: Deny tcp src outside:10.0.0.1/12345 dst inside:192.168.1.1/80 ...
    let parts: Vec<&str> = message.splitn(2, ": ").collect();
    let header = parts.first().unwrap_or(&"");
    let body = parts.get(1).unwrap_or(&"");

    // Parse header: %ASA-LEVEL-MSGID
    let header_parts: Vec<&str> = header.split('-').collect();
    let level_str = header_parts.get(1).unwrap_or(&"4");
    let msg_id = header_parts.get(2).unwrap_or(&"");

    let level: u8 = level_str.parse().unwrap_or(4);
    let severity = match level {
        0..=2 => Severity::Critical,
        3..=4 => Severity::High,
        5..=6 => Severity::Medium,
        _ => Severity::Low,
    };

    // Parse source/destination from body
    let src_ip = extract_ip_from_cisco(body, "src");
    let dst_ip = extract_ip_from_cisco(body, "dst");

    let raw_payload = serde_json::json!({
        "device_type": "cisco_asa",
        "msg_id": msg_id,
        "level": level,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "message": body,
        "raw_syslog": message,
    });

    Ok(NormalizedAlert {
        id: Uuid::new_v4(),
        source_id: Uuid::new_v4().to_string(),
        connector_id: "cisco_asa".to_string(),
        severity,
        source: "cisco-asa".to_string(),
        timestamp: Utc::now(),
        raw_payload,
        status: AlertStatus::Open,
    })
}

/// Extract IP address from Cisco ASA message body.
fn extract_ip_from_cisco(body: &str, keyword: &str) -> Option<String> {
    let parts: Vec<&str> = body.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == keyword {
            // Format: src outside:10.0.0.1/12345
            if let Some(addr_port) = parts.get(i + 1) {
                if let Some(ip) = addr_port.split(':').next_back() {
                    if let Some(ip_only) = ip.split('/').next() {
                        return Some(ip_only.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract CEF extension from message (after the 7th pipe).
#[allow(dead_code)]
fn extract_extension(message: &str) -> String {
    let cef_start = message.find("CEF:").unwrap_or(0);
    let cef_body = &message[cef_start..];
    let parts: Vec<&str> = cef_body.splitn(8, '|').collect();
    if parts.len() >= 8 {
        parts[7].to_string()
    } else {
        String::new()
    }
}

/// Parse a timestamp string.
#[allow(dead_code)]
fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try common formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%b %d %Y %H:%M:%S",
    ];

    for format in &formats {
        if let Ok(dt) = DateTime::parse_from_str(s, format) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    // Try chrono::DateTime::parse_from_rfc3339 as fallback
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cef_extension() {
        let ext = "src=10.0.0.1 dst=192.168.1.1 dpt=80 act=allow";
        let fields = parse_cef_extension(ext);
        assert_eq!(fields.get("src").unwrap(), "10.0.0.1");
        assert_eq!(fields.get("dst").unwrap(), "192.168.1.1");
        assert_eq!(fields.get("dpt").unwrap(), "80");
        assert_eq!(fields.get("act").unwrap(), "allow");
    }

    #[test]
    fn test_parse_cef() {
        let msg = "CEF:0|Fortinet|FortiGate|6.2|106001|Firewall Deny|4|src=10.0.0.1 dst=192.168.1.1 dpt=80 act=deny";
        let parsed = parse_cef(msg).unwrap();
        assert_eq!(parsed.source_ip, "10.0.0.1");
        assert_eq!(parsed.source_name, "Firewall Deny");
    }

    #[test]
    fn test_cisco_extract_ip() {
        let body = "Deny tcp src outside:10.0.0.1/12345 dst inside:192.168.1.1/80";
        assert_eq!(extract_ip_from_cisco(body, "src").unwrap(), "10.0.0.1");
        assert_eq!(extract_ip_from_cisco(body, "dst").unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_network_device_type() {
        assert_eq!(
            NetworkDeviceType::from_str("fortinet"),
            NetworkDeviceType::Fortinet
        );
        assert_eq!(
            NetworkDeviceType::from_str("fortigate"),
            NetworkDeviceType::Fortinet
        );
        assert_eq!(
            NetworkDeviceType::from_str("paloalto"),
            NetworkDeviceType::PaloAlto
        );
        assert_eq!(
            NetworkDeviceType::from_str("pan-os"),
            NetworkDeviceType::PaloAlto
        );
        assert_eq!(
            NetworkDeviceType::from_str("cisco-asa"),
            NetworkDeviceType::CiscoAsa
        );
    }
}
