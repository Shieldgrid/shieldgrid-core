//! Threat intelligence service implementation.
//!
//! Handles IOC reputation lookups (VirusTotal, EPSS, threat feeds) with PostgreSQL caching.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use reqwest::Client;
use serde_json::Value;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::config::Config;
use crate::models::threat_intel::{EnrichIocsResponse, IocType, ThreatIntelResult, ThreatVerdict};

/// Fetch EPSS score from FIRST.org with local PostgreSQL caching.
pub async fn lookup_epss(cve: &str, pool: &PgPool) -> Result<ThreatIntelResult> {
    let normalized_cve = cve.trim().to_uppercase();

    // 1. Check cache first
    let cached = sqlx::query!(
        r#"
        SELECT id, ioc_type, ioc_value, provider, verdict, score, raw_data, expires_at, created_at
        FROM threat_intel_cache
        WHERE ioc_type = 'cve' AND ioc_value = $1 AND provider = 'epss' AND expires_at > NOW()
        "#,
        normalized_cve
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = cached {
        return Ok(ThreatIntelResult {
            id: Some(row.id),
            ioc_type: IocType::Cve,
            ioc_value: row.ioc_value,
            provider: row.provider,
            verdict: ThreatVerdict::from_str(&row.verdict),
            score: row.score,
            details: row.raw_data,
            cached: true,
            checked_at: row.created_at,
        });
    }

    // 2. Fetch live from FIRST.org API
    let url = format!("https://api.first.org/data/v1/epss?cve={normalized_cve}");
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("EPSS API returned status {}", resp.status()));
    }

    let json: Value = resp.json().await?;
    let data_array = json.get("data").and_then(|d| d.as_array());

    let (score, verdict, raw_data) = if let Some(items) = data_array {
        if let Some(first_item) = items.first() {
            let epss_val: f64 = first_item
                .get("epss")
                .and_then(|e| e.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);

            let verdict = if epss_val >= 0.5 {
                ThreatVerdict::Malicious
            } else if epss_val >= 0.15 {
                ThreatVerdict::Suspicious
            } else {
                ThreatVerdict::Benign
            };

            (Some(epss_val), verdict, first_item.clone())
        } else {
            (None, ThreatVerdict::Unknown, json.clone())
        }
    } else {
        (None, ThreatVerdict::Unknown, json.clone())
    };

    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::days(7); // Cache EPSS for 7 days
    let verdict_str = verdict.as_str();

    // 3. Upsert into database cache
    sqlx::query!(
        r#"
        INSERT INTO threat_intel_cache (id, ioc_type, ioc_value, provider, verdict, score, raw_data, expires_at, created_at, updated_at)
        VALUES ($1, 'cve', $2, 'epss', $3, $4, $5, $6, NOW(), NOW())
        ON CONFLICT (ioc_type, ioc_value, provider) DO UPDATE SET
            verdict = EXCLUDED.verdict,
            score = EXCLUDED.score,
            raw_data = EXCLUDED.raw_data,
            expires_at = EXCLUDED.expires_at,
            updated_at = NOW()
        "#,
        id,
        normalized_cve,
        verdict_str,
        score,
        raw_data,
        expires_at
    )
    .execute(pool)
    .await?;

    Ok(ThreatIntelResult {
        id: Some(id),
        ioc_type: IocType::Cve,
        ioc_value: normalized_cve,
        provider: "epss".to_string(),
        verdict,
        score,
        details: raw_data,
        cached: false,
        checked_at: Utc::now(),
    })
}

/// Fetch VirusTotal threat intelligence for an IP, Domain, Hash, or URL.
pub async fn lookup_virustotal(
    ioc: &str,
    ioc_type: &IocType,
    api_key: &str,
    pool: &PgPool,
) -> Result<ThreatIntelResult> {
    let normalized_ioc = ioc.trim().to_string();
    let ioc_type_str = ioc_type.as_str();

    // 1. Check cache
    let cached = sqlx::query!(
        r#"
        SELECT id, ioc_type, ioc_value, provider, verdict, score, raw_data, expires_at, created_at
        FROM threat_intel_cache
        WHERE ioc_type = $1 AND ioc_value = $2 AND provider = 'virustotal' AND expires_at > NOW()
        "#,
        ioc_type_str,
        normalized_ioc
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = cached {
        return Ok(ThreatIntelResult {
            id: Some(row.id),
            ioc_type: ioc_type.clone(),
            ioc_value: row.ioc_value,
            provider: row.provider,
            verdict: ThreatVerdict::from_str(&row.verdict),
            score: row.score,
            details: row.raw_data,
            cached: true,
            checked_at: row.created_at,
        });
    }

    // 2. Build VirusTotal v3 endpoint URL
    let url = match ioc_type {
        IocType::Ip => format!("https://www.virustotal.com/api/v3/ip_addresses/{normalized_ioc}"),
        IocType::Domain => format!("https://www.virustotal.com/api/v3/domains/{normalized_ioc}"),
        IocType::Hash => format!("https://www.virustotal.com/api/v3/files/{normalized_ioc}"),
        IocType::Url => {
            // URL identifier in VT v3 is base64 without padding
            let encoded = base64_url_encode(normalized_ioc.as_bytes());
            format!("https://www.virustotal.com/api/v3/urls/{encoded}")
        }
        IocType::Cve => return lookup_epss(&normalized_ioc, pool).await,
    };

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .header("accept", "application/json")
        .send()
        .await?;

    if resp.status().as_u16() == 404 {
        // Not found in VirusTotal
        let details = serde_json::json!({ "message": "Item not found in VirusTotal database" });
        return Ok(ThreatIntelResult {
            id: None,
            ioc_type: ioc_type.clone(),
            ioc_value: normalized_ioc,
            provider: "virustotal".to_string(),
            verdict: ThreatVerdict::Unknown,
            score: Some(0.0),
            details,
            cached: false,
            checked_at: Utc::now(),
        });
    }

    if !resp.status().is_success() {
        return Err(anyhow!("VirusTotal API error: {}", resp.status()));
    }

    let json: Value = resp.json().await?;
    let attributes = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .cloned()
        .unwrap_or(Value::Null);

    let stats = attributes.get("last_analysis_stats");
    let malicious = stats
        .and_then(|s| s.get("malicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let suspicious = stats
        .and_then(|s| s.get("suspicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let harmless = stats
        .and_then(|s| s.get("harmless"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let undetected = stats
        .and_then(|s| s.get("undetected"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let total = malicious + suspicious + harmless + undetected;
    let score = if total > 0 {
        Some((malicious as f64) / (total as f64))
    } else {
        None
    };

    let verdict = if malicious >= 3 {
        ThreatVerdict::Malicious
    } else if malicious >= 1 || suspicious >= 2 {
        ThreatVerdict::Suspicious
    } else if harmless > 0 || undetected > 0 {
        ThreatVerdict::Benign
    } else {
        ThreatVerdict::Unknown
    };

    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(24); // Cache VT for 24 hours
    let verdict_str = verdict.as_str();

    sqlx::query!(
        r#"
        INSERT INTO threat_intel_cache (id, ioc_type, ioc_value, provider, verdict, score, raw_data, expires_at, created_at, updated_at)
        VALUES ($1, $2, $3, 'virustotal', $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (ioc_type, ioc_value, provider) DO UPDATE SET
            verdict = EXCLUDED.verdict,
            score = EXCLUDED.score,
            raw_data = EXCLUDED.raw_data,
            expires_at = EXCLUDED.expires_at,
            updated_at = NOW()
        "#,
        id,
        ioc_type_str,
        normalized_ioc,
        verdict_str,
        score,
        attributes,
        expires_at
    )
    .execute(pool)
    .await?;

    Ok(ThreatIntelResult {
        id: Some(id),
        ioc_type: ioc_type.clone(),
        ioc_value: normalized_ioc,
        provider: "virustotal".to_string(),
        verdict,
        score,
        details: attributes,
        cached: false,
        checked_at: Utc::now(),
    })
}

/// Base64 URL safe encoding without padding for VirusTotal URL queries.
fn base64_url_encode(data: &[u8]) -> String {
    const CUSTOM_ENGINE: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CUSTOM_ENGINE[(n >> 18) & 63] as char);
        result.push(CUSTOM_ENGINE[(n >> 12) & 63] as char);
        if i + 1 < data.len() {
            result.push(CUSTOM_ENGINE[(n >> 6) & 63] as char);
        }
        if i + 2 < data.len() {
            result.push(CUSTOM_ENGINE[n & 63] as char);
        }
        i += 3;
    }
    result
}

/// Universal IOC enrichment endpoint routing to EPSS or VirusTotal based on IOC type.
pub async fn enrich_ioc(ioc: &str, config: &Config, pool: &PgPool) -> Result<ThreatIntelResult> {
    let inferred_type = IocType::infer(ioc);
    match inferred_type {
        IocType::Cve => lookup_epss(ioc, pool).await,
        _ => {
            if let Some(vt_key) = &config.virustotal_api_key {
                lookup_virustotal(ioc, &inferred_type, vt_key, pool).await
            } else {
                // Fallback if no VirusTotal API key configured: return unknown / pending
                Ok(ThreatIntelResult {
                    id: None,
                    ioc_type: inferred_type,
                    ioc_value: ioc.trim().to_string(),
                    provider: "shieldgrid-local".to_string(),
                    verdict: ThreatVerdict::Unknown,
                    score: None,
                    details: serde_json::json!({
                        "message": "VirusTotal API key not configured in VIRUSTOTAL_API_KEY"
                    }),
                    cached: false,
                    checked_at: Utc::now(),
                })
            }
        }
    }
}

/// Batch IOC enrichment helper.
pub async fn enrich_batch(iocs: &[String], config: &Config, pool: &PgPool) -> EnrichIocsResponse {
    let mut results = Vec::new();
    for ioc in iocs {
        if ioc.trim().is_empty() {
            continue;
        }
        match enrich_ioc(ioc, config, pool).await {
            Ok(res) => results.push(res),
            Err(e) => {
                warn!("Enrichment error for IOC '{ioc}': {e}");
                results.push(ThreatIntelResult {
                    id: None,
                    ioc_type: IocType::infer(ioc),
                    ioc_value: ioc.clone(),
                    provider: "error".to_string(),
                    verdict: ThreatVerdict::Unknown,
                    score: None,
                    details: serde_json::json!({ "error": e.to_string() }),
                    cached: false,
                    checked_at: Utc::now(),
                });
            }
        }
    }
    let count = results.len();
    EnrichIocsResponse { count, results }
}
