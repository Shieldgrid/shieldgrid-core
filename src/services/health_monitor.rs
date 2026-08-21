//! Health & Performance Monitoring Service.
//!
//! # Overview
//!
//! Provides:
//! - Connector health monitoring
//! - System performance metrics
//! - Alert ingestion rates
//! - Action execution statistics

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::connectors::Connector;

/// System health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: String, // "healthy", "degraded", "unhealthy"
    pub timestamp: DateTime<Utc>,
    pub connectors: Vec<ConnectorHealth>,
    pub database: DatabaseHealth,
    pub metrics: SystemMetrics,
}

/// Connector health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorHealth {
    pub id: String,
    pub name: String,
    pub status: String, // "healthy", "degraded", "down", "unknown"
    pub last_check: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
    pub details: Option<String>,
}

/// Database health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub connection_count: Option<i64>,
    pub active_connections: Option<i64>,
}

/// System performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub alerts_last_hour: i64,
    pub alerts_last_24h: i64,
    pub cases_last_hour: i64,
    pub cases_last_24h: i64,
    pub actions_last_hour: i64,
    pub actions_last_24h: i64,
    pub avg_alert_response_time_ms: Option<f64>,
    pub uptime_seconds: u64,
}

/// Alert ingestion rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionRate {
    pub timestamp: DateTime<Utc>,
    pub alerts_per_minute: f64,
    pub alerts_per_hour: f64,
    pub alerts_per_day: f64,
    pub by_connector: Vec<ConnectorRate>,
}

/// Alert rate by connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRate {
    pub connector_id: String,
    pub rate_per_hour: f64,
}

/// Performance dashboard data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceDashboard {
    pub system_health: SystemHealth,
    pub ingestion_rate: IngestionRate,
    pub top_alert_sources: Vec<AlertSource>,
    pub severity_distribution: SeverityDistribution,
}

/// Alert source with count.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AlertSource {
    pub source: String,
    pub count: Option<i64>,
}

/// Severity distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// Get comprehensive system health.
pub async fn get_system_health(
    connectors: &[std::sync::Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<SystemHealth> {
    let mut connector_healths = Vec::new();

    for connector in connectors {
        let start = std::time::Instant::now();
        let status = connector.health_check().await;
        let response_time = start.elapsed().as_millis() as u64;

        let (status_str, details) = match status {
            crate::connectors::HealthStatus::Healthy => ("healthy".to_string(), None),
            crate::connectors::HealthStatus::Degraded { reason } => {
                ("degraded".to_string(), Some(reason))
            }
            crate::connectors::HealthStatus::Down { reason } => ("down".to_string(), Some(reason)),
        };

        connector_healths.push(ConnectorHealth {
            id: connector.id().to_string(),
            name: connector.id().to_string(),
            status: status_str,
            last_check: Utc::now(),
            response_time_ms: Some(response_time),
            details,
        });
    }

    let database = get_database_health(pool).await?;
    let metrics = get_system_metrics(pool).await?;

    let overall_status = if connector_healths.iter().all(|c| c.status == "healthy") {
        "healthy".to_string()
    } else if connector_healths.iter().any(|c| c.status == "down") {
        "unhealthy".to_string()
    } else {
        "degraded".to_string()
    };

    Ok(SystemHealth {
        status: overall_status,
        timestamp: Utc::now(),
        connectors: connector_healths,
        database,
        metrics,
    })
}

/// Get database health.
async fn get_database_health(pool: &PgPool) -> Result<DatabaseHealth> {
    // Simple connectivity check
    let result = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(pool)
        .await;

    let status = match result {
        Ok(_) => "healthy".to_string(),
        Err(_) => "unhealthy".to_string(),
    };

    Ok(DatabaseHealth {
        status,
        connection_count: None,
        active_connections: None,
    })
}

/// Get system metrics.
pub async fn get_system_metrics(pool: &PgPool) -> Result<SystemMetrics> {
    let alerts_1h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await
    .ok();

    let alerts_24h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .ok();

    let cases_1h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cases WHERE created_at > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await
    .ok();

    let cases_24h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cases WHERE created_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .ok();

    let actions_1h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_executions WHERE started_at > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await
    .ok();

    let actions_24h: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_executions WHERE started_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .ok();

    Ok(SystemMetrics {
        alerts_last_hour: alerts_1h.unwrap_or(0),
        alerts_last_24h: alerts_24h.unwrap_or(0),
        cases_last_hour: cases_1h.unwrap_or(0),
        cases_last_24h: cases_24h.unwrap_or(0),
        actions_last_hour: actions_1h.unwrap_or(0),
        actions_last_24h: actions_24h.unwrap_or(0),
        avg_alert_response_time_ms: None,
        uptime_seconds: 0, // TODO: track process start time
    })
}

/// Get alert ingestion rate.
pub async fn get_ingestion_rate(pool: &PgPool) -> Result<IngestionRate> {
    let alerts_24h: Vec<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT connector_id, COUNT(*) as count FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours' GROUP BY connector_id"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let total_24h: i64 = alerts_24h.iter().map(|(_, c)| c.unwrap_or(0)).sum();
    let rate_per_hour = total_24h as f64 / 24.0;
    let rate_per_minute = rate_per_hour / 60.0;

    let by_connector: Vec<ConnectorRate> = alerts_24h
        .into_iter()
        .filter_map(|(id, count)| {
            id.map(|connector_id| ConnectorRate {
                connector_id,
                rate_per_hour: count.unwrap_or(0) as f64 / 24.0,
            })
        })
        .collect();

    Ok(IngestionRate {
        timestamp: Utc::now(),
        alerts_per_minute: rate_per_minute,
        alerts_per_hour: rate_per_hour,
        alerts_per_day: total_24h as f64,
        by_connector,
    })
}

/// Get top alert sources.
pub async fn get_top_alert_sources(pool: &PgPool) -> Result<Vec<AlertSource>> {
    let sources = sqlx::query_as::<_, AlertSource>(
        r#"
        SELECT source, COUNT(*) as count
        FROM alerts
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY source
        ORDER BY count DESC
        LIMIT 10
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    Ok(sources)
}

/// Get severity distribution.
pub async fn get_severity_distribution(pool: &PgPool) -> Result<SeverityDistribution> {
    let critical: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND timestamp > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await
    .ok();

    let high: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'high' AND timestamp > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await
    .ok();

    let medium: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'medium' AND timestamp > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await
    .ok();

    let low: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'low' AND timestamp > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await
    .ok();

    let info: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'info' AND timestamp > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(pool)
    .await
    .ok();

    Ok(SeverityDistribution {
        critical: critical.unwrap_or(0),
        high: high.unwrap_or(0),
        medium: medium.unwrap_or(0),
        low: low.unwrap_or(0),
        info: info.unwrap_or(0),
    })
}

/// Get comprehensive performance dashboard.
pub async fn get_performance_dashboard(
    connectors: &[std::sync::Arc<dyn Connector>],
    pool: &PgPool,
) -> Result<PerformanceDashboard> {
    let system_health = get_system_health(connectors, pool).await?;
    let ingestion_rate = get_ingestion_rate(pool).await?;
    let top_alert_sources = get_top_alert_sources(pool).await?;
    let severity_distribution = get_severity_distribution(pool).await?;

    Ok(PerformanceDashboard {
        system_health,
        ingestion_rate,
        top_alert_sources,
        severity_distribution,
    })
}
