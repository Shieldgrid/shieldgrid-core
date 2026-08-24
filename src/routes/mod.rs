//! Route definitions for the Shieldgrid API.
//!
//! `build_router` is the single construction point for the Axum [`Router`].
//! It accepts [`AppState`] containing the registered connectors so every
//! handler can reach them via Axum's state extraction.

use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::connectors::Connector;

pub mod actions;
pub mod agents;
pub mod ai_analyst;
pub mod alerts;
pub mod audit;
pub mod auth;
pub mod cases;
pub mod detection;
pub mod health;
pub mod incidents;
pub mod jobs;
pub mod monitoring;
pub mod network_connectors;
pub mod notifications;
pub mod scheduler;
pub mod shuffle;
pub mod threat_intel;
pub mod velociraptor;
pub mod wazuh;

// ── App state ─────────────────────────────────────────────────────────────────

/// Shared state threaded through every Axum request handler.
///
/// Cloning is cheap — `Arc<dyn Connector>` bumps a reference count, and the
/// outer `Vec` is small (one entry per registered connector).
#[derive(Clone)]
pub struct AppState {
    /// All registered connectors.  Empty in tests; populated at startup.
    pub connectors: Vec<Arc<dyn Connector>>,
    /// Connection pool for the PostgreSQL database.
    pub db: sqlx::PgPool,
    /// Application configuration
    pub config: Arc<crate::config::Config>,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the main application router with all registered routes.
pub fn build_router(state: AppState) -> Router {
    let allowed_origin = state
        .config
        .allowed_origin
        .parse::<axum::http::HeaderValue>()
        .expect("ALLOWED_ORIGIN must be a valid HTTP header value");

    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/api/v1/alerts", get(alerts::alerts_handler))
        .route(
            "/api/v1/alerts/{id}",
            axum::routing::patch(alerts::update_alert_handler),
        )
        .route("/api/v1/jobs", axum::routing::get(jobs::list_jobs_handler))
        .route(
            "/api/v1/auth/login",
            axum::routing::post(auth::login_handler),
        )
        .route("/api/v1/auth/me", axum::routing::get(auth::me_handler))
        .route(
            "/api/v1/auth/refresh",
            axum::routing::get(auth::refresh_handler),
        )
        .route(
            "/api/v1/auth/logout",
            axum::routing::post(auth::logout_handler),
        )
        .route(
            "/api/v1/audit",
            axum::routing::get(audit::list_audit_log_handler),
        )
        .route(
            "/api/v1/cases",
            axum::routing::get(cases::list_cases_handler).post(cases::create_case_handler),
        )
        .route(
            "/api/v1/cases/{id}",
            axum::routing::get(cases::get_case_handler).patch(cases::update_case_handler),
        )
        .route(
            "/api/v1/cases/{id}/alerts",
            axum::routing::get(cases::list_case_alerts_handler).post(cases::attach_alert_handler),
        )
        .route(
            "/api/v1/cases/{id}/alerts/{alert_id}",
            axum::routing::delete(cases::detach_alert_handler),
        )
        .route(
            "/api/v1/cases/{id}/actions",
            axum::routing::get(cases::list_case_actions_handler)
                .post(cases::execute_action_handler),
        )
        .route(
            "/api/v1/velociraptor/clients",
            axum::routing::get(velociraptor::list_clients_handler),
        )
        .route(
            "/api/v1/velociraptor/artifacts",
            axum::routing::get(velociraptor::list_artifacts_handler),
        )
        .route(
            "/api/v1/velociraptor/query",
            axum::routing::post(velociraptor::run_query_handler),
        )
        .route(
            "/api/v1/wazuh/agents",
            axum::routing::get(wazuh::list_agents_handler),
        )
        .route(
            "/api/v1/agents",
            axum::routing::get(agents::list_agents_handler),
        )
        .route(
            "/api/v1/agents/sync",
            axum::routing::post(agents::sync_agents_handler),
        )
        .route(
            "/api/v1/threat-intel/lookup",
            axum::routing::get(threat_intel::lookup_ioc_handler),
        )
        .route(
            "/api/v1/threat-intel/enrich",
            axum::routing::post(threat_intel::enrich_iocs_handler),
        )
        .route(
            "/api/v1/threat-intel/epss/{cve}",
            axum::routing::get(threat_intel::lookup_epss_handler),
        )
        .route(
            "/api/v1/actions/templates",
            axum::routing::get(actions::list_action_templates_handler),
        )
        .route(
            "/api/v1/actions/execute",
            axum::routing::post(actions::execute_action_handler),
        )
        .route(
            "/api/v1/actions/executions",
            axum::routing::get(actions::list_action_executions_handler),
        )
        .route(
            "/api/v1/actions/executions/{id}",
            axum::routing::get(actions::get_action_execution_handler),
        )
        .route(
            "/api/v1/rules",
            axum::routing::get(detection::list_detection_rules_handler),
        )
        .route(
            "/api/v1/rules/{id}",
            axum::routing::get(detection::get_detection_rule_handler)
                .patch(detection::update_detection_rule_handler),
        )
        .route(
            "/api/v1/mitre/tactics",
            axum::routing::get(detection::list_mitre_tactics_handler),
        )
        .route(
            "/api/v1/mitre/matrix",
            axum::routing::get(detection::get_mitre_matrix_handler),
        )
        .route(
            "/api/v1/ai/triage",
            axum::routing::post(ai_analyst::triage_handler),
        )
        .route(
            "/api/v1/ai/summary",
            axum::routing::get(ai_analyst::posture_summary_handler),
        )
        .route(
            "/api/v1/shuffle/workflows",
            axum::routing::get(shuffle::list_workflows_handler),
        )
        .route(
            "/api/v1/shuffle/trigger",
            axum::routing::post(shuffle::trigger_workflow_handler),
        )
        .route(
            "/api/v1/shuffle/webhook",
            axum::routing::post(shuffle::webhook_handler),
        )
        .route(
            "/api/v1/shuffle/status/{execution_id}",
            axum::routing::get(shuffle::get_execution_status_handler),
        )
        .route(
            "/api/v1/scheduler/schedules",
            axum::routing::get(scheduler::list_schedules_handler)
                .post(scheduler::create_schedule_handler),
        )
        .route(
            "/api/v1/scheduler/schedules/{id}",
            axum::routing::get(scheduler::get_schedule_handler)
                .patch(scheduler::update_schedule_handler)
                .delete(scheduler::delete_schedule_handler),
        )
        .route(
            "/api/v1/scheduler/schedules/{id}/executions",
            axum::routing::get(scheduler::get_execution_history_handler),
        )
        .route(
            "/api/v1/network-connectors",
            axum::routing::get(network_connectors::list_network_connectors_handler)
                .post(network_connectors::create_network_connector_handler),
        )
        .route(
            "/api/v1/network-connectors/stats",
            axum::routing::get(network_connectors::network_connector_stats_handler),
        )
        .route(
            "/api/v1/network-connectors/{id}",
            axum::routing::get(network_connectors::get_network_connector_handler)
                .patch(network_connectors::update_network_connector_handler)
                .delete(network_connectors::delete_network_connector_handler),
        )
        .route(
            "/api/v1/network-connectors/{id}/messages",
            axum::routing::get(network_connectors::list_syslog_messages_handler),
        )
        // Enhanced Incidents: Tasks
        .route(
            "/api/v1/cases/{id}/tasks",
            axum::routing::get(incidents::list_tasks_handler).post(incidents::create_task_handler),
        )
        .route(
            "/api/v1/tasks/{id}",
            axum::routing::patch(incidents::update_task_handler)
                .delete(incidents::delete_task_handler),
        )
        // Enhanced Incidents: Observables
        .route(
            "/api/v1/cases/{id}/observables",
            axum::routing::get(incidents::list_observables_handler)
                .post(incidents::create_observable_handler),
        )
        .route(
            "/api/v1/observables/{id}",
            axum::routing::patch(incidents::update_observable_handler)
                .delete(incidents::delete_observable_handler),
        )
        // Enhanced Incidents: Templates
        .route(
            "/api/v1/templates",
            axum::routing::get(incidents::list_templates_handler),
        )
        .route(
            "/api/v1/templates/{id}",
            axum::routing::get(incidents::get_template_handler),
        )
        .route(
            "/api/v1/cases/{id}/apply-template/{template_id}",
            axum::routing::post(incidents::apply_template_handler),
        )
        .route(
            "/api/v1/cases/{id}/progress",
            axum::routing::get(incidents::case_progress_handler),
        )
        // Monitoring
        .route(
            "/api/v1/monitoring/health",
            axum::routing::get(monitoring::system_health_handler),
        )
        .route(
            "/api/v1/monitoring/metrics",
            axum::routing::get(monitoring::metrics_handler),
        )
        .route(
            "/api/v1/monitoring/ingestion",
            axum::routing::get(monitoring::ingestion_rate_handler),
        )
        .route(
            "/api/v1/monitoring/dashboard",
            axum::routing::get(monitoring::dashboard_handler),
        )
        .route(
            "/api/v1/monitoring/sources",
            axum::routing::get(monitoring::top_sources_handler),
        )
        .route(
            "/api/v1/monitoring/severity",
            axum::routing::get(monitoring::severity_distribution_handler),
        )
        // Notifications
        .route(
            "/api/v1/notifications/channels",
            axum::routing::get(notifications::list_channels_handler)
                .post(notifications::create_channel_handler),
        )
        .route(
            "/api/v1/notifications/channels/{id}",
            axum::routing::patch(notifications::update_channel_handler)
                .delete(notifications::delete_channel_handler),
        )
        .route(
            "/api/v1/notifications/rules",
            axum::routing::get(notifications::list_rules_handler)
                .post(notifications::create_rule_handler),
        )
        .route(
            "/api/v1/notifications/rules/{id}",
            axum::routing::delete(notifications::delete_rule_handler),
        )
        .route(
            "/api/v1/notifications/send",
            axum::routing::post(notifications::send_notification_handler),
        )
        .route(
            "/api/v1/notifications/logs",
            axum::routing::get(notifications::list_logs_handler),
        )
        .route(
            "/api/v1/notifications/stats",
            axum::routing::get(notifications::notification_stats_handler),
        )
        .layer(cors)
        .with_state(state)
}
