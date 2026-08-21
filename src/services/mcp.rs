//! MCP Agent Layer — exposes Shieldgrid API as MCP tools for AI agents.
//!
//! # Overview
//!
//! This module defines the tools that AI agents can call via the MCP protocol.
//! Each tool wraps one or more Shieldgrid API endpoints.
//!
//! # Architecture
//!
//! ```text
//! AI Agent (Claude, GPT, etc.)
//!        │ MCP Protocol
//!        ▼
//! shieldgrid-mcp (Node.js/TypeScript)
//!        │ REST / JSON
//!        ▼
//! shieldgrid-core (Rust API)
//!        │
//!        ▼
//! Connectors (Wazuh, Velociraptor, Shuffle, etc.)
//! ```
//!
//! # Available Tools
//!
//! ## Alert Tools
//! - `list_alerts` — List alerts with filtering
//! - `get_alert` — Get a specific alert
//! - `update_alert` — Update alert status
//!
//! ## Case Tools
//! - `list_cases` — List all cases
//! - `create_case` — Create a new case
//! - `get_case` — Get case details
//! - `update_case` — Update case status
//!
//! ## Action Tools
//! - `list_action_templates` — List available actions
//! - `execute_action` — Execute an action on an endpoint
//! - `list_action_executions` — Get action history
//!
//! ## AI Tools
//! - `triage_alert` — Run AI triage on an alert
//! - `batch_triage` — Triage multiple alerts
//! - `correlate_alerts` — Correlate alerts
//! - `ai_chat` — Chat with AI analyst
//!
//! ## Threat Intel Tools
//! - `lookup_ioc` — Look up threat intelligence
//! - `enrich_iocs` — Batch enrich IOCs
//!
//! ## Connector Tools
//! - `list_wazuh_agents` — List Wazuh agents
//! - `list_velociraptor_clients` — List Velociraptor clients
//! - `trigger_shuffle_workflow` — Trigger a Shuffle workflow
//!
//! ## Monitoring Tools
//! - `system_health` — Get system health
//! - `performance_dashboard` — Get performance metrics

use serde::{Deserialize, Serialize};

/// MCP Tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Get all available MCP tools.
pub fn get_mcp_tools() -> Vec<McpTool> {
    vec![
        // Alert Tools
        McpTool {
            name: "list_alerts".to_string(),
            description: "List alerts with optional filtering by severity, source, or status".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
                    "source": {"type": "string", "description": "Filter by source connector"},
                    "status": {"type": "string", "description": "Filter by status: open, closed"},
                    "limit": {"type": "integer", "description": "Max alerts to return", "default": 50}
                }
            }),
        },
        McpTool {
            name: "get_alert".to_string(),
            description: "Get a specific alert by ID".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Alert UUID"}
                },
                "required": ["alert_id"]
            }),
        },
        McpTool {
            name: "update_alert".to_string(),
            description: "Update alert status (open/closed)".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Alert UUID"},
                    "status": {"type": "string", "description": "New status: open or closed"}
                },
                "required": ["alert_id", "status"]
            }),
        },
        // Case Tools
        McpTool {
            name: "list_cases".to_string(),
            description: "List all cases".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        McpTool {
            name: "create_case".to_string(),
            description: "Create a new case".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Case title"}
                },
                "required": ["title"]
            }),
        },
        McpTool {
            name: "get_case".to_string(),
            description: "Get case details including linked alerts and tasks".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"}
                },
                "required": ["case_id"]
            }),
        },
        McpTool {
            name: "update_case".to_string(),
            description: "Update case status or assignment".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"},
                    "status": {"type": "string", "description": "New status: Open, In Progress, Closed"},
                    "assigned_to": {"type": "string", "description": "Assign to user email"}
                },
                "required": ["case_id"]
            }),
        },
        // Action Tools
        McpTool {
            name: "list_action_templates".to_string(),
            description: "List all available action templates (isolate, block IP, etc.)".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        McpTool {
            name: "execute_action".to_string(),
            description: "Execute an action on an endpoint (isolate host, block IP, etc.)".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "template_name": {"type": "string", "description": "Action template name"},
                    "target_id": {"type": "string", "description": "Target endpoint ID"},
                    "params": {"type": "object", "description": "Action parameters"},
                    "case_id": {"type": "string", "description": "Associated case UUID"}
                },
                "required": ["template_name", "target_id"]
            }),
        },
        McpTool {
            name: "list_action_executions".to_string(),
            description: "List recent action execution history".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max results", "default": 50}
                }
            }),
        },
        // AI Tools
        McpTool {
            name: "triage_alert".to_string(),
            description: "Run AI-powered triage on an alert to get risk score, MITRE mapping, and recommended actions".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Alert UUID to triage"}
                },
                "required": ["alert_id"]
            }),
        },
        McpTool {
            name: "batch_triage".to_string(),
            description: "Triage multiple alerts at once with optional correlation".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alert_ids": {"type": "array", "items": {"type": "string"}, "description": "List of alert UUIDs"},
                    "correlate": {"type": "boolean", "description": "Correlate alerts", "default": false}
                },
                "required": ["alert_ids"]
            }),
        },
        McpTool {
            name: "correlate_alerts".to_string(),
            description: "Correlate multiple alerts to identify attack patterns".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alert_ids": {"type": "array", "items": {"type": "string"}, "description": "List of alert UUIDs"}
                },
                "required": ["alert_ids"]
            }),
        },
        McpTool {
            name: "ai_chat".to_string(),
            description: "Chat with the AI analyst for collaborative investigation".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Your question or request"},
                    "alert_id": {"type": "string", "description": "Optional alert context"}
                },
                "required": ["message"]
            }),
        },
        // Threat Intel Tools
        McpTool {
            name: "lookup_ioc".to_string(),
            description: "Look up threat intelligence for an IOC (IP, domain, hash, CVE)".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "IOC to look up (IP, domain, hash, CVE)"}
                },
                "required": ["ioc"]
            }),
        },
        McpTool {
            name: "enrich_iocs".to_string(),
            description: "Batch enrich multiple IOCs with threat intelligence".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "iocs": {"type": "array", "items": {"type": "string"}, "description": "List of IOCs to enrich"}
                },
                "required": ["iocs"]
            }),
        },
        // Connector Tools
        McpTool {
            name: "list_wazuh_agents".to_string(),
            description: "List Wazuh agents with their status and OS information".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Filter by status: active, disconnected, pending"}
                }
            }),
        },
        McpTool {
            name: "list_velociraptor_clients".to_string(),
            description: "List Velociraptor clients with OS and version information".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        McpTool {
            name: "trigger_shuffle_workflow".to_string(),
            description: "Trigger a Shuffle SOAR workflow".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "workflow_id": {"type": "string", "description": "Shuffle workflow ID"},
                    "data": {"type": "object", "description": "Input data for the workflow"}
                },
                "required": ["workflow_id"]
            }),
        },
        // Monitoring Tools
        McpTool {
            name: "system_health".to_string(),
            description: "Get system health status including all connectors".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        McpTool {
            name: "performance_dashboard".to_string(),
            description: "Get performance metrics, ingestion rates, and severity distribution".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        // Scheduler Tools
        McpTool {
            name: "list_schedules".to_string(),
            description: "List all scheduled automation tasks".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        McpTool {
            name: "create_schedule".to_string(),
            description: "Create a scheduled automation task".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Schedule name"},
                    "connector_id": {"type": "string", "description": "Target connector"},
                    "action_type": {"type": "string", "description": "Action to execute"},
                    "trigger": {"type": "object", "description": "Trigger config: {\"type\": \"interval\", \"seconds\": 3600}"}
                },
                "required": ["name", "connector_id", "action_type", "trigger"]
            }),
        },
        // Enhanced Incident Tools
        McpTool {
            name: "list_case_tasks".to_string(),
            description: "List all tasks for a case".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"}
                },
                "required": ["case_id"]
            }),
        },
        McpTool {
            name: "create_case_task".to_string(),
            description: "Create a task for a case".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"},
                    "title": {"type": "string", "description": "Task title"},
                    "description": {"type": "string", "description": "Task description"}
                },
                "required": ["case_id", "title"]
            }),
        },
        McpTool {
            name: "list_observables".to_string(),
            description: "List observables (IOCs) for a case".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"}
                },
                "required": ["case_id"]
            }),
        },
        McpTool {
            name: "create_observable".to_string(),
            description: "Add an observable (IOC) to a case".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"},
                    "type": {"type": "string", "description": "IOC type: ip, domain, hash_sha256, url, email"},
                    "value": {"type": "string", "description": "IOC value"},
                    "confidence": {"type": "string", "description": "low, medium, high"}
                },
                "required": ["case_id", "type", "value"]
            }),
        },
        McpTool {
            name: "apply_template".to_string(),
            description: "Apply a case template to create tasks and observables".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case UUID"},
                    "template_id": {"type": "string", "description": "Template UUID"}
                },
                "required": ["case_id", "template_id"]
            }),
        },
    ]
}

/// Get tool by name.
pub fn get_tool(name: &str) -> Option<McpTool> {
    get_mcp_tools().into_iter().find(|t| t.name == name)
}
