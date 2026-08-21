-- Scheduled Actions Framework
--
-- Manages automated recurring tasks that run on defined schedules.
-- Supports interval-based, cron-based, and event-triggered automation.

CREATE TABLE scheduled_actions (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    connector_id    TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    target_id       TEXT,
    trigger         JSONB NOT NULL,  -- { "type": "interval", "seconds": 3600 } or { "type": "cron", "expression": "..." }
    params          JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scheduled_actions_enabled ON scheduled_actions(enabled) WHERE enabled = true;
CREATE INDEX idx_scheduled_actions_next_run ON scheduled_actions(next_run_at) WHERE enabled = true;
CREATE INDEX idx_scheduled_actions_connector ON scheduled_actions(connector_id);

CREATE TABLE scheduled_action_executions (
    id              UUID PRIMARY KEY,
    schedule_id     UUID NOT NULL REFERENCES scheduled_actions(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'timeout'
    result          TEXT,
    error           TEXT,
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_scheduled_action_executions_schedule ON scheduled_action_executions(schedule_id);
CREATE INDEX idx_scheduled_action_executions_status ON scheduled_action_executions(status);
CREATE INDEX idx_scheduled_action_executions_executed ON scheduled_action_executions(executed_at DESC);

-- Seed some useful scheduled actions
INSERT INTO scheduled_actions (id, name, description, connector_id, action_type, trigger, params, enabled)
VALUES
    ('33333333-3333-3333-3333-333333333301', 'Connector Health Check', 'Check health of all connectors every 5 minutes', 'wazuh', 'health_check', '{"type": "interval", "seconds": 300}'::jsonb, '{}'::jsonb, true),
    ('33333333-3333-3333-3333-333333333302', 'Critical Alert Notification', 'Trigger Shuffle workflow for new critical alerts', 'shuffle', 'trigger_workflow', '{"type": "interval", "seconds": 900}'::jsonb, '{"workflow_id": "critical-alert-handler"}'::jsonb, false)
ON CONFLICT (id) DO NOTHING;
