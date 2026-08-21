-- Notifications System
--
-- Manages notification channels and delivery tracking.

CREATE TABLE notification_channels (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    channel_type TEXT NOT NULL, -- 'email', 'slack', 'webhook', 'sms'
    enabled     BOOLEAN NOT NULL DEFAULT true,
    config      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_rules (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    channel_id      UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    trigger_type    TEXT NOT NULL, -- 'alert', 'case', 'action', 'schedule'
    conditions      JSONB NOT NULL DEFAULT '{}'::jsonb,
    template        TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_rules_enabled ON notification_rules(enabled) WHERE enabled = true;
CREATE INDEX idx_notification_rules_trigger ON notification_rules(trigger_type);

CREATE TABLE notification_log (
    id          UUID PRIMARY KEY,
    rule_id     UUID REFERENCES notification_rules(id) ON DELETE SET NULL,
    channel_id  UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    status      TEXT NOT NULL, -- 'sent', 'failed', 'pending'
    recipient   TEXT NOT NULL,
    subject     TEXT,
    message     TEXT NOT NULL,
    error       TEXT,
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_log_rule ON notification_log(rule_id);
CREATE INDEX idx_notification_log_sent ON notification_log(sent_at DESC);
CREATE INDEX idx_notification_log_status ON notification_log(status);

-- Seed default notification channels
INSERT INTO notification_channels (id, name, channel_type, config)
VALUES
    ('55555555-5555-5555-5555-555555555501', 'Default Webhook', 'webhook', '{"url": ""}'::jsonb),
    ('55555555-5555-5555-5555-555555555502', 'Default Email', 'email', '{"smtp_host": "", "smtp_port": 587, "from": ""}'::jsonb),
    ('55555555-5555-5555-5555-555555555503', 'Default Slack', 'slack', '{"webhook_url": ""}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- Seed notification rules
INSERT INTO notification_rules (id, name, description, channel_id, trigger_type, conditions, template)
VALUES
    ('66666666-6666-6666-6666-666666666601', 'Critical Alert Notification', 'Notify on critical alerts', '55555555-5555-5555-5555-555555555501', 'alert', '{"severity": ["critical"]}'::jsonb, 'CRITICAL ALERT: {{alert.source_id}} from {{alert.source}}'),
    ('66666666-6666-6666-6666-666666666602', 'Action Failure Alert', 'Notify when actions fail', '55555555-5555-5555-5555-555555555501', 'action', '{"status": ["failed", "timeout"]}'::jsonb, 'Action {{action.template_name}} failed on {{action.target_id}}')
ON CONFLICT (id) DO NOTHING;
