-- Shieldgrid Actions & Active Response Framework
--
-- Manages automated and analyst-driven containment, remediation,
-- and forensic collection actions across endpoints (Velociraptor, Wazuh, EDRs).

CREATE TABLE action_templates (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description  TEXT NOT NULL,
    category     TEXT NOT NULL, -- 'containment', 'remediation', 'forensics', 'network'
    provider     TEXT NOT NULL, -- 'velociraptor', 'wazuh', 'generic'
    risk_level   TEXT NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    params_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE action_executions (
    id           UUID PRIMARY KEY,
    template_id  UUID REFERENCES action_templates(id) ON DELETE SET NULL,
    template_name TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    target_type  TEXT NOT NULL, -- 'agent', 'host', 'ip', 'user'
    initiated_by TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'timeout'
    params       JSONB NOT NULL DEFAULT '{}'::jsonb,
    output       TEXT,
    error        TEXT,
    case_id      UUID REFERENCES cases(id) ON DELETE SET NULL,
    alert_id     UUID REFERENCES alerts(id) ON DELETE SET NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_action_executions_target ON action_executions(target_id);
CREATE INDEX idx_action_executions_status ON action_executions(status);
CREATE INDEX idx_action_executions_created ON action_executions(started_at DESC);

-- Seed core action templates
INSERT INTO action_templates (id, name, display_name, description, category, provider, risk_level, params_schema)
VALUES
    ('11111111-1111-1111-1111-111111111101', 'isolate_endpoint', 'Isolate Endpoint from Network', 'Quarantines the host at the network layer while preserving SOC telemetry communication.', 'containment', 'velociraptor', 'high', '{"client_id": {"type": "string", "required": true}}'::jsonb),
    ('11111111-1111-1111-1111-111111111102', 'unisolate_endpoint', 'Restore Endpoint Network Access', 'Removes network quarantine rules and restores full connectivity.', 'containment', 'velociraptor', 'medium', '{"client_id": {"type": "string", "required": true}}'::jsonb),
    ('11111111-1111-1111-1111-111111111103', 'terminate_process', 'Terminate Malicious Process', 'Forcefully terminates running processes by PID or process name.', 'remediation', 'velociraptor', 'medium', '{"client_id": {"type": "string", "required": true}, "pid": {"type": "number", "required": false}, "name": {"type": "string", "required": false}}'::jsonb),
    ('11111111-1111-1111-1111-111111111104', 'quarantine_file', 'Quarantine File to Vault', 'Relocates a malicious binary to the secure quarantined folder and strips execute permissions.', 'remediation', 'velociraptor', 'low', '{"client_id": {"type": "string", "required": true}, "path": {"type": "string", "required": true}}'::jsonb),
    ('11111111-1111-1111-1111-111111111105', 'collect_triage', 'Collect Rapid Forensic Triage', 'Collects process listings, network connections, autoruns, and recent event logs into an encrypted triage zip.', 'forensics', 'velociraptor', 'low', '{"client_id": {"type": "string", "required": true}}'::jsonb),
    ('11111111-1111-1111-1111-111111111106', 'wazuh_active_response', 'Trigger Wazuh Active Response', 'Executes Wazuh AR script on the target agent ID.', 'containment', 'wazuh', 'medium', '{"agent_id": {"type": "string", "required": true}, "command": {"type": "string", "required": true}}'::jsonb)
ON CONFLICT (name) DO NOTHING;
