-- Agent Status History
--
-- Tracks agent health status over time for monitoring and alerting.

CREATE TABLE agent_status_history (
    id          UUID PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    source      TEXT NOT NULL, -- 'wazuh', 'velociraptor', etc.
    status      TEXT NOT NULL, -- 'healthy', 'unhealthy', 'active', 'disconnected', etc.
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_status_history_agent ON agent_status_history(agent_id, source);
CREATE INDEX idx_agent_status_history_checked ON agent_status_history(checked_at DESC);
CREATE INDEX idx_agent_status_history_status ON agent_status_history(status);
