-- Agent Correlation
--
-- Maps Wazuh agents to Velociraptor clients on the same physical host.
-- Uses multiple matching signals with a confidence score.

CREATE TABLE agent_correlations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wazuh_agent_id  TEXT NOT NULL,
    wazuh_agent_name TEXT NOT NULL,
    velo_client_id  TEXT NOT NULL,
    velo_hostname   TEXT NOT NULL,
    match_method    TEXT NOT NULL,        -- 'hostname_exact', 'hostname_partial', 'ip_os', 'manual'
    confidence      REAL NOT NULL,        -- 0.0 to 1.0
    confirmed       BOOLEAN NOT NULL DEFAULT false,  -- analyst-confirmed
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(wazuh_agent_id, velo_client_id)
);

CREATE INDEX idx_corr_wazuh ON agent_correlations(wazuh_agent_id);
CREATE INDEX idx_corr_velo ON agent_correlations(velo_client_id);
