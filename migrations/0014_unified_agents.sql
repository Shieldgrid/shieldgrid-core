-- Unified Agents
--
-- Replaces agent_correlations by storing a single row per physical host,
-- syncing data from both Wazuh and Velociraptor by matching exact hostnames.

CREATE TABLE unified_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL UNIQUE,
    
    -- Wazuh Info
    wazuh_id TEXT,
    wazuh_status TEXT,
    wazuh_last_seen TIMESTAMPTZ,
    wazuh_ip TEXT,
    wazuh_os TEXT,
    wazuh_version TEXT,
    
    -- Velociraptor Info
    velo_id TEXT,
    velo_status TEXT,
    velo_last_seen TIMESTAMPTZ,
    velo_version TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_unified_agents_wazuh_id ON unified_agents(wazuh_id);
CREATE INDEX idx_unified_agents_velo_id ON unified_agents(velo_id);

-- Drop the old table
DROP TABLE IF EXISTS agent_correlations;
