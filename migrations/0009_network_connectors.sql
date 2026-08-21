-- Network Connectors
--
-- Manages syslog-based network device integrations (Fortinet, Palo Alto, Cisco).
-- These connectors receive and parse syslog from firewalls and network devices.

CREATE TABLE network_connectors (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    device_type     TEXT NOT NULL, -- 'fortinet', 'paloalto', 'cisco_asa', 'cisco_ftd', 'generic'
    ip_address      TEXT NOT NULL,
    syslog_port     INTEGER NOT NULL DEFAULT 514,
    syslog_protocol TEXT NOT NULL DEFAULT 'udp', -- 'udp', 'tcp', 'tcp-tls'
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_seen_at    TIMESTAMPTZ,
    alert_count     BIGINT NOT NULL DEFAULT 0,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_network_connectors_type ON network_connectors(device_type);
CREATE INDEX idx_network_connectors_enabled ON network_connectors(enabled) WHERE enabled = true;

CREATE TABLE syslog_messages (
    id              UUID PRIMARY KEY,
    connector_id    UUID NOT NULL REFERENCES network_connectors(id) ON DELETE CASCADE,
    source_ip       TEXT NOT NULL,
    raw_message     TEXT NOT NULL,
    parsed_format   TEXT, -- 'cef', 'leef', 'plain'
    parsed_success  BOOLEAN NOT NULL DEFAULT false,
    alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_syslog_messages_connector ON syslog_messages(connector_id);
CREATE INDEX idx_syslog_messages_received ON syslog_messages(received_at DESC);
CREATE INDEX idx_syslog_messages_parsed ON syslog_messages(parsed_success);
