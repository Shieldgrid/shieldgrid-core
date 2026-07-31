-- Alert persistence and ingest job registry.
--
-- `alerts` is the durable store for normalised alerts. Each row is keyed on
-- the stable source identifier (OpenSearch `_id` for Wazuh, the source UUID
-- for Velociraptor) so re-fetching the same event from the upstream tool is an
-- idempotent upsert instead of a duplicate row. `id` remains the Shieldgrid
-- UUID used by case links and the API.

CREATE TABLE alerts (
    id           UUID PRIMARY KEY,
    connector_id TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    source       TEXT NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL,
    raw_payload  JSONB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (connector_id, source_id)
);

CREATE INDEX idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX idx_alerts_connector_status ON alerts (connector_id, status);

-- `jobs` is the ingest scheduler registry. One row per connector, seeded at
-- startup. The background loop in `services/ingest.rs` runs any enabled job
-- whose `next_run_at` has passed and tracks its progress (`last_watermark`,
-- `last_run_at`, `last_status`, `last_error`) so a connector failure is
-- observable and does not lose the ingestion cursor.

CREATE TABLE jobs (
    id               UUID PRIMARY KEY,
    connector_id     TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL DEFAULT 5,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at      TIMESTAMPTZ,
    last_status      TEXT,
    last_error       TEXT,
    last_watermark   TIMESTAMPTZ,
    next_run_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Record when an alert was linked to a case. Previously a re-link was
-- indistinguishable from a fresh link.
ALTER TABLE case_alerts ADD COLUMN linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
