-- Threat intelligence cache and IOC enrichment store.
--
-- Caches lookup results from external intelligence providers (VirusTotal,
-- EPSS, AlienVault OTX, custom threat feeds) to avoid duplicate external API
-- calls and rate limit exhaustion.

CREATE TABLE threat_intel_cache (
    id           UUID PRIMARY KEY,
    ioc_type     TEXT NOT NULL,
    ioc_value    TEXT NOT NULL,
    provider     TEXT NOT NULL,
    verdict      TEXT NOT NULL DEFAULT 'unknown',
    score        DOUBLE PRECISION,
    raw_data     JSONB NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value, provider)
);

CREATE INDEX idx_threat_intel_lookup ON threat_intel_cache (ioc_value);
CREATE INDEX idx_threat_intel_expires ON threat_intel_cache (expires_at);
