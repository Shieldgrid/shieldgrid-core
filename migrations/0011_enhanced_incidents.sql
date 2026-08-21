-- Enhanced Incidents: Tasks, Observables, and Templates
--
-- Extends the case management system with structured investigation workflows.

-- Tasks: Break cases into discrete, assignable checklist items
CREATE TABLE case_tasks (
    id          UUID PRIMARY KEY,
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'in_progress', 'completed', 'skipped'
    assigned_to TEXT,
    due_date    TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_case_tasks_case ON case_tasks(case_id);
CREATE INDEX idx_case_tasks_status ON case_tasks(status);

-- Observables: Structured IOCs attached to cases
CREATE TABLE observables (
    id          UUID PRIMARY KEY,
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type        TEXT NOT NULL, -- 'ip', 'domain', 'hash_md5', 'hash_sha256', 'url', 'email', 'file_path', 'user_agent'
    value       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    confidence  TEXT NOT NULL DEFAULT 'low', -- 'low', 'medium', 'high'
    source      TEXT NOT NULL DEFAULT 'manual', -- 'manual', 'alert', 'enrichment', 'threat_intel'
    tlp         TEXT NOT NULL DEFAULT 'white', -- 'white', 'green', 'amber', 'red'
    enriched    BOOLEAN NOT NULL DEFAULT false,
    enrichment_data JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_observables_case ON observables(case_id);
CREATE INDEX idx_observables_type ON observables(type);
CREATE INDEX idx_observables_value ON observables(value);
CREATE UNIQUE INDEX idx_observables_case_value_type ON observables(case_id, type, value);

-- Case templates: Starting task/observable checklists for common incident types
CREATE TABLE case_templates (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    category    TEXT NOT NULL, -- 'phishing', 'malware', 'unauthorized_access', 'data_breach', 'insider_threat', 'ddos'
    tasks       JSONB NOT NULL DEFAULT '[]'::jsonb,
    observables JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed common case templates
INSERT INTO case_templates (id, name, description, category, tasks, observables)
VALUES
    ('44444444-4444-4444-4444-444444444401', 'Phishing Investigation', 'Standard playbook for phishing email incidents', 'phishing',
     '[{"title": "Analyze email headers", "description": "Check sender, SPF/DKIM/DMARC"}, {"title": "Extract and analyze URLs", "description": "Check all links in the email"}, {"title": "Extract attachments", "description": "Sandbox any attachments"}, {"title": "Identify targeted users", "description": "Determine who received the email"}, {"title": "Check for credential submission", "description": "Review logs for credential use"}, {"title": "Block IOCs", "description": "Block sender, URLs, and file hashes"}]'::jsonb,
     '[{"type": "email", "value": "", "description": "Phishing sender email", "confidence": "high"}, {"type": "domain", "value": "", "description": "Phishing domain", "confidence": "medium"}, {"type": "hash_sha256", "value": "", "description": "Malicious attachment hash", "confidence": "medium"}]'::jsonb),

    ('44444444-4444-4444-4444-444444444402', 'Malware Incident', 'Standard playbook for malware detection', 'malware',
     '[{"title": "Isolate affected host", "description": "Network quarantine immediately"}, {"title": "Identify malware family", "description": "Run static/dynamic analysis"}, {"title": "Determine infection vector", "description": "How did it get in?"}, {"title": "Check lateral movement", "description": "Scan network for similar IOCs"}, {"title": "Remove malware", "description": "Clean or reimage affected systems"}, {"title": "Restore from backup", "description": "If files were encrypted or deleted"}]'::jsonb,
     '[{"type": "hash_sha256", "value": "", "description": "Malware file hash", "confidence": "high"}, {"type": "ip", "value": "", "description": "C2 server IP", "confidence": "high"}, {"type": "file_path", "value": "", "description": "Malware file location", "confidence": "high"}]'::jsonb),

    ('44444444-4444-4444-4444-444444444403', 'Unauthorized Access', 'Standard playbook for unauthorized access', 'unauthorized_access',
     '[{"title": "Identify compromised account", "description": "Which account was used?"}, {"title": "Review access logs", "description": "Timeline of access events"}, {"title": "Check data exfiltration", "description": "Look for large transfers"}, {"title": "Reset credentials", "description": "Force password reset"}, {"title": "Enable MFA", "description": "If not already enabled"}, {"title": "Review access permissions", "description": "Check for privilege escalation"}]'::jsonb,
     '[{"type": "user_agent", "value": "", "description": "Suspicious user agent", "confidence": "medium"}, {"type": "ip", "value": "", "description": "Attacker IP", "confidence": "high"}]'::jsonb),

    ('44444444-4444-4444-4444-444444444404', 'Data Breach', 'Standard playbook for data breach investigation', 'data_breach',
     '[{"title": "Identify exposed data", "description": "What data was accessed/leaked?"}, {"title": "Determine scope", "description": "How many records affected?"}, {"title": "Identify attack vector", "description": "How did they get in?"}, {"title": "Notify stakeholders", "description": "Legal, compliance, affected parties"}, {"title": "Contain the breach", "description": "Stop ongoing access"}, {"title": "Forensic analysis", "description": "Full timeline reconstruction"}]'::jsonb,
     '[{"type": "hash_sha256", "value": "", "description": "Exfiltrated file hash", "confidence": "high"}]'::jsonb)
ON CONFLICT (name) DO NOTHING;
