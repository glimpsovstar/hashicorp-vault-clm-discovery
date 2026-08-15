-- M3 explainable posture: versioned ops policy, persisted findings, waivers, PQC tag.

CREATE TABLE policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL DEFAULT 'ops',
    version INTEGER NOT NULL,
    windows JSONB NOT NULL DEFAULT '{"critical_days":7,"high_days":30}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT policy_versions_kind_version_unique UNIQUE (kind, version)
);

INSERT INTO policy_versions (kind, version, windows)
VALUES ('ops', 1, '{"critical_days":7,"high_days":30}');

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    pack TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    policy_version_id UUID REFERENCES policy_versions(id) ON DELETE SET NULL,
    waived BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT findings_cert_rule_unique UNIQUE (cert_id, rule_id),
    CONSTRAINT findings_severity_check CHECK (severity IN ('critical','high','medium','low','info')),
    CONSTRAINT findings_status_check CHECK (status IN ('open','resolved'))
);

CREATE INDEX idx_findings_cert_status ON findings (cert_id, status);
CREATE INDEX idx_findings_pack_severity ON findings (pack, severity);
CREATE INDEX idx_findings_rule ON findings (rule_id);

CREATE TABLE waivers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_waivers_cert_rule ON waivers (cert_id, rule_id);
CREATE INDEX idx_waivers_expires ON waivers (expires_at);

ALTER TABLE certificates
    ADD COLUMN pqc_tag TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN risk_reasons JSONB NOT NULL DEFAULT '[]';

ALTER TABLE certificates
    ADD CONSTRAINT certificates_pqc_tag_check
    CHECK (pqc_tag IN ('classic','hybrid','pqc','unknown'));

CREATE INDEX idx_certificates_risk_score ON certificates (risk_score DESC);
CREATE INDEX idx_certificates_pqc_tag ON certificates (pqc_tag);
