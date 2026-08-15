-- M2 durable lifecycle jobs: persist AAP job ids, claim leases for a worker,
-- and record expected/observed wire verification separately from the EDA outbox.
CREATE TABLE lifecycle_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL DEFAULT 'renew',
    status TEXT NOT NULL,
    predecessor_cert_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    successor_cert_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    aap_job_id INTEGER,
    aap_workflow BOOLEAN NOT NULL DEFAULT FALSE,
    idempotency_key TEXT NOT NULL,
    expected JSONB NOT NULL DEFAULT '{}',
    observed JSONB NOT NULL DEFAULT '{}',
    failure_reason TEXT,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT lifecycle_jobs_idempotency_key_unique UNIQUE (idempotency_key)
);

CREATE INDEX idx_lifecycle_jobs_status_lease
    ON lifecycle_jobs (status, lease_expires_at NULLS FIRST);

CREATE INDEX idx_lifecycle_jobs_predecessor
    ON lifecycle_jobs (predecessor_cert_id, created_at DESC);

-- Append-only per-job timeline (distinct from EDA events outbox).
CREATE TABLE lifecycle_job_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES lifecycle_jobs(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lifecycle_job_events_job
    ON lifecycle_job_events (job_id, created_at);

-- Thin approvals (auto or human). SoD completeness is M1 actors; rows still recorded.
CREATE TABLE lifecycle_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES lifecycle_jobs(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lifecycle_approvals_job
    ON lifecycle_approvals (job_id, created_at);
