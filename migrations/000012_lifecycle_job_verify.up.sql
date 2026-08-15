-- Migrate / pending-verify (#87): backoff schedule + timeout on lifecycle jobs.
ALTER TABLE lifecycle_jobs
    ADD COLUMN IF NOT EXISTS next_verify_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS timeout_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    ADD COLUMN IF NOT EXISTS verify_attempt INT NOT NULL DEFAULT 0;

-- Allow pending_verify / timed_out; keep verifying/verify_failed for M2 compatibility.
ALTER TABLE lifecycle_jobs DROP CONSTRAINT IF EXISTS lifecycle_jobs_status_check;
ALTER TABLE lifecycle_jobs ADD CONSTRAINT lifecycle_jobs_status_check
    CHECK (status IN (
        'pending_approval', 'launching', 'aap_pending', 'aap_running', 'aap_successful',
        'verifying', 'verify_failed',
        'pending_verify', 'verified', 'timed_out', 'failed'
    ));

ALTER TABLE lifecycle_jobs DROP CONSTRAINT IF EXISTS lifecycle_jobs_kind_check;
ALTER TABLE lifecycle_jobs ADD CONSTRAINT lifecycle_jobs_kind_check
    CHECK (kind IN ('migrate', 'renew'));

CREATE INDEX IF NOT EXISTS lifecycle_jobs_verify_due_idx
    ON lifecycle_jobs (next_verify_at)
    WHERE status = 'pending_verify';
