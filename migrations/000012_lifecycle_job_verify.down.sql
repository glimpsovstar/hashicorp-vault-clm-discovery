DROP INDEX IF EXISTS lifecycle_jobs_verify_due_idx;

ALTER TABLE lifecycle_jobs DROP CONSTRAINT IF EXISTS lifecycle_jobs_kind_check;
ALTER TABLE lifecycle_jobs DROP CONSTRAINT IF EXISTS lifecycle_jobs_status_check;

ALTER TABLE lifecycle_jobs
    DROP COLUMN IF EXISTS verify_attempt,
    DROP COLUMN IF EXISTS timeout_at,
    DROP COLUMN IF EXISTS next_verify_at;
