ALTER TABLE scans
    DROP COLUMN IF EXISTS failure_samples,
    DROP COLUMN IF EXISTS upsert_failures,
    DROP COLUMN IF EXISTS targets_failed,
    DROP COLUMN IF EXISTS targets_succeeded,
    DROP COLUMN IF EXISTS expansion_warnings;
