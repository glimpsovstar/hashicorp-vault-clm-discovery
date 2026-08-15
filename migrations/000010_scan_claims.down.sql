ALTER TABLE events
    DROP COLUMN IF EXISTS lease_owner,
    DROP COLUMN IF EXISTS lease_expires_at;

DROP INDEX IF EXISTS idx_events_undelivered_lease;

DROP INDEX IF EXISTS idx_scans_claimable;

ALTER TABLE scans
    DROP COLUMN IF EXISTS claimed_by,
    DROP COLUMN IF EXISTS claimed_at;
