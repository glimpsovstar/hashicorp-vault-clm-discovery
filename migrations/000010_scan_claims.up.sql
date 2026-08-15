-- M4 durable scan queue: claim columns so replicas share work via SKIP LOCKED.
ALTER TABLE scans
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claimed_at TIMESTAMPTZ;

CREATE INDEX idx_scans_claimable
    ON scans (status, claimed_at NULLS FIRST)
    WHERE status IN ('pending', 'running');

-- Outbox claim leases so two EDA dispatchers cannot double-deliver the same event.
ALTER TABLE events
    ADD COLUMN lease_owner TEXT,
    ADD COLUMN lease_expires_at TIMESTAMPTZ;

CREATE INDEX idx_events_undelivered_lease
    ON events (created_at)
    WHERE delivered_at IS NULL;
