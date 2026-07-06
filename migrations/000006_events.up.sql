-- Event outbox (ADR 0001, event Phase 1). Certificate lifecycle events are
-- written here in the same transaction as the state change that produced them,
-- so a committed change can never lose its event. A dispatcher (Phase 1b) later
-- delivers undelivered rows to Ansible EDA.
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

-- Partial index for the dispatcher's "next undelivered, oldest first" scan.
CREATE INDEX idx_events_undelivered ON events (created_at) WHERE delivered_at IS NULL;
