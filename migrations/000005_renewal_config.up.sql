-- Per-certificate renewal configuration (Mode C auto-renewal). Stored as JSONB
-- so it is easy to extend; it is set when a cert is tracked in CLM and preserved
-- across rescans (UpsertCertificate's ON CONFLICT does not touch this column).
ALTER TABLE certificates ADD COLUMN renewal_config JSONB;
