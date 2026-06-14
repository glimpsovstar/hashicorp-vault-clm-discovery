-- Scan diagnostics: separate expansion warnings from fatal errors and persist probe/upsert stats.
ALTER TABLE scans
    ADD COLUMN expansion_warnings TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN targets_succeeded INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN targets_failed INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN upsert_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN failure_samples JSONB NOT NULL DEFAULT '[]';
