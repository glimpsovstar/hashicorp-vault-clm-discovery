DROP INDEX IF EXISTS idx_certificates_pqc_tag;
DROP INDEX IF EXISTS idx_certificates_risk_score;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_pqc_tag_check;
ALTER TABLE certificates DROP COLUMN IF EXISTS risk_reasons;
ALTER TABLE certificates DROP COLUMN IF EXISTS pqc_tag;

DROP TABLE IF EXISTS waivers;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS policy_versions;
