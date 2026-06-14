DROP INDEX IF EXISTS idx_certificates_cert_scope;
ALTER TABLE certificates DROP COLUMN IF EXISTS cert_scope;
DROP TYPE IF EXISTS cert_scope;
