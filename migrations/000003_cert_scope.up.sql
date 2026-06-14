CREATE TYPE cert_scope AS ENUM ('internal', 'external');

ALTER TABLE certificates
    ADD COLUMN cert_scope cert_scope NOT NULL DEFAULT 'external';

CREATE INDEX idx_certificates_cert_scope ON certificates(cert_scope);
