CREATE TYPE cert_status AS ENUM ('valid', 'expiring_soon', 'expired', 'revoked');
CREATE TYPE chain_status AS ENUM ('complete', 'self_signed', 'incomplete', 'untrusted_root');
CREATE TYPE managed_status AS ENUM ('managed_in_vault', 'unmanaged', 'imported');
CREATE TYPE remediation_state AS ENUM ('none', 'flagged', 'import_requested', 'reissue_requested');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed');

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL DEFAULT 'network',
    status scan_status NOT NULL DEFAULT 'pending',
    cidrs TEXT[] NOT NULL,
    ports INTEGER[] NOT NULL,
    concurrency INTEGER NOT NULL DEFAULT 50,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    targets_total INTEGER NOT NULL DEFAULT 0,
    targets_scanned INTEGER NOT NULL DEFAULT 0,
    certs_found INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    subject_cn TEXT,
    subject_alt_names JSONB NOT NULL DEFAULT '[]',
    issuer_dn TEXT NOT NULL,
    authority_key_id TEXT,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    key_type TEXT NOT NULL,
    key_bits INTEGER NOT NULL,
    signature_algorithm TEXT NOT NULL,
    is_ca BOOLEAN NOT NULL DEFAULT FALSE,
    key_usage TEXT[] NOT NULL DEFAULT '{}',
    ext_key_usage TEXT[] NOT NULL DEFAULT '{}',
    pem TEXT NOT NULL,
    days_until_expiry INTEGER NOT NULL DEFAULT 0,
    status cert_status NOT NULL DEFAULT 'valid',
    revocation_status TEXT,
    revocation_checked_at TIMESTAMPTZ,
    crl_distribution_points TEXT[] NOT NULL DEFAULT '{}',
    ocsp_servers TEXT[] NOT NULL DEFAULT '{}',
    first_discovered TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname_matches_san BOOLEAN NOT NULL DEFAULT TRUE,
    chain_status chain_status NOT NULL DEFAULT 'incomplete',
    managed_status managed_status NOT NULL DEFAULT 'unmanaged',
    vault_issuer_ref TEXT,
    vault_pki_mount TEXT,
    owner TEXT,
    team TEXT,
    environment TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0,
    remediation_state remediation_state NOT NULL DEFAULT 'none',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);
CREATE INDEX idx_certificates_subject_cn ON certificates(subject_cn);

CREATE TABLE certificate_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    hostname TEXT,
    sni TEXT,
    tls_version TEXT,
    cipher_suite TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (certificate_id, scan_id, ip, port, sni)
);

CREATE INDEX idx_observations_certificate ON certificate_observations(certificate_id);
CREATE INDEX idx_observations_scan ON certificate_observations(scan_id);

CREATE TABLE issuers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    serial_number TEXT NOT NULL,
    subject_cn TEXT,
    subject_alt_names JSONB NOT NULL DEFAULT '[]',
    issuer_dn TEXT NOT NULL,
    authority_key_id TEXT,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    key_type TEXT NOT NULL,
    key_bits INTEGER NOT NULL,
    signature_algorithm TEXT NOT NULL,
    is_ca BOOLEAN NOT NULL DEFAULT TRUE,
    key_usage TEXT[] NOT NULL DEFAULT '{}',
    ext_key_usage TEXT[] NOT NULL DEFAULT '{}',
    pem TEXT NOT NULL,
    days_until_expiry INTEGER NOT NULL DEFAULT 0,
    status cert_status NOT NULL DEFAULT 'valid',
    issuer_name TEXT,
    issuer_id TEXT,
    ca_chain TEXT[] NOT NULL DEFAULT '{}',
    vault_issuer_ref TEXT,
    vault_pki_mount TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_issuers_fingerprint ON issuers(fingerprint_sha256);
