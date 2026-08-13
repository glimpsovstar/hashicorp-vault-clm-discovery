-- Operator-configured Vault / AAP / EDA connections. Metadata is non-secret
-- JSON; secret material is AES-256-GCM sealed in secrets_enc under
-- CLM_CONNECTIONS_KEY. source=env means Compose/12-factor still applies;
-- a UI save sets source=db and overlays env for that target.
CREATE TABLE connections (
    target      TEXT PRIMARY KEY CHECK (target IN ('vault', 'aap', 'eda')),
    metadata    JSONB NOT NULL DEFAULT '{}',
    secrets_enc BYTEA,
    secrets_set BOOLEAN NOT NULL DEFAULT FALSE,
    source      TEXT NOT NULL DEFAULT 'env' CHECK (source IN ('env', 'db')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  TEXT
);
