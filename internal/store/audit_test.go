package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditInsertSQLIsAppendOnlyInsert(t *testing.T) {
	t.Parallel()

	q := strings.ToLower(auditInsertSQL)
	if !strings.Contains(q, "insert into audit_events") {
		t.Fatalf("expected INSERT INTO audit_events, got %s", auditInsertSQL)
	}
	for _, col := range []string{
		"actor_id", "actor_type", "role", "action", "target_type", "target_id",
		"decision", "request_id", "remote_ip", "payload",
	} {
		if !strings.Contains(q, col) {
			t.Fatalf("missing column %s in %s", col, auditInsertSQL)
		}
	}
	if strings.Contains(q, "update ") || strings.Contains(q, "delete ") {
		t.Fatal("audit SQL must be insert-only")
	}
	if strings.Contains(q, " into events ") {
		t.Fatal("must not write the EDA events outbox")
	}
}

func TestAppendAuditNilPoolIsNoop(t *testing.T) {
	t.Parallel()

	st := &Store{}
	err := st.AppendAudit(context.Background(), AuditEvent{
		Action:   "import_ca",
		Decision: "allow",
		ActorID:  "static:vault_import_admin",
	})
	if err != nil {
		t.Fatalf("nil pool should no-op, got %v", err)
	}
}

func TestMarshalAuditPayloadRedactsSecretsAndPEM(t *testing.T) {
	t.Parallel()

	raw, err := marshalAuditPayload(map[string]any{
		"mount":           "pki",
		"token":           "s.super-secret",
		"pem":             "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
		"Authorization":   "Bearer tok_platform",
		"role_id":         "role-uuid",
		"secret_id":       "secret-uuid",
		"aap_token":       "aap-secret",
		"vault_token":     "hvs.xxx",
		"secrets_enc":     []byte("ciphertext"),
		"pem_bundle":      "-----BEGIN CERTIFICATE-----\nY\n-----END CERTIFICATE-----",
		"ca_chain":        []string{"-----BEGIN CERTIFICATE-----\nZ\n-----END CERTIFICATE-----"},
		"leaf":            "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
		"nested":          map[string]any{"token": "nested-secret", "mount": "pki_int"},
		"authorization":   "Bearer also-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("s.super-secret")) ||
		bytes.Contains(raw, []byte("tok_platform")) ||
		bytes.Contains(raw, []byte("role-uuid")) ||
		bytes.Contains(raw, []byte("secret-uuid")) ||
		bytes.Contains(raw, []byte("aap-secret")) ||
		bytes.Contains(raw, []byte("hvs.xxx")) ||
		bytes.Contains(raw, []byte("nested-secret")) ||
		bytes.Contains(raw, []byte("also-secret")) ||
		bytes.Contains(raw, []byte("ciphertext")) {
		t.Fatalf("payload leaked a secret: %s", raw)
	}
	if bytes.Contains(raw, []byte("BEGIN CERTIFICATE")) || bytes.Contains(raw, []byte("-----BEGIN")) {
		t.Fatalf("payload leaked PEM: %s", raw)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["mount"] != "pki" {
		t.Fatalf("safe field mount = %v, want pki", decoded["mount"])
	}
	nested, _ := decoded["nested"].(map[string]any)
	if nested["mount"] != "pki_int" {
		t.Fatalf("nested safe field lost: %#v", nested)
	}
	for _, banned := range []string{"token", "pem", "Authorization", "authorization", "role_id", "secret_id", "aap_token", "vault_token", "secrets_enc", "pem_bundle", "ca_chain"} {
		if _, ok := decoded[banned]; ok {
			t.Fatalf("banned key %q still present: %s", banned, raw)
		}
	}
}

func TestMarshalAuditPayloadEmptyIsObject(t *testing.T) {
	t.Parallel()

	raw, err := marshalAuditPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("nil payload = %s, want {}", raw)
	}
}
