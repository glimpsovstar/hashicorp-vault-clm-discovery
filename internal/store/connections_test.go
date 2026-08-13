package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testHexKey() string {
	return strings.Repeat("ab", 32) // 64 hex chars → 32 bytes
}

func testRawKey() string {
	return strings.Repeat("K", 32)
}

func TestParseConnectionsKeyAccepts32ByteRaw(t *testing.T) {
	key, err := parseConnectionsKey(testRawKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len(key) = %d, want 32", len(key))
	}
	if string(key) != testRawKey() {
		t.Fatalf("raw key was not used as-is")
	}
}

func TestParseConnectionsKeyAccepts64CharHex(t *testing.T) {
	key, err := parseConnectionsKey(testHexKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len(key) = %d, want 32", len(key))
	}
}

func TestParseConnectionsKeyRejectsMissingAndInvalid(t *testing.T) {
	cases := []string{"", "short", strings.Repeat("g", 64), strings.Repeat("ab", 8)}
	for _, in := range cases {
		_, err := parseConnectionsKey(in)
		if !errors.Is(err, ErrConnectionsKeyMissing) {
			t.Fatalf("parseConnectionsKey(%q) err = %v, want ErrConnectionsKeyMissing", in, err)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := parseConnectionsKey(testHexKey())
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"token": "s.unit-test-token", "role_id": "role-1"}
	ct, err := sealSecrets(key, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
	got, err := openSecrets(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if got["token"] != secrets["token"] || got["role_id"] != secrets["role_id"] {
		t.Fatalf("opened secrets = %#v, want %#v", got, secrets)
	}
}

func TestMergeSecretsKeepSecretsLeavesPrevious(t *testing.T) {
	previous := map[string]string{"token": "s.kept", "role_id": "old-role"}
	incoming := map[string]string{"token": "", "role_id": "new-role"}
	got := mergeSecrets(previous, incoming, []string{"token"})
	if got["token"] != "s.kept" {
		t.Fatalf("token = %q, want previous value", got["token"])
	}
	if got["role_id"] != "new-role" {
		t.Fatalf("role_id = %q, want incoming value", got["role_id"])
	}
}

func TestPrepareConnectionUpsertEncryptDecryptRoundTrip(t *testing.T) {
	meta := json.RawMessage(`{"addr":"https://vault.example:8200"}`)
	row, err := prepareConnectionUpsert(testHexKey(), nil, "vault", meta, map[string]string{"token": "s.round-trip"}, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if row.Target != "vault" {
		t.Fatalf("Target = %q", row.Target)
	}
	if row.Source != "db" {
		t.Fatalf("Source = %q, want db", row.Source)
	}
	if !row.SecretsSet {
		t.Fatal("SecretsSet = false, want true")
	}
	if row.UpdatedBy != "alice" {
		t.Fatalf("UpdatedBy = %q", row.UpdatedBy)
	}
	if len(row.SecretsEnc) == 0 {
		t.Fatal("SecretsEnc empty after upsert prepare")
	}

	st := &Store{connectionsKey: testHexKey()}
	got, err := st.DecryptSecrets(row)
	if err != nil {
		t.Fatal(err)
	}
	if got["token"] != "s.round-trip" {
		t.Fatalf("decrypted token = %q", got["token"])
	}
}

func TestPrepareConnectionUpsertKeepSecretsLeavesCiphertext(t *testing.T) {
	meta := json.RawMessage(`{"addr":"https://vault.example:8200"}`)
	first, err := prepareConnectionUpsert(testHexKey(), nil, "vault", meta, map[string]string{"token": "s.original"}, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	meta2 := json.RawMessage(`{"addr":"https://vault.example:8200","namespace":"admin"}`)
	second, err := prepareConnectionUpsert(testHexKey(), &first, "vault", meta2, map[string]string{"token": ""}, []string{"token"}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.SecretsEnc, second.SecretsEnc) {
		t.Fatal("omitted token should leave previous ciphertext unchanged")
	}
	if second.UpdatedBy != "bob" {
		t.Fatalf("UpdatedBy = %q, want bob", second.UpdatedBy)
	}
	st := &Store{connectionsKey: testHexKey()}
	got, err := st.DecryptSecrets(second)
	if err != nil {
		t.Fatal(err)
	}
	if got["token"] != "s.original" {
		t.Fatalf("token = %q, want s.original", got["token"])
	}
}

func TestPrepareConnectionUpsertMissingKeyReturnsTypedError(t *testing.T) {
	meta := json.RawMessage(`{}`)
	_, err := prepareConnectionUpsert("", nil, "aap", meta, map[string]string{"token": "new-secret"}, nil, "alice")
	if !errors.Is(err, ErrConnectionsKeyMissing) {
		t.Fatalf("err = %v, want ErrConnectionsKeyMissing", err)
	}

	_, err = prepareConnectionUpsert("not-a-valid-key", nil, "aap", meta, map[string]string{"token": "new-secret"}, nil, "alice")
	if !errors.Is(err, ErrConnectionsKeyMissing) {
		t.Fatalf("invalid key err = %v, want ErrConnectionsKeyMissing", err)
	}
}

func TestPrepareConnectionUpsertKeepSecretsDoesNotRequireKey(t *testing.T) {
	meta := json.RawMessage(`{}`)
	first, err := prepareConnectionUpsert(testHexKey(), nil, "eda", meta, map[string]string{"token": "s.eda"}, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareConnectionUpsert("", &first, "eda", json.RawMessage(`{"webhook_url":"https://eda.example/hook"}`), nil, []string{"token"}, "bob")
	if err != nil {
		t.Fatalf("metadata-only upsert should not require key: %v", err)
	}
	if !bytes.Equal(first.SecretsEnc, second.SecretsEnc) {
		t.Fatal("ciphertext changed on keep-only upsert")
	}
}

func TestConnectionJSONOmitsSecretsEnc(t *testing.T) {
	row := Connection{
		Target:     "vault",
		Metadata:   json.RawMessage(`{"addr":"https://vault.example:8200"}`),
		SecretsEnc: []byte("ciphertext-must-not-appear"),
		SecretsSet: true,
		Source:     "db",
		UpdatedAt:  time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		UpdatedBy:  "alice",
	}
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("SecretsEnc")) || bytes.Contains(data, []byte("secrets_enc")) {
		t.Fatalf("JSON included secrets field: %s", data)
	}
	if bytes.Contains(data, []byte("ciphertext-must-not-appear")) {
		t.Fatalf("JSON leaked ciphertext: %s", data)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["secrets_enc"]; ok {
		t.Fatal("decoded JSON has secrets_enc")
	}
}
