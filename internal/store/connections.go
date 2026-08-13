package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrConnectionsKeyMissing is returned when UpsertConnection would persist new
// secrets but CLM_CONNECTIONS_KEY is missing or invalid. Callers map this to 503.
var ErrConnectionsKeyMissing = errors.New("connections encryption key missing or invalid")

// Connection is a persisted Vault, AAP, or EDA integration. Metadata never
// contains secrets. Secret material lives in SecretsEnc (AES-256-GCM) and is
// omitted from JSON; use DecryptSecrets for runtime/API resolution only.
type Connection struct {
	Target     string          `json:"target"`
	Metadata   json.RawMessage `json:"metadata"`
	SecretsEnc []byte          `json:"-"`
	SecretsSet bool            `json:"secrets_set"`
	Source     string          `json:"source"`
	UpdatedAt  time.Time       `json:"updated_at"`
	UpdatedBy  string          `json:"updated_by"`
}

// UpsertConnection writes one target's metadata and optionally secret material.
// Keys listed in keepSecrets (and empty incoming secret values) leave the
// previous ciphertext unchanged. source is set to "db". Missing or invalid
// CLM_CONNECTIONS_KEY when new secrets would be persisted returns
// ErrConnectionsKeyMissing. Never logs plaintext or ciphertext.
func (s *Store) UpsertConnection(ctx context.Context, target string, metadata json.RawMessage, secrets map[string]string, keepSecrets []string, actor string) error {
	existing, err := s.getConnection(ctx, target)
	if err != nil {
		return err
	}
	row, err := prepareConnectionUpsert(s.connectionsKey, existing, target, metadata, secrets, keepSecrets, actor)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO connections (target, metadata, secrets_enc, secrets_set, source, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6)
		ON CONFLICT (target) DO UPDATE SET
			metadata = EXCLUDED.metadata,
			secrets_enc = EXCLUDED.secrets_enc,
			secrets_set = EXCLUDED.secrets_set,
			source = EXCLUDED.source,
			updated_at = NOW(),
			updated_by = EXCLUDED.updated_by
	`, row.Target, row.Metadata, row.SecretsEnc, row.SecretsSet, row.Source, nullStr(row.UpdatedBy))
	return err
}

// GetConnections returns all connection rows. SecretsEnc is populated for
// DecryptSecrets but omitted from JSON.
func (s *Store) GetConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT target, metadata, secrets_enc, secrets_set, source, updated_at, COALESCE(updated_by, '')
		FROM connections
		ORDER BY target
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Connection{}
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.Target, &c.Metadata, &c.SecretsEnc, &c.SecretsSet, &c.Source, &c.UpdatedAt, &c.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DecryptSecrets opens SecretsEnc for API/runtime use. The map must never be
// serialized to HTTP. A nil or empty ciphertext returns an empty map.
func (s *Store) DecryptSecrets(row Connection) (map[string]string, error) {
	if len(row.SecretsEnc) == 0 {
		return map[string]string{}, nil
	}
	key, err := parseConnectionsKey(s.connectionsKey)
	if err != nil {
		return nil, err
	}
	return openSecrets(key, row.SecretsEnc)
}

func (s *Store) getConnection(ctx context.Context, target string) (*Connection, error) {
	var c Connection
	err := s.pool.QueryRow(ctx, `
		SELECT target, metadata, secrets_enc, secrets_set, source, updated_at, COALESCE(updated_by, '')
		FROM connections WHERE target = $1
	`, target).Scan(&c.Target, &c.Metadata, &c.SecretsEnc, &c.SecretsSet, &c.Source, &c.UpdatedAt, &c.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func prepareConnectionUpsert(keyMaterial string, existing *Connection, target string, metadata json.RawMessage, secrets map[string]string, keepSecrets []string, actor string) (Connection, error) {
	if target != "vault" && target != "aap" && target != "eda" {
		return Connection{}, fmt.Errorf("invalid connection target %q", target)
	}
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}

	row := Connection{
		Target:    target,
		Metadata:  metadata,
		Source:    "db",
		UpdatedAt: time.Now().UTC(),
		UpdatedBy: actor,
	}
	if existing != nil {
		row.SecretsEnc = existing.SecretsEnc
		row.SecretsSet = existing.SecretsSet
	}

	if !hasNewSecrets(secrets, keepSecrets) {
		return row, nil
	}

	key, err := parseConnectionsKey(keyMaterial)
	if err != nil {
		return Connection{}, err
	}

	previous := map[string]string{}
	if existing != nil && len(existing.SecretsEnc) > 0 {
		previous, err = openSecrets(key, existing.SecretsEnc)
		if err != nil {
			return Connection{}, err
		}
	}
	merged := mergeSecrets(previous, secrets, keepSecrets)
	if len(merged) == 0 {
		row.SecretsEnc = nil
		row.SecretsSet = false
		return row, nil
	}
	ct, err := sealSecrets(key, merged)
	if err != nil {
		return Connection{}, err
	}
	row.SecretsEnc = ct
	row.SecretsSet = true
	return row, nil
}

func hasNewSecrets(incoming map[string]string, keep []string) bool {
	held := heldSecrets(keep)
	for k, v := range incoming {
		if v == "" {
			continue
		}
		if _, ok := held[k]; ok {
			continue
		}
		return true
	}
	return false
}

func mergeSecrets(previous, incoming map[string]string, keep []string) map[string]string {
	out := map[string]string{}
	for k, v := range previous {
		out[k] = v
	}
	held := heldSecrets(keep)
	for k, v := range incoming {
		if _, ok := held[k]; ok {
			continue
		}
		if v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func heldSecrets(keep []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		set[k] = struct{}{}
	}
	return set
}

func parseConnectionsKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, ErrConnectionsKeyMissing
	}
	if len(raw) == 64 {
		key, err := hex.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, ErrConnectionsKeyMissing
		}
		return key, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, ErrConnectionsKeyMissing
}

func sealSecrets(key []byte, secrets map[string]string) ([]byte, error) {
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrConnectionsKeyMissing
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func openSecrets(key []byte, ciphertext []byte) (map[string]string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrConnectionsKeyMissing
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("connections secrets ciphertext is truncated")
	}
	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return nil, err
	}
	return out, nil
}
