package store

import (
	"context"
	"encoding/json"
	"strings"
)

// AuditEvent is a control-plane audit row. It is distinct from the EDA
// events outbox (Event / table events).
type AuditEvent struct {
	ActorID    string
	ActorType  string
	Role       string
	Action     string
	TargetType string
	TargetID   string
	Decision   string
	RequestID  string
	RemoteIP   string
	Payload    map[string]any
}

// auditInsertSQL is the append-only write. at/id use table defaults.
const auditInsertSQL = `
	INSERT INTO audit_events (
		actor_id, actor_type, role, action, target_type, target_id,
		decision, request_id, remote_ip, payload
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`

// AppendAudit inserts one audit row. A nil store or pool is a no-op so API
// unit tests without Postgres do not panic.
func (s *Store) AppendAudit(ctx context.Context, ev AuditEvent) error {
	if s == nil || s.pool == nil {
		return nil
	}
	payload, err := marshalAuditPayload(ev.Payload)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, auditInsertSQL,
		ev.ActorID, ev.ActorType, ev.Role, ev.Action, ev.TargetType, ev.TargetID,
		ev.Decision, ev.RequestID, ev.RemoteIP, payload)
	return err
}

func marshalAuditPayload(payload map[string]any) ([]byte, error) {
	if payload == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(redactAuditValue(payload))
}

func redactAuditValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if sensitiveAuditKey(k) {
				continue
			}
			out[k] = redactAuditValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactAuditValue(item)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactAuditValue(item)
		}
		return out
	case string:
		if looksLikePEM(x) {
			return "[redacted]"
		}
		return x
	default:
		return v
	}
}

func sensitiveAuditKey(k string) bool {
	n := strings.ToLower(strings.TrimSpace(k))
	n = strings.ReplaceAll(n, "-", "_")
	switch n {
	case "authorization", "token", "secret", "secret_id", "role_id",
		"password", "pem", "pem_bundle", "ca_chain", "secrets", "secrets_enc",
		"aap_token", "vault_token", "api_key", "bearer":
		return true
	}
	if strings.Contains(n, "token") || strings.Contains(n, "secret") || strings.Contains(n, "password") {
		return true
	}
	if strings.HasSuffix(n, "_pem") || n == "pem" {
		return true
	}
	return false
}

func looksLikePEM(s string) bool {
	return strings.Contains(s, "-----BEGIN")
}
