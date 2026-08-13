package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/settings"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

const (
	rolePlatformAdmin = "platform_admin"
	roleRemediator    = "remediator"
)

type settingsActorKey struct{}

// ContextWithActor injects a Settings RBAC role for tests (and future M1
// middleware). Production without M1 has no actor unless CLM_INSECURE_NO_AUTH.
func ContextWithActor(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, settingsActorKey{}, role)
}

// connectionsStore is the Settings persistence surface. Production uses
// *store.Store; tests inject a fake so handlers do not need Postgres.
type connectionsStore interface {
	GetConnections(ctx context.Context) ([]store.Connection, error)
	DecryptSecrets(row store.Connection) (map[string]string, error)
	UpsertConnection(ctx context.Context, target string, metadata json.RawMessage, secrets map[string]string, keepSecrets []string, actor string) error
}

// secretField distinguishes omit, empty string (keep), explicit JSON null
// (clear → fall back to env), and a new value.
type secretField struct {
	present bool
	null    bool
	value   string
}

func (s *secretField) UnmarshalJSON(data []byte) error {
	s.present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		s.null = true
		return nil
	}
	return json.Unmarshal(data, &s.value)
}

type connectionsWrite struct {
	Vault *vaultWrite `json:"vault"`
	AAP   *aapWrite   `json:"aap"`
	EDA   *edaWrite   `json:"eda"`
}

type vaultWrite struct {
	Deployment *string     `json:"deployment"`
	Addr       *string     `json:"addr"`
	Namespace  *string     `json:"namespace"`
	AuthMethod *string     `json:"auth_method"`
	Token      secretField `json:"token"`
	RoleID     secretField `json:"role_id"`
	SecretID   secretField `json:"secret_id"`
}

type aapWrite struct {
	URL           *string     `json:"url"`
	RenewTemplate *string     `json:"renew_template"`
	RenewWorkflow *bool       `json:"renew_workflow"`
	SkipTLSVerify *bool       `json:"skip_tls_verify"`
	DefaultMount  *string     `json:"default_mount"`
	Token         secretField `json:"token"`
}

type edaWrite struct {
	WebhookURL *string     `json:"webhook_url"`
	Token      secretField `json:"token"`
}

type vaultStoredMeta struct {
	Deployment string `json:"deployment"`
	Addr       string `json:"addr"`
	Namespace  string `json:"namespace"`
	AuthMethod string `json:"auth_method"`
}

type aapStoredMeta struct {
	URL           string `json:"url"`
	RenewTemplate string `json:"renew_template"`
	RenewWorkflow bool   `json:"renew_workflow"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	DefaultMount  string `json:"default_mount"`
}

type edaStoredMeta struct {
	WebhookURL string `json:"webhook_url"`
}

func (s *Server) requestActor(r *http.Request) string {
	if role, ok := r.Context().Value(settingsActorKey{}).(string); ok && role != "" {
		return role
	}
	if s.actor != "" {
		return s.actor
	}
	if s.cfg.InsecureNoAuth {
		return rolePlatformAdmin
	}
	return ""
}

func (s *Server) requireSettingsRead(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := s.requestActor(r)
	if actor == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	if actor != rolePlatformAdmin && actor != roleRemediator {
		writeError(w, r, http.StatusForbidden, "forbidden")
		return "", false
	}
	return actor, true
}

func (s *Server) requireSettingsWrite(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := s.requestActor(r)
	if actor == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	if actor != rolePlatformAdmin {
		writeError(w, r, http.StatusForbidden, "forbidden")
		return "", false
	}
	return actor, true
}

// handleGetConnections returns the masked Connections view. Secrets never appear.
func (s *Server) handleGetConnections(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSettingsRead(w, r); !ok {
		return
	}
	s.writeConnectionsView(w, r)
}

// handlePutConnections replaces all three targets' metadata. Secrets follow
// write-only rules (omit/empty keep; JSON null clears).
func (s *Server) handlePutConnections(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireSettingsWrite(w, r)
	if !ok {
		return
	}
	req, ok := decodeConnectionsWrite(w, r)
	if !ok {
		return
	}
	if req.Vault == nil || req.AAP == nil || req.EDA == nil {
		writeError(w, r, http.StatusBadRequest, "vault, aap, and eda are required")
		return
	}
	if err := validateConnectionsWrite(req); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if !s.upsertTarget(w, r, "vault", req.Vault, nil, true, actor) {
		return
	}
	if !s.upsertTarget(w, r, "aap", req.AAP, nil, true, actor) {
		return
	}
	if !s.upsertTarget(w, r, "eda", req.EDA, nil, true, actor) {
		return
	}
	s.writeConnectionsView(w, r)
}

// handlePatchConnections partially updates one or more targets. Omitted or
// empty secret fields keep stored values; JSON null clears them.
func (s *Server) handlePatchConnections(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireSettingsWrite(w, r)
	if !ok {
		return
	}
	req, ok := decodeConnectionsWrite(w, r)
	if !ok {
		return
	}
	if req.Vault == nil && req.AAP == nil && req.EDA == nil {
		writeError(w, r, http.StatusBadRequest, "at least one of vault, aap, or eda is required")
		return
	}
	if err := validateConnectionsWrite(req); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.connectionByTarget(r.Context())
	if err != nil {
		s.writeServerError(w, r, err, "failed to load connections")
		return
	}
	if req.Vault != nil {
		if !s.upsertTarget(w, r, "vault", req.Vault, existing["vault"], false, actor) {
			return
		}
	}
	if req.AAP != nil {
		if !s.upsertTarget(w, r, "aap", req.AAP, existing["aap"], false, actor) {
			return
		}
	}
	if req.EDA != nil {
		if !s.upsertTarget(w, r, "eda", req.EDA, existing["eda"], false, actor) {
			return
		}
	}
	s.writeConnectionsView(w, r)
}

func decodeConnectionsWrite(w http.ResponseWriter, r *http.Request) (connectionsWrite, bool) {
	var req connectionsWrite
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return connectionsWrite{}, false
	}
	return req, true
}

func validateConnectionsWrite(req connectionsWrite) error {
	if req.Vault != nil {
		if req.Vault.Deployment != nil && !validDeployment(*req.Vault.Deployment) {
			return errors.New("invalid deployment")
		}
		if req.Vault.AuthMethod != nil && !validAuthMethod(*req.Vault.AuthMethod) {
			return errors.New("invalid auth_method")
		}
	}
	return nil
}

func validDeployment(d string) bool {
	return d == "" || d == "self_managed" || d == "hcp_dedicated"
}

func validAuthMethod(m string) bool {
	return m == "" || m == "token" || m == "approle"
}

func (s *Server) upsertTarget(w http.ResponseWriter, r *http.Request, target string, patch any, existing *store.Connection, replace bool, actor string) bool {
	var (
		meta    json.RawMessage
		secrets map[string]string
		keep    []string
		err     error
	)
	var prev json.RawMessage
	if existing != nil {
		prev = existing.Metadata
	}
	switch t := patch.(type) {
	case *vaultWrite:
		meta, err = applyVaultMeta(prev, *t, replace)
		secrets, keep = collectSecrets(map[string]secretField{
			"token":     t.Token,
			"role_id":   t.RoleID,
			"secret_id": t.SecretID,
		})
	case *aapWrite:
		meta, err = applyAAPMeta(prev, *t, replace)
		secrets, keep = collectSecrets(map[string]secretField{"token": t.Token})
	case *edaWrite:
		meta, err = applyEDAMeta(prev, *t, replace)
		secrets, keep = collectSecrets(map[string]secretField{"token": t.Token})
	default:
		writeError(w, r, http.StatusBadRequest, "invalid target")
		return false
	}
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid connection metadata")
		return false
	}
	if err := s.connections.UpsertConnection(r.Context(), target, meta, secrets, keep, actor); err != nil {
		if errors.Is(err, store.ErrConnectionsKeyMissing) {
			writeError(w, r, http.StatusServiceUnavailable, "connections encryption key missing; cannot persist secrets")
			return false
		}
		s.writeServerError(w, r, err, "failed to save connection")
		return false
	}
	return true
}

func collectSecrets(fields map[string]secretField) (map[string]string, []string) {
	secrets := map[string]string{}
	keep := []string{}
	for key, f := range fields {
		if !f.present || (f.value == "" && !f.null) {
			keep = append(keep, key)
			continue
		}
		if f.null {
			secrets[key] = ""
			continue
		}
		secrets[key] = f.value
	}
	return secrets, keep
}

func applyVaultMeta(existing json.RawMessage, patch vaultWrite, replace bool) (json.RawMessage, error) {
	cur := vaultStoredMeta{Deployment: "self_managed", AuthMethod: "token"}
	if !replace && len(existing) > 0 {
		if err := json.Unmarshal(existing, &cur); err != nil {
			return nil, err
		}
	}
	if patch.Deployment != nil {
		cur.Deployment = *patch.Deployment
	}
	if patch.Addr != nil {
		cur.Addr = *patch.Addr
	}
	if patch.Namespace != nil {
		cur.Namespace = *patch.Namespace
	}
	if patch.AuthMethod != nil {
		cur.AuthMethod = *patch.AuthMethod
	}
	if cur.Deployment == "" {
		cur.Deployment = "self_managed"
	}
	if cur.AuthMethod == "" {
		cur.AuthMethod = "token"
	}
	return json.Marshal(cur)
}

func applyAAPMeta(existing json.RawMessage, patch aapWrite, replace bool) (json.RawMessage, error) {
	cur := aapStoredMeta{}
	if !replace && len(existing) > 0 {
		if err := json.Unmarshal(existing, &cur); err != nil {
			return nil, err
		}
	}
	if patch.URL != nil {
		cur.URL = *patch.URL
	}
	if patch.RenewTemplate != nil {
		cur.RenewTemplate = *patch.RenewTemplate
	}
	if patch.RenewWorkflow != nil {
		cur.RenewWorkflow = *patch.RenewWorkflow
	}
	if patch.SkipTLSVerify != nil {
		cur.SkipTLSVerify = *patch.SkipTLSVerify
	}
	if patch.DefaultMount != nil {
		cur.DefaultMount = *patch.DefaultMount
	}
	return json.Marshal(cur)
}

func applyEDAMeta(existing json.RawMessage, patch edaWrite, replace bool) (json.RawMessage, error) {
	cur := edaStoredMeta{}
	if !replace && len(existing) > 0 {
		if err := json.Unmarshal(existing, &cur); err != nil {
			return nil, err
		}
	}
	if patch.WebhookURL != nil {
		cur.WebhookURL = *patch.WebhookURL
	}
	return json.Marshal(cur)
}

func (s *Server) connectionByTarget(ctx context.Context) (map[string]*store.Connection, error) {
	rows, err := s.connections.GetConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]*store.Connection{}
	for i := range rows {
		row := rows[i]
		out[row.Target] = &row
	}
	return out, nil
}

func (s *Server) writeConnectionsView(w http.ResponseWriter, r *http.Request) {
	if s.connections == nil {
		s.writeServerError(w, r, errors.New("connections store not configured"), "failed to load connections")
		return
	}
	rows, err := s.connections.GetConnections(r.Context())
	if err != nil {
		s.writeServerError(w, r, err, "failed to load connections")
		return
	}
	secrets := map[string]map[string]string{}
	for _, row := range rows {
		sec, err := s.connections.DecryptSecrets(row)
		if err != nil {
			s.writeServerError(w, r, err, "failed to resolve connections")
			return
		}
		secrets[row.Target] = sec
	}
	resolved, err := settings.Resolve(s.cfg, rows, secrets)
	if err != nil {
		s.writeServerError(w, r, err, "failed to resolve connections")
		return
	}
	writeJSON(w, http.StatusOK, resolved.View)
}
