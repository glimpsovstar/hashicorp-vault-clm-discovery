package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeConnections struct {
	mu         sync.Mutex
	rows       map[string]store.Connection
	secrets    map[string]map[string]string
	keyMissing bool
	upserts    []fakeUpsert
}

type fakeUpsert struct {
	target   string
	metadata json.RawMessage
	secrets  map[string]string
	keep     []string
	actor    string
}

func newFakeConnections() *fakeConnections {
	return &fakeConnections{
		rows:    map[string]store.Connection{},
		secrets: map[string]map[string]string{},
	}
}

func (f *fakeConnections) GetConnections(context.Context) ([]store.Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.Connection{}
	for _, target := range []string{"aap", "eda", "vault"} {
		if row, ok := f.rows[target]; ok {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeConnections) DecryptSecrets(row store.Connection) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.secrets[row.Target] {
		out[k] = v
	}
	return out, nil
}

func (f *fakeConnections) UpsertConnection(_ context.Context, target string, metadata json.RawMessage, secrets map[string]string, keepSecrets []string, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cpSecrets := map[string]string{}
	for k, v := range secrets {
		cpSecrets[k] = v
	}
	f.upserts = append(f.upserts, fakeUpsert{
		target: target, metadata: append(json.RawMessage(nil), metadata...),
		secrets: cpSecrets, keep: append([]string(nil), keepSecrets...), actor: actor,
	})
	if wouldPersistSecrets(secrets, keepSecrets) && f.keyMissing {
		return store.ErrConnectionsKeyMissing
	}
	prev := map[string]string{}
	for k, v := range f.secrets[target] {
		prev[k] = v
	}
	held := map[string]struct{}{}
	for _, k := range keepSecrets {
		held[k] = struct{}{}
	}
	for k, v := range secrets {
		if _, ok := held[k]; ok {
			continue
		}
		if v == "" {
			delete(prev, k)
			continue
		}
		prev[k] = v
	}
	f.secrets[target] = prev
	f.rows[target] = store.Connection{
		Target:     target,
		Metadata:   append(json.RawMessage(nil), metadata...),
		SecretsSet: len(prev) > 0,
		Source:     "db",
		UpdatedBy:  actor,
	}
	return nil
}

func wouldPersistSecrets(incoming map[string]string, keep []string) bool {
	held := map[string]struct{}{}
	for _, k := range keep {
		held[k] = struct{}{}
	}
	for k, v := range incoming {
		if _, ok := held[k]; ok {
			continue
		}
		if v != "" {
			return true
		}
	}
	return false
}

func newConnectionsServer(cfg config.Config, cs *fakeConnections) *Server {
	srv := NewServer(cfg, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.connections = cs
	return srv
}

func doConnections(srv *Server, method, body, actor string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/api/v1/settings/connections", rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor != "" {
		req = req.WithContext(ContextWithActor(req.Context(), actor))
	}
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	return rec
}

func TestConnectionsGET_MasksSecrets(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		VaultAddr:  "https://vault.example:8200",
		VaultToken: "s.env-vault-token",
		AAPURL:     "https://aap.example",
		AAPToken:   "hvs.env-aap-token",
	}
	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"https://db-vault.example:8200","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": "s.db-vault-token"}

	rec := doConnections(newConnectionsServer(cfg, cs), http.MethodGet, "", "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"s.env-vault-token", "s.db-vault-token", "hvs.env-aap-token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("GET leaked secret %q: %s", secret, body)
		}
	}
	if strings.Contains(body, `"token":`) || strings.Contains(body, `"role_id":`) || strings.Contains(body, `"secret_id":`) {
		t.Fatalf("GET must not include secret keys, only *_set flags: %s", body)
	}
	if !strings.Contains(body, `"token_set":true`) {
		t.Fatalf("expected token_set true: %s", body)
	}
}

func TestConnections_UnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	srv := newConnectionsServer(config.Config{}, newFakeConnections())
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch} {
		rec := doConnections(srv, method, `{}`, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401 (body: %s)", method, rec.Code, rec.Body.String())
		}
	}
}

func TestConnections_InsecureNoAuthActsAsPlatformAdmin(t *testing.T) {
	t.Parallel()

	cfg := config.Config{InsecureNoAuth: true, VaultAddr: "https://vault.example:8200"}
	srv := newConnectionsServer(cfg, newFakeConnections())
	rec := doConnections(srv, http.MethodGet, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 under CLM_INSECURE_NO_AUTH (body: %s)", rec.Code, rec.Body.String())
	}
	rec = doConnections(srv, http.MethodPut, validPutBody(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 under CLM_INSECURE_NO_AUTH (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnections_RemediatorGet200PutPatch403(t *testing.T) {
	t.Parallel()

	srv := newConnectionsServer(config.Config{VaultAddr: "https://vault.example:8200"}, newFakeConnections())
	if rec := doConnections(srv, http.MethodGet, "", "remediator"); rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := validPutBody()
	if rec := doConnections(srv, http.MethodPut, body, "remediator"); rec.Code != http.StatusForbidden {
		t.Fatalf("PUT status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := doConnections(srv, http.MethodPatch, `{"vault":{"addr":"https://vault.example:8200"}}`, "remediator"); rec.Code != http.StatusForbidden {
		t.Fatalf("PATCH status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnections_PlatformAdminPut200(t *testing.T) {
	t.Parallel()

	cs := newFakeConnections()
	srv := newConnectionsServer(config.Config{}, cs)
	rec := doConnections(srv, http.MethodPut, validPutBody(), "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(cs.upserts) != 3 {
		t.Fatalf("upserts = %d, want 3 targets", len(cs.upserts))
	}
	if cs.upserts[0].actor != "platform_admin" && cs.rows["vault"].UpdatedBy != "platform_admin" {
		t.Fatalf("expected platform_admin actor on upsert, got %+v", cs.upserts)
	}
	if strings.Contains(rec.Body.String(), "s.put-vault-token") {
		t.Fatalf("PUT response leaked token: %s", rec.Body.String())
	}
}

func TestConnections_ViewerGet403(t *testing.T) {
	t.Parallel()

	rec := doConnections(newConnectionsServer(config.Config{}, newFakeConnections()), http.MethodGet, "", "viewer")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionsPUT_MissingKeyWithNewSecretsIs503(t *testing.T) {
	t.Parallel()

	cs := newFakeConnections()
	cs.keyMissing = true
	rec := doConnections(newConnectionsServer(config.Config{}, cs), http.MethodPut, validPutBody(), "platform_admin")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionsPATCH_OmitTokenKeepsStoredSecret(t *testing.T) {
	t.Parallel()

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"https://vault.example:8200","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": "s.stored-token"}

	patch := `{"vault":{"addr":"https://vault.example:8200","namespace":"admin","auth_method":"token"}}`
	rec := doConnections(newConnectionsServer(config.Config{}, cs), http.MethodPatch, patch, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if cs.secrets["vault"]["token"] != "s.stored-token" {
		t.Fatalf("stored token = %q, want kept secret", cs.secrets["vault"]["token"])
	}
	if strings.Contains(rec.Body.String(), "s.stored-token") {
		t.Fatalf("PATCH response leaked token: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"token_set":true`) {
		t.Fatalf("expected token_set true after omit: %s", rec.Body.String())
	}
}

func TestConnectionsPATCH_EmptyStringTokenKeepsStoredSecret(t *testing.T) {
	t.Parallel()

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"https://vault.example:8200","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": "s.stored-token"}

	rec := doConnections(newConnectionsServer(config.Config{}, cs), http.MethodPatch, `{"vault":{"token":""}}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if cs.secrets["vault"]["token"] != "s.stored-token" {
		t.Fatalf("empty string must keep stored token, got %q", cs.secrets["vault"]["token"])
	}
}

func TestConnectionsPATCH_NullTokenClearsStoredSecret(t *testing.T) {
	t.Parallel()

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"https://vault.example:8200","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": "s.stored-token"}

	rec := doConnections(newConnectionsServer(config.Config{}, cs), http.MethodPatch, `{"vault":{"token":null}}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, ok := cs.secrets["vault"]["token"]; ok {
		t.Fatalf("null token should clear stored secret, got %q", cs.secrets["vault"]["token"])
	}
	if strings.Contains(rec.Body.String(), "s.stored-token") {
		t.Fatalf("cleared token leaked: %s", rec.Body.String())
	}
}

func TestConnectionsPUT_InvalidAuthMethodIs400(t *testing.T) {
	t.Parallel()

	body := strings.Replace(validPutBody(), `"token"`, `"userpass"`, 1)
	rec := doConnections(newConnectionsServer(config.Config{}, newFakeConnections()), http.MethodPut, body, "platform_admin")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionsPUT_InvalidDeploymentIs400(t *testing.T) {
	t.Parallel()

	body := strings.Replace(validPutBody(), `"self_managed"`, `"cloud_only"`, 1)
	rec := doConnections(newConnectionsServer(config.Config{}, newFakeConnections()), http.MethodPut, body, "platform_admin")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionsPUT_BadJSONIs400(t *testing.T) {
	t.Parallel()

	rec := doConnections(newConnectionsServer(config.Config{}, newFakeConnections()), http.MethodPut, `{`, "platform_admin")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func validPutBody() string {
	var buf bytes.Buffer
	buf.WriteString(`{
		"vault":{"deployment":"self_managed","addr":"https://vault.example:8200","namespace":"","auth_method":"token","token":"s.put-vault-token"},
		"aap":{"url":"https://aap.example","renew_template":"CLM - Issue Certificate","renew_workflow":false,"skip_tls_verify":false,"default_mount":"pki","token":"put-aap-token"},
		"eda":{"webhook_url":"https://eda.example/hook","token":"put-eda-token"}
	}`)
	return buf.String()
}
