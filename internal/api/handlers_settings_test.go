package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

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
	srv := NewServer(openTestConfig(cfg), &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.connections = cs
	return srv
}

func newLockedConnectionsServer(cs *fakeConnections) *Server {
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
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

	srv := newLockedConnectionsServer(newFakeConnections())
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

func doConnectionTest(srv *Server, body, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/connections/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req = req.WithContext(ContextWithActor(req.Context(), actor))
	}
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	return rec
}

type connectionTestResp struct {
	OK     bool   `json:"ok"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	Error  string `json:"error"`
}

func parseConnectionTest(t *testing.T, rec *httptest.ResponseRecorder) connectionTestResp {
	t.Helper()
	var out connectionTestResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	return out
}

func assertNoSecrets(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(body, secret) {
			t.Fatalf("response leaked secret %q: %s", secret, body)
		}
	}
}

func TestConnectionTest_VaultTokenProbeOK(t *testing.T) {
	t.Parallel()

	const token = "s.db-vault-token"
	var gotPath, gotToken, gotNS string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		gotNS = r.Header.Get("X-Vault-Namespace")
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/health", "/v1/sys/mounts":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"pki/":{"type":"pki"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"` + peer.URL + `","namespace":"admin","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": token}

	cfg := config.Config{VaultAddr: "http://env-vault.invalid:8200", VaultToken: "s.env-token"}
	rec := doConnectionTest(newConnectionsServer(cfg, cs), `{"target":"vault"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if !got.OK || got.Target != "vault" {
		t.Fatalf("got %+v, want ok vault", got)
	}
	if got.Detail == "" || strings.Contains(strings.ToLower(got.Detail), "token") {
		t.Fatalf("detail must be non-empty and non-secret: %q", got.Detail)
	}
	assertNoSecrets(t, rec.Body.String(), token, "s.env-token")
	if gotToken != token {
		t.Fatalf("probe used token %q, want overlay %q (path %s)", gotToken, token, gotPath)
	}
	if gotNS != "admin" {
		t.Fatalf("X-Vault-Namespace = %q, want admin", gotNS)
	}
	if gotPath != "/v1/sys/health" && gotPath != "/v1/sys/mounts" {
		t.Fatalf("path = %s, want sys/health or sys/mounts", gotPath)
	}
}

func TestConnectionTest_VaultAppRoleLoginThenProbe(t *testing.T) {
	t.Parallel()

	const (
		roleID      = "role-uuid"
		secretID    = "secret-uuid"
		clientToken = "hvs.approle-client-token"
	)
	var loginHits, probeHits int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			loginHits++
			if r.Header.Get("X-Vault-Token") != "" {
				t.Errorf("login must not send X-Vault-Token")
			}
			var body struct {
				RoleID   string `json:"role_id"`
				SecretID string `json:"secret_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.RoleID != roleID || body.SecretID != secretID {
				t.Errorf("login body %+v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": clientToken, "lease_duration": 3600, "renewable": true},
			})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/sys/health" || r.URL.Path == "/v1/sys/mounts"):
			probeHits++
			if got := r.Header.Get("X-Vault-Token"); got != clientToken {
				t.Errorf("probe token = %q, want client token", got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"pki/":{"type":"pki"}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"` + peer.URL + `","namespace":"admin","auth_method":"approle"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"role_id": roleID, "secret_id": secretID}

	rec := doConnectionTest(newConnectionsServer(config.Config{}, cs), `{"target":"vault"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if !got.OK {
		t.Fatalf("got %+v, want ok", got)
	}
	if loginHits != 1 || probeHits != 1 {
		t.Fatalf("loginHits=%d probeHits=%d, want 1/1", loginHits, probeHits)
	}
	if _, ok := cs.secrets["vault"]["token"]; ok {
		t.Fatalf("AppRole client token must not be persisted: %+v", cs.secrets["vault"])
	}
	if cs.secrets["vault"]["role_id"] != roleID || cs.secrets["vault"]["secret_id"] != secretID {
		t.Fatalf("stored secrets mutated: %+v", cs.secrets["vault"])
	}
	assertNoSecrets(t, rec.Body.String(), clientToken, roleID, secretID)
}

func TestConnectionTest_AfterPUTUsesSavedOverlay(t *testing.T) {
	t.Parallel()

	const putToken = "s.put-overlay-token"
	var gotToken string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"initialized":true,"pki/":{"type":"pki"}}`))
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	srv := newConnectionsServer(config.Config{VaultAddr: "http://env-vault.invalid:8200", VaultToken: "s.env-token"}, cs)
	put := fmt.Sprintf(`{
		"vault":{"deployment":"self_managed","addr":%q,"namespace":"","auth_method":"token","token":%q},
		"aap":{"url":"https://aap.example","renew_template":"T","renew_workflow":false,"skip_tls_verify":false,"default_mount":"pki"},
		"eda":{"webhook_url":"https://eda.example/hook"}
	}`, peer.URL, putToken)
	if rec := doConnections(srv, http.MethodPut, put, "platform_admin"); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	rec := doConnectionTest(srv, `{"target":"vault"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("Test status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if !got.OK {
		t.Fatalf("got %+v, want ok after PUT overlay", got)
	}
	if gotToken != putToken {
		t.Fatalf("probe token = %q, want saved overlay %q", gotToken, putToken)
	}
	assertNoSecrets(t, rec.Body.String(), putToken, "s.env-token")
}

func TestConnectionTest_AAPMeAndTemplateOK(t *testing.T) {
	t.Parallel()

	const aapToken = "aap-db-token"
	var launchHits, meHits, tmplHits int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+aapToken {
			t.Errorf("Authorization = %q", got)
		}
		if strings.Contains(r.URL.Path, "/launch") {
			launchHits++
			t.Errorf("must not launch: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/api/v2/me"):
			meHits++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1,"username":"admin"}`))
		case strings.Contains(r.URL.Path, "/job_templates"):
			tmplHits++
			if r.URL.Query().Get("name") != "CLM - Issue Certificate" {
				t.Errorf("template name = %q", r.URL.Query().Get("name"))
			}
			_, _ = w.Write([]byte(`{"count":1,"results":[{"id":7,"name":"CLM - Issue Certificate"}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["aap"] = store.Connection{
		Target:     "aap",
		Source:     "db",
		Metadata:   json.RawMessage(`{"url":"` + peer.URL + `","renew_template":"CLM - Issue Certificate","renew_workflow":false}`),
		SecretsSet: true,
	}
	cs.secrets["aap"] = map[string]string{"token": aapToken}

	rec := doConnectionTest(newConnectionsServer(config.Config{AAPURL: "https://env-aap.invalid", AAPToken: "env-aap-token"}, cs), `{"target":"aap"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if !got.OK || got.Target != "aap" {
		t.Fatalf("got %+v, want ok aap", got)
	}
	if meHits != 1 || tmplHits != 1 || launchHits != 0 {
		t.Fatalf("me=%d tmpl=%d launch=%d, want 1/1/0", meHits, tmplHits, launchHits)
	}
	assertNoSecrets(t, rec.Body.String(), aapToken, "env-aap-token")
}

func TestConnectionTest_AAPMissingTemplateOKFalseNoLaunch(t *testing.T) {
	t.Parallel()

	var launchHits int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/launch") {
			launchHits++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/api/v2/me") {
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["aap"] = store.Connection{
		Target:     "aap",
		Source:     "db",
		Metadata:   json.RawMessage(`{"url":"` + peer.URL + `","renew_template":"Missing Template","renew_workflow":false}`),
		SecretsSet: true,
	}
	cs.secrets["aap"] = map[string]string{"token": "tok"}

	rec := doConnectionTest(newConnectionsServer(config.Config{}, cs), `{"target":"aap"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if got.OK {
		t.Fatalf("missing template must be ok:false, got %+v", got)
	}
	if launchHits != 0 {
		t.Fatalf("launch hits = %d, want 0", launchHits)
	}
	if !strings.Contains(strings.ToLower(got.Detail), "template") {
		t.Fatalf("detail should mention template: %q", got.Detail)
	}
}

func TestConnectionTest_EDAPing2xxNoOutboxInsert(t *testing.T) {
	t.Parallel()

	const edaToken = "eda-db-token"
	var gotMethod, gotAuth, gotCT string
	var gotBody map[string]any
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["eda"] = store.Connection{
		Target:     "eda",
		Source:     "db",
		Metadata:   json.RawMessage(`{"webhook_url":"` + peer.URL + `/hook"}`),
		SecretsSet: true,
	}
	cs.secrets["eda"] = map[string]string{"token": edaToken}

	res := &fakeResourceStore{events: []store.Event{{EventType: "cert.revoked"}}}
	srv := newConnectionsServer(config.Config{EDAWebhookURL: "http://env-eda.invalid/hook", EDAWebhookToken: "env-eda-token"}, cs)
	srv.resources = res
	before := len(res.events)

	rec := doConnectionTest(srv, `{"target":"eda"}`, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := parseConnectionTest(t, rec)
	if !got.OK || got.Target != "eda" {
		t.Fatalf("got %+v, want ok eda", got)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want POST", gotMethod)
	}
	if gotAuth != "Bearer "+edaToken {
		t.Fatalf("Authorization = %q, want Bearer overlay token", gotAuth)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("Content-Type = %q", gotCT)
	}
	if gotBody["event_type"] != "clm.connection.test" {
		t.Fatalf("event_type = %v", gotBody["event_type"])
	}
	if _, err := uuid.Parse(fmt.Sprint(gotBody["id"])); err != nil {
		t.Fatalf("id = %v, want uuid: %v", gotBody["id"], err)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(gotBody["created_at"])); err != nil {
		t.Fatalf("created_at = %v, want rfc3339: %v", gotBody["created_at"], err)
	}
	if len(res.events) != before {
		t.Fatalf("events row count = %d, want unchanged %d", len(res.events), before)
	}
	assertNoSecrets(t, rec.Body.String(), edaToken, "env-eda-token")
}

func TestConnectionTest_UnconfiguredIs503(t *testing.T) {
	t.Parallel()

	srv := newConnectionsServer(config.Config{}, newFakeConnections())
	for _, target := range []string{"vault", "aap", "eda"} {
		rec := doConnectionTest(srv, `{"target":"`+target+`"}`, "platform_admin")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d, want 503 (body: %s)", target, rec.Code, rec.Body.String())
		}
	}
}

func TestConnectionTest_BadTargetIs400(t *testing.T) {
	t.Parallel()

	srv := newConnectionsServer(config.Config{}, newFakeConnections())
	for _, body := range []string{`{"target":"ldap"}`, `{"target":""}`, `{`, `{}`} {
		rec := doConnectionTest(srv, body, "platform_admin")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d, want 400 (body: %s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestConnectionTest_UnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	rec := doConnectionTest(newLockedConnectionsServer(newFakeConnections()), `{"target":"vault"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionTest_InsecureNoAuthActsAsPlatformAdmin(t *testing.T) {
	t.Parallel()

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:   "vault",
		Source:   "db",
		Metadata: json.RawMessage(`{"addr":"` + peer.URL + `","auth_method":"token"}`),
	}
	cs.secrets["vault"] = map[string]string{"token": "s.tok"}

	rec := doConnectionTest(newConnectionsServer(config.Config{InsecureNoAuth: true}, cs), `{"target":"vault"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 under CLM_INSECURE_NO_AUTH (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionTest_RemediatorIs403(t *testing.T) {
	t.Parallel()

	rec := doConnectionTest(newConnectionsServer(config.Config{VaultAddr: "https://vault.example:8200"}, newFakeConnections()), `{"target":"vault"}`, "remediator")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestConnectionTest_IgnoresSecretsInBody(t *testing.T) {
	t.Parallel()

	const overlayToken = "s.overlay-token"
	var gotToken string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(peer.Close)

	cs := newFakeConnections()
	cs.rows["vault"] = store.Connection{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"` + peer.URL + `","auth_method":"token"}`),
		SecretsSet: true,
	}
	cs.secrets["vault"] = map[string]string{"token": overlayToken}

	body := `{"target":"vault","token":"s.body-secret","secret_id":"body-secret-id"}`
	rec := doConnectionTest(newConnectionsServer(config.Config{}, cs), body, "platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if gotToken != overlayToken {
		t.Fatalf("used token %q, must use resolved overlay not body secret", gotToken)
	}
	assertNoSecrets(t, rec.Body.String(), overlayToken, "s.body-secret", "body-secret-id")
}
