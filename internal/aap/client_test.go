package aap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(Config{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestConfigured(t *testing.T) {
	t.Parallel()
	c, _ := NewClient(Config{})
	if c.Configured() {
		t.Fatal("empty BaseURL should be unconfigured")
	}
	c, _ = NewClient(Config{BaseURL: "aap.example.com"})
	if !c.Configured() {
		t.Fatal("BaseURL should be configured")
	}
}

func TestFindJobTemplate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		// Simulate the Controller's contains-match: return exact + a prefix match.
		switch name {
		case "CLM - Issue Certificate":
			_, _ = w.Write([]byte(`{"count":2,"results":[
				{"id":7,"name":"CLM - Issue Certificate"},
				{"id":9,"name":"CLM - Issue Certificate (staging)"}
			]}`))
		case "Missing":
			_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
		case "Dup":
			_, _ = w.Write([]byte(`{"count":2,"results":[
				{"id":1,"name":"Dup"},{"id":2,"name":"Dup"}
			]}`))
		default:
			_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
		}
	}))
	defer srv.Close()
	c := newClient(t, srv)

	id, err := c.FindJobTemplate(context.Background(), "CLM - Issue Certificate")
	if err != nil {
		t.Fatalf("FindJobTemplate: %v", err)
	}
	if id != 7 {
		t.Fatalf("id = %d, want 7 (exact match, not the prefix template)", id)
	}

	if _, err := c.FindJobTemplate(context.Background(), "Missing"); err == nil {
		t.Fatal("expected error for missing template")
	}
	if _, err := c.FindJobTemplate(context.Background(), "Dup"); err == nil {
		t.Fatal("expected error for ambiguous template")
	}
}

func TestLaunchJobTemplate_RoundTripsExtraVars(t *testing.T) {
	t.Parallel()

	var gotVars map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/job_templates/7/launch/") {
			t.Errorf("path = %s, want launch path", r.URL.Path)
		}
		var body struct {
			ExtraVars map[string]any `json:"extra_vars"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		gotVars = body.ExtraVars
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job":123,"id":123}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	res, err := c.LaunchJobTemplate(context.Background(), 7, map[string]any{
		"cert_common_name_override": "app.example.com",
		"vault_pki_mount":           "pki-int",
	})
	if err != nil {
		t.Fatalf("LaunchJobTemplate: %v", err)
	}
	if res.JobID != 123 || res.Workflow {
		t.Fatalf("result = %+v, want job 123 (non-workflow)", res)
	}
	if gotVars["cert_common_name_override"] != "app.example.com" || gotVars["vault_pki_mount"] != "pki-int" {
		t.Fatalf("extra_vars not round-tripped: %#v", gotVars)
	}
}

func TestLaunchWorkflowJobTemplate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/workflow_job_templates/3/launch/") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workflow_job":55}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	res, err := c.LaunchWorkflowJobTemplate(context.Background(), 3, nil)
	if err != nil {
		t.Fatalf("LaunchWorkflowJobTemplate: %v", err)
	}
	if res.JobID != 55 || !res.Workflow {
		t.Fatalf("result = %+v, want workflow job 55", res)
	}
}

func TestLaunch_ErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"variables needed to start"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	if _, err := c.LaunchJobTemplate(context.Background(), 7, nil); err == nil {
		t.Fatal("expected error for 400 launch")
	}
}

func TestJobStatusNormalization(t *testing.T) {
	t.Parallel()

	cases := map[string]Status{
		"new":        StatusPending,
		"pending":    StatusPending,
		"waiting":    StatusPending,
		"running":    StatusRunning,
		"successful": StatusSuccessful,
		"failed":     StatusFailed,
		"error":      StatusError,
		"canceled":   StatusCanceled,
		"weird":      StatusUnknown,
	}
	for raw, want := range cases {
		raw, want := raw, want
		t.Run(raw, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/jobs/123/") {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"` + raw + `"}`))
			}))
			defer srv.Close()
			c := newClient(t, srv)

			st, err := c.JobStatus(context.Background(), LaunchResult{JobID: 123})
			if err != nil {
				t.Fatalf("JobStatus: %v", err)
			}
			if st != want {
				t.Fatalf("status(%q) = %q, want %q", raw, st, want)
			}
		})
	}
}

func TestWaitForJob_PollsToTerminal(t *testing.T) {
	t.Parallel()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n < 3 {
			_, _ = w.Write([]byte(`{"status":"running"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"successful"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	st, err := c.WaitForJob(context.Background(), LaunchResult{JobID: 1}, time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForJob: %v", err)
	}
	if st != StatusSuccessful {
		t.Fatalf("status = %q, want successful", st)
	}
	if atomic.LoadInt32(&calls) < 3 {
		t.Fatalf("expected at least 3 polls, got %d", calls)
	}
}

func TestWaitForJob_ContextCancel(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"running"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := c.WaitForJob(ctx, LaunchResult{JobID: 1}, 5*time.Millisecond); err == nil {
		t.Fatal("expected context deadline error while job stays running")
	}
}

func TestWaitForJob_ToleratesTransientFailures(t *testing.T) {
	t.Parallel()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			w.WriteHeader(http.StatusBadGateway) // transient blip
		case 2:
			_, _ = w.Write([]byte(`{"status":"running"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"successful"}`))
		}
	}))
	defer srv.Close()
	c := newClient(t, srv)

	st, err := c.WaitForJob(context.Background(), LaunchResult{JobID: 1}, time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForJob should tolerate a transient failure: %v", err)
	}
	if st != StatusSuccessful {
		t.Fatalf("status = %q, want successful", st)
	}
}

func TestWaitForJob_ImmediateTerminal(t *testing.T) {
	t.Parallel()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"successful"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	st, err := c.WaitForJob(context.Background(), LaunchResult{JobID: 1}, time.Hour)
	if err != nil {
		t.Fatalf("WaitForJob: %v", err)
	}
	if st != StatusSuccessful {
		t.Fatalf("status = %q, want successful", st)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("polls = %d, want exactly 1 (already terminal)", got)
	}
}

func TestJobStatus_WorkflowPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/workflow_jobs/9/") {
			t.Errorf("path = %s, want workflow_jobs path", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"running"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	st, err := c.JobStatus(context.Background(), LaunchResult{JobID: 9, Workflow: true})
	if err != nil {
		t.Fatalf("JobStatus: %v", err)
	}
	if st != StatusRunning {
		t.Fatalf("status = %q, want running", st)
	}
}

func TestNewClient_InvalidURL(t *testing.T) {
	t.Parallel()
	if _, err := NewClient(Config{BaseURL: "http://[::1"}); err == nil {
		t.Fatal("expected error for malformed base url")
	}
	c, err := NewClient(Config{BaseURL: "aap.example.com"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !strings.HasPrefix(c.url("/x"), "https://aap.example.com") {
		t.Fatalf("url = %q, want https scheme prepended", c.url("/x"))
	}
}

func TestNoAuthHeaderWhenTokenEmpty(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header should be absent when token is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"successful"}`))
	}))
	defer srv.Close()
	c, err := NewClient(Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.JobStatus(context.Background(), LaunchResult{JobID: 1}); err != nil {
		t.Fatalf("JobStatus: %v", err)
	}
}

func TestStatusHelpers(t *testing.T) {
	t.Parallel()
	if !StatusSuccessful.IsTerminal() || !StatusSuccessful.IsSuccess() {
		t.Fatal("successful should be terminal and success")
	}
	if !StatusFailed.IsTerminal() || StatusFailed.IsSuccess() {
		t.Fatal("failed should be terminal but not success")
	}
	if StatusRunning.IsTerminal() {
		t.Fatal("running should not be terminal")
	}
}
