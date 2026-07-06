// Package aap is a small client for an Ansible Automation Platform (AWX-
// compatible) Controller. It discovers job/workflow templates by name — so no
// numeric template IDs are baked into CLM — launches them with extra_vars, and
// polls job status to completion. It is the orchestration arm of Mode C: Vault
// issues/governs certificates, AAP deploys/rotates/verifies them, and CLM
// triggers and tracks that work.
package aap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpTimeout bounds a single Controller request. Job execution is tracked by
// polling, so this only caps individual API calls, not the whole job.
const httpTimeout = 30 * time.Second

// maxBody caps how much of a Controller response we read, guarding against a
// hostile or misbehaving endpoint.
const maxBody = 4 << 20 // 4 MiB

// Config holds the Controller connection settings. Values come from the
// environment at runtime and are never logged.
type Config struct {
	// BaseURL is the Controller root, e.g. https://aap.example.com. The /api/v2
	// prefix is added by the client.
	BaseURL string
	// Token is an OAuth2 bearer token for the Controller API.
	Token string
	// SkipTLSVerify disables TLS verification (test/lab only; off by default).
	SkipTLSVerify bool
}

// Client talks to a single Controller.
type Client struct {
	cfg  Config
	http *http.Client
}

// Status is a normalized job status. AAP reports several non-terminal states
// (new/pending/waiting/running) and terminal ones (successful/failed/error/
// canceled); callers should branch on IsTerminal / IsSuccess.
type Status string

const (
	StatusPending    Status = "pending"
	StatusRunning    Status = "running"
	StatusSuccessful Status = "successful"
	StatusFailed     Status = "failed"
	StatusError      Status = "error"
	StatusCanceled   Status = "canceled"
	StatusUnknown    Status = "unknown"
)

// IsTerminal reports whether the job has finished (no further polling needed).
func (s Status) IsTerminal() bool {
	switch s {
	case StatusSuccessful, StatusFailed, StatusError, StatusCanceled:
		return true
	default:
		return false
	}
}

// IsSuccess reports whether the job completed successfully.
func (s Status) IsSuccess() bool { return s == StatusSuccessful }

// normalizeStatus maps the Controller's status strings onto Status.
func normalizeStatus(raw string) Status {
	switch raw {
	case "new", "pending", "waiting":
		return StatusPending
	case "running":
		return StatusRunning
	case "successful":
		return StatusSuccessful
	case "failed":
		return StatusFailed
	case "error":
		return StatusError
	case "canceled":
		return StatusCanceled
	default:
		return StatusUnknown
	}
}

// LaunchResult identifies a job created by a launch call.
type LaunchResult struct {
	// JobID is the created job (job_templates) or workflow job
	// (workflow_job_templates) id.
	JobID int
	// Workflow is true when the launched resource was a workflow job template.
	Workflow bool
}

// NewClient builds a Controller client. It returns an error only for a
// malformed base URL; a client with an empty BaseURL is allowed but reports
// Configured()==false so callers can degrade gracefully.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL != "" && !strings.HasPrefix(cfg.BaseURL, "http://") && !strings.HasPrefix(cfg.BaseURL, "https://") {
		cfg.BaseURL = "https://" + cfg.BaseURL
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for lab/test only
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: httpTimeout, Transport: transport},
	}, nil
}

// Configured reports whether a Controller URL is set.
func (c *Client) Configured() bool { return c.cfg.BaseURL != "" }

// FindJobTemplate resolves an exact template name to its id. It returns an
// error when no template matches or when the name is ambiguous.
func (c *Client) FindJobTemplate(ctx context.Context, name string) (int, error) {
	return c.findTemplate(ctx, "job_templates", name)
}

// FindWorkflowJobTemplate resolves an exact workflow-template name to its id.
func (c *Client) FindWorkflowJobTemplate(ctx context.Context, name string) (int, error) {
	return c.findTemplate(ctx, "workflow_job_templates", name)
}

func (c *Client) findTemplate(ctx context.Context, kind, name string) (int, error) {
	if !c.Configured() {
		return 0, fmt.Errorf("aap client is not configured")
	}
	q := url.Values{"name": {name}}
	var page struct {
		Count   int `json:"count"`
		Results []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := c.get(ctx, fmt.Sprintf("/api/v2/%s/?%s", kind, q.Encode()), &page); err != nil {
		return 0, err
	}
	// The name filter is a contains-match server-side, so re-check for an exact
	// name to avoid launching the wrong (prefix-matching) template.
	var matches []int
	for _, r := range page.Results {
		if r.Name == name {
			matches = append(matches, r.ID)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no %s named %q", kind, name)
	case 1:
		return matches[0], nil
	default:
		return 0, fmt.Errorf("ambiguous %s name %q matched %d templates", kind, name, len(matches))
	}
}

// LaunchJobTemplate launches a job template with the given extra_vars and
// returns the created job.
func (c *Client) LaunchJobTemplate(ctx context.Context, id int, extraVars map[string]any) (LaunchResult, error) {
	return c.launch(ctx, "job_templates", id, extraVars, false)
}

// LaunchWorkflowJobTemplate launches a workflow job template with the given
// extra_vars and returns the created workflow job.
func (c *Client) LaunchWorkflowJobTemplate(ctx context.Context, id int, extraVars map[string]any) (LaunchResult, error) {
	return c.launch(ctx, "workflow_job_templates", id, extraVars, true)
}

func (c *Client) launch(ctx context.Context, kind string, id int, extraVars map[string]any, workflow bool) (LaunchResult, error) {
	if !c.Configured() {
		return LaunchResult{}, fmt.Errorf("aap client is not configured")
	}
	payload := map[string]any{}
	if len(extraVars) > 0 {
		payload["extra_vars"] = extraVars
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return LaunchResult{}, fmt.Errorf("marshal launch payload: %w", err)
	}
	var out struct {
		Job         int `json:"job"`
		WorkflowJob int `json:"workflow_job"`
		ID          int `json:"id"`
	}
	if err := c.post(ctx, fmt.Sprintf("/api/v2/%s/%d/launch/", kind, id), body, &out); err != nil {
		return LaunchResult{}, err
	}
	jobID := out.Job
	if workflow {
		jobID = out.WorkflowJob
	}
	// Older/newer Controllers may return the launched job under "id".
	if jobID == 0 {
		jobID = out.ID
	}
	if jobID == 0 {
		return LaunchResult{}, fmt.Errorf("launch %s %d: no job id in response", kind, id)
	}
	return LaunchResult{JobID: jobID, Workflow: workflow}, nil
}

// JobStatus returns the normalized status of a (unified) job. It works for both
// job_templates jobs and workflow jobs via the /api/v2/jobs and
// /api/v2/workflow_jobs endpoints respectively.
func (c *Client) JobStatus(ctx context.Context, res LaunchResult) (Status, error) {
	if !c.Configured() {
		return StatusUnknown, fmt.Errorf("aap client is not configured")
	}
	kind := "jobs"
	if res.Workflow {
		kind = "workflow_jobs"
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, fmt.Sprintf("/api/v2/%s/%d/", kind, res.JobID), &out); err != nil {
		return StatusUnknown, err
	}
	return normalizeStatus(out.Status), nil
}

// WaitForJob polls JobStatus every interval until the job reaches a terminal
// status or ctx is canceled. It returns the terminal status.
func (c *Client) WaitForJob(ctx context.Context, res LaunchResult, interval time.Duration) (Status, error) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	// Check once immediately, then on each tick.
	for {
		st, err := c.JobStatus(ctx, res)
		if err != nil {
			return StatusUnknown, err
		}
		if st.IsTerminal() {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aap request %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aap %s: status %d: %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + path
}
