// Package adcs collects issued public certificates from Microsoft ADCS via an
// AAP job template (Windows collection plane). CLM never speaks WinRM/SSH.
package adcs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
)

const Source = "adcs"

// DefaultTemplate is the AAP job template name resolved by find-by-name.
const DefaultTemplate = "CLM - Collect ADCS"

// Controller is the AAP surface needed for ADCS collect.
type Controller interface {
	Configured() bool
	FindJobTemplate(ctx context.Context, name string) (int, error)
	LaunchJobTemplate(ctx context.Context, id int, extraVars map[string]any) (aap.LaunchResult, error)
	WaitForJob(ctx context.Context, res aap.LaunchResult, interval time.Duration) (aap.Status, error)
	JobStdout(ctx context.Context, jobID int) ([]byte, error)
}

type inventoryPayload struct {
	CAHost       string            `json:"ca_host"`
	Certificates []collectors.Item `json:"certificates"`
}

// Collect launches the ADCS AAP job, waits for success, parses stdout inventory
// JSON, and ingests public PEMs only. extra_vars contain no secrets.
func Collect(ctx context.Context, ctrl Controller, up collectors.Upserter, scanID uuid.UUID, templateName, caHost string) (ingested, skipped int, err error) {
	if ctrl == nil || !ctrl.Configured() {
		return 0, 0, fmt.Errorf("aap not configured")
	}
	if strings.TrimSpace(caHost) == "" {
		return 0, 0, fmt.Errorf("ca_host required")
	}
	if templateName == "" {
		templateName = DefaultTemplate
	}
	tmplID, err := ctrl.FindJobTemplate(ctx, templateName)
	if err != nil {
		return 0, 0, err
	}
	extra := map[string]any{
		"ca_host":     caHost,
		"clm_scan_id": scanID.String(),
	}
	for k := range extra {
		if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "secret") {
			return 0, 0, fmt.Errorf("refusing secret-like extra_vars key %q", k)
		}
	}
	res, err := ctrl.LaunchJobTemplate(ctx, tmplID, extra)
	if err != nil {
		return 0, 0, err
	}
	st, err := ctrl.WaitForJob(ctx, res, 50*time.Millisecond)
	if err != nil {
		return 0, 0, err
	}
	if !st.IsSuccess() {
		return 0, 0, fmt.Errorf("aap ADCS job %d ended with status %s", res.JobID, st)
	}
	raw, err := ctrl.JobStdout(ctx, res.JobID)
	if err != nil {
		return 0, 0, err
	}
	var payload inventoryPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, 0, fmt.Errorf("parse ADCS inventory JSON: %w", err)
	}
	items := payload.Certificates
	for i := range items {
		if items[i].Name == "" {
			items[i].Name = caHost
		}
	}
	return collectors.IngestPublicPEMs(ctx, up, scanID, Source, items)
}
