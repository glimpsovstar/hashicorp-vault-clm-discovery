package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors/adcs"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors/akv"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type collectScanRequest struct {
	Consent      bool              `json:"consent"`
	Source       string            `json:"source"`
	Certificates []collectors.Item `json:"certificates"`
}

// handleCollectScan ingests public PEMs from a cloud collector source into the
// fingerprint inventory. Consent-gated. Rejects private keys. Completes the scan
// synchronously (no network probe). No cloud root keys are stored.
func (s *Server) handleCollectScan(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, r, http.StatusServiceUnavailable, "store not configured")
		return
	}
	var req collectScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "scan consent required; set consent=true to confirm authorized scanning")
		return
	}
	if err := collectors.ValidateSource(req.Source); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid source (want adcs|cloud_akv|cloud_acm|cloud_gcp)")
		return
	}
	if len(req.Certificates) == 0 {
		writeError(w, r, http.StatusBadRequest, "certificates required")
		return
	}

	scan, err := s.store.CreateScanWithSource(r.Context(), req.Source, nil, nil, []int{}, 1, 0)
	if err != nil {
		s.writeServerError(w, r, err, "failed to create collector scan")
		return
	}
	if err := s.store.UpdateScanRunning(r.Context(), scan.ID, len(req.Certificates)); err != nil {
		s.writeServerError(w, r, err, "failed to start collector scan")
		return
	}

	ingested, skipped, err := collectors.IngestPublicPEMs(r.Context(), s.store, scan.ID, req.Source, req.Certificates)
	if err != nil {
		_ = s.store.FailScan(r.Context(), scan.ID, err.Error())
		if errors.Is(err, collectors.ErrPrivateKeyRejected) {
			writeError(w, r, http.StatusBadRequest, "private key material is not accepted")
			return
		}
		s.writeServerError(w, r, err, "failed to ingest certificates")
		return
	}

	summary := store.ScanSummary{
		TargetsTotal:     len(req.Certificates),
		TargetsScanned:   len(req.Certificates),
		TargetsSucceeded: ingested,
		TargetsFailed:    skipped,
		CertsFound:       ingested,
	}
	if err := s.store.CompleteScan(r.Context(), scan.ID, summary); err != nil {
		s.writeServerError(w, r, err, "failed to complete collector scan")
		return
	}
	scan, _ = s.store.GetScan(r.Context(), scan.ID)

	s.auditAllow(r, "collect_scan", "scan", scan.ID.String(), map[string]any{
		"source": req.Source, "ingested": ingested, "skipped": skipped,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":     scan,
		"ingested": ingested,
		"skipped":  skipped,
	})
}

type collectADCSRequest struct {
	Consent bool   `json:"consent"`
	CAHost  string `json:"ca_host"`
}

// handleCollectADCS launches AAP template "CLM - Collect ADCS", ingests public
// PEMs from stdout, source=adcs. 503 if AAP unset.
func (s *Server) handleCollectADCS(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, r, http.StatusServiceUnavailable, "store not configured")
		return
	}
	if s.aapClient == nil || !s.aapClient.Configured() {
		writeError(w, r, http.StatusServiceUnavailable, "AAP not configured for ADCS collect")
		return
	}
	var req collectADCSRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "scan consent required; set consent=true to confirm authorized scanning")
		return
	}
	if req.CAHost == "" {
		writeError(w, r, http.StatusBadRequest, "ca_host required")
		return
	}

	scan, err := s.store.CreateScanWithSource(r.Context(), adcs.Source, nil, nil, []int{}, 1, 0)
	if err != nil {
		s.writeServerError(w, r, err, "failed to create ADCS scan")
		return
	}
	_ = s.store.UpdateScanRunning(r.Context(), scan.ID, 0)

	tmpl := s.cfg.AAPADCSTemplate
	if tmpl == "" {
		tmpl = adcs.DefaultTemplate
	}
	ingested, skipped, err := adcs.Collect(r.Context(), s.aapClient, s.store, scan.ID, tmpl, req.CAHost)
	if err != nil {
		_ = s.store.FailScan(r.Context(), scan.ID, err.Error())
		if errors.Is(err, collectors.ErrPrivateKeyRejected) {
			writeError(w, r, http.StatusBadRequest, "private key material is not accepted")
			return
		}
		s.writeServerError(w, r, err, "ADCS collect failed")
		return
	}
	summary := store.ScanSummary{
		TargetsTotal:     ingested + skipped,
		TargetsScanned:   ingested + skipped,
		TargetsSucceeded: ingested,
		TargetsFailed:    skipped,
		CertsFound:       ingested,
	}
	_ = s.store.CompleteScan(r.Context(), scan.ID, summary)
	scan, _ = s.store.GetScan(r.Context(), scan.ID)
	s.auditAllow(r, "collect_adcs", "scan", scan.ID.String(), map[string]any{
		"ca_host": req.CAHost, "ingested": ingested, "skipped": skipped,
	})
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan, "ingested": ingested, "skipped": skipped})
}

type collectAKVRequest struct {
	Consent bool `json:"consent"`
}

// handleCollectAKV lists+gets public Key Vault certificates into source=cloud_akv.
func (s *Server) handleCollectAKV(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, r, http.StatusServiceUnavailable, "store not configured")
		return
	}
	if s.cfg.AzureKeyVaultURI == "" {
		writeError(w, r, http.StatusServiceUnavailable, "AZURE_KEY_VAULT_URI not configured")
		return
	}
	var req collectAKVRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "scan consent required; set consent=true to confirm authorized scanning")
		return
	}

	token, err := resolveAzureToken(r.Context(), s.cfg)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "Azure credentials not configured")
		return
	}

	scan, err := s.store.CreateScanWithSource(r.Context(), akv.ScanSource, nil, nil, []int{}, 1, 0)
	if err != nil {
		s.writeServerError(w, r, err, "failed to create AKV scan")
		return
	}
	_ = s.store.UpdateScanRunning(r.Context(), scan.ID, 0)

	src := &akv.VaultSource{VaultURI: s.cfg.AzureKeyVaultURI, Token: token}
	ingested, skipped, err := akv.Collect(r.Context(), s.store, scan.ID, src)
	if err != nil {
		_ = s.store.FailScan(r.Context(), scan.ID, err.Error())
		s.writeServerError(w, r, err, "AKV collect failed")
		return
	}
	summary := store.ScanSummary{
		TargetsTotal:     ingested + skipped,
		TargetsScanned:   ingested + skipped,
		TargetsSucceeded: ingested,
		TargetsFailed:    skipped,
		CertsFound:       ingested,
	}
	_ = s.store.CompleteScan(r.Context(), scan.ID, summary)
	scan, _ = s.store.GetScan(r.Context(), scan.ID)
	s.auditAllow(r, "collect_akv", "scan", scan.ID.String(), map[string]any{
		"ingested": ingested, "skipped": skipped,
	})
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan, "ingested": ingested, "skipped": skipped})
}
