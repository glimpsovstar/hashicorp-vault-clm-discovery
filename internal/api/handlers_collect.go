package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
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
		writeError(w, r, http.StatusBadRequest, "invalid source (want cloud_akv|cloud_acm|cloud_gcp)")
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
