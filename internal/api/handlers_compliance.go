package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type complianceStore interface {
	compliance.CertStore
	GetScan(ctx context.Context, id uuid.UUID) (store.Scan, error)
}

func (s *Server) handleGetScanCompliance(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	if _, err := s.compliance.GetScan(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
		return
	}

	summary, err := compliance.EvaluateScan(r.Context(), s.compliance, &id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to evaluate compliance")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleGetComplianceSummary(w http.ResponseWriter, r *http.Request) {
	var scanID *uuid.UUID
	if raw := r.URL.Query().Get("scan_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid scan_id")
			return
		}
		if _, err := s.compliance.GetScan(r.Context(), id); err != nil {
			writeError(w, r, http.StatusNotFound, "scan not found")
			return
		}
		scanID = &id
	}

	summary, err := compliance.EvaluateScan(r.Context(), s.compliance, scanID)
	if err != nil {
		s.writeServerError(w, r, err, "failed to evaluate compliance")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
