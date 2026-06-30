package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// BlindSpotSummary aggregates Vault vs discovered certificate counts.
type BlindSpotSummary struct {
	VaultManaged    int `json:"vault_managed"`
	Discovered      int `json:"discovered"`
	Shadow          int `json:"shadow"`
	SC081Violations int `json:"sc081_violations"`
}

type blindSpotStore interface {
	CountByManagedStatus(ctx context.Context, scanID *uuid.UUID) (managed, discovered int, err error)
	GetScan(ctx context.Context, id uuid.UUID) (store.Scan, error)
}

func buildBlindSpotSummary(managed, discovered int) BlindSpotSummary {
	shadow := discovered - managed
	if shadow < 0 {
		shadow = 0
	}
	return BlindSpotSummary{
		VaultManaged:    managed,
		Discovered:      discovered,
		Shadow:          shadow,
		SC081Violations: 0, // wired in Task 9 when compliance package ships
	}
}

func (s *Server) blindSpotSummary(ctx context.Context, scanID *uuid.UUID) (BlindSpotSummary, error) {
	managed, discovered, err := s.blindSpot.CountByManagedStatus(ctx, scanID)
	if err != nil {
		return BlindSpotSummary{}, err
	}
	return buildBlindSpotSummary(managed, discovered), nil
}

func (s *Server) handleGetScanBlindSpot(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	if _, err := s.blindSpot.GetScan(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
		return
	}

	summary, err := s.blindSpotSummary(r.Context(), &id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to compute blind-spot summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleGetBlindSpot(w http.ResponseWriter, r *http.Request) {
	summary, err := s.blindSpotSummary(r.Context(), nil)
	if err != nil {
		s.writeServerError(w, r, err, "failed to compute blind-spot summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
