package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/posture"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

const postureAfterScanTimeout = 2 * time.Minute

func (s *Server) maybeRecomputePostureAfterScan(ctx context.Context, scanID uuid.UUID) {
	ctx, cancel := context.WithTimeout(ctx, postureAfterScanTimeout)
	defer cancel()
	if err := posture.RecomputeScan(ctx, s.store, scanID); err != nil {
		s.log.Warn("posture recompute after scan failed", "scan_id", scanID, "err", err)
		return
	}
	s.log.Info("posture recompute after scan complete", "scan_id", scanID)
}

type createWaiverRequest struct {
	RuleID    string    `json:"rule_id"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleListCertFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	findings, err := s.store.ListOpenFindings(r.Context(), id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings})
}

func (s *Server) handleListCertWaivers(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	waivers, err := s.store.ListWaiversForCert(r.Context(), id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list waivers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": waivers})
}

func (s *Server) handleCreateCertWaiver(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	actor := s.requestActor(r)
	if actor == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createWaiverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	wvr, err := s.store.CreateWaiver(r.Context(), id, req.RuleID, req.Reason, actor, req.ExpiresAt)
	if err != nil {
		if errors.Is(err, store.ErrWaiverExpired) {
			writeError(w, r, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		s.writeServerError(w, r, err, "failed to create waiver")
		return
	}
	if _, err := posture.RecomputeCert(r.Context(), s.store, id); err != nil {
		s.log.Warn("posture recompute after waiver failed", "cert_id", id, "err", err)
	}
	s.auditAllow(r, "create_waiver", "certificate", id.String(), map[string]any{
		"rule_id": req.RuleID, "waiver_id": wvr.ID.String(),
	})
	writeJSON(w, http.StatusCreated, wvr)
}

func (s *Server) handleRevokeWaiver(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid waiver id")
		return
	}
	wvr, err := s.store.GetWaiver(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, r, err, store.ErrWaiverNotFound, "waiver not found", "failed to load waiver")
		return
	}
	if err := s.store.RevokeWaiver(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrWaiverNotFound, "waiver not found", "failed to revoke waiver")
		return
	}
	if _, err := posture.RecomputeCert(r.Context(), s.store, wvr.CertID); err != nil {
		s.log.Warn("posture recompute after waiver revoke failed", "cert_id", wvr.CertID, "err", err)
	}
	s.auditAllow(r, "revoke_waiver", "waiver", id.String(), map[string]any{
		"cert_id": wvr.CertID.String(), "rule_id": wvr.RuleID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePQCInventory(w http.ResponseWriter, r *http.Request) {
	counts, err := s.store.CountPQCTags(r.Context())
	if err != nil {
		s.writeServerError(w, r, err, "failed to count pqc tags")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pqc_tags": counts})
}

func (s *Server) handleListScanFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	if _, err := s.store.GetScan(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrScanNotFound, "scan not found", "failed to load scan")
		return
	}
	findings, err := s.store.ListFindingsForScan(r.Context(), id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings})
}
