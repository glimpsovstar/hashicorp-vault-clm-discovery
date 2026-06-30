package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

type reconcileRunner interface {
	Reconcile(ctx context.Context) (vault.Summary, error)
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VaultAddr == "" {
		writeError(w, r, http.StatusServiceUnavailable, "vault not configured")
		return
	}
	if s.reconciler == nil {
		writeError(w, r, http.StatusServiceUnavailable, "vault not configured")
		return
	}

	summary, err := s.reconciler.Reconcile(r.Context())
	if err != nil {
		s.writeServerError(w, r, err, "reconcile failed")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) maybeReconcileAfterScan(ctx context.Context, scanID uuid.UUID) {
	if !s.cfg.ReconcileOnScanComplete || s.reconciler == nil {
		return
	}
	summary, err := s.reconciler.Reconcile(ctx)
	if err != nil {
		s.log.Warn("reconcile after scan failed", "scan_id", scanID, "err", err)
		return
	}
	s.log.Info("reconcile after scan complete",
		"scan_id", scanID,
		"matched", summary.Matched,
		"unmatched_clm", summary.UnmatchedCLM,
	)
}
