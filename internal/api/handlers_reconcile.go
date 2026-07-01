package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

// reconcileAfterScanTimeout bounds the best-effort reconcile that runs on the
// single scan worker after a scan completes.
const reconcileAfterScanTimeout = 2 * time.Minute

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
	// This runs on the single scan worker with a background context; bound it so
	// an unresponsive Vault cannot block all subsequent scans indefinitely.
	ctx, cancel := context.WithTimeout(ctx, reconcileAfterScanTimeout)
	defer cancel()
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
