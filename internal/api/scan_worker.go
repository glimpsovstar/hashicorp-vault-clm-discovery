package api

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanrunner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// scanClaimStore is the durable queue surface the poller needs.
type scanClaimStore interface {
	ClaimNextScans(ctx context.Context, owner string, leaseTTL time.Duration, limit int) ([]store.Scan, error)
	HeartbeatScanClaim(ctx context.Context, id uuid.UUID, owner string) error
	ReleaseScanClaim(ctx context.Context, id uuid.UUID, owner string) error
}

// ScanWorker claims pending/stale scans from Postgres (SKIP LOCKED) and runs them.
// There is no in-memory job channel — POST /scans only inserts a pending row.
type ScanWorker struct {
	srv    *Server
	store  scanClaimStore
	log    *slog.Logger
	owner  string
	slots  int
	every  time.Duration
	lease  time.Duration
	sem    chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewScanWorker builds a poller. Call Run to start claiming.
func NewScanWorker(srv *Server) *ScanWorker {
	owner := srv.cfg.ScanWorkerID
	if owner == "" {
		host, _ := os.Hostname()
		owner = host + "-" + uuid.NewString()[:8]
	}
	slots := srv.cfg.ScanWorkerSlots
	if slots <= 0 {
		slots = 2
	}
	every := srv.cfg.ScanClaimInterval
	if every <= 0 {
		every = 2 * time.Second
	}
	lease := srv.cfg.ScanLeaseTTL
	if lease <= 0 {
		lease = 30 * time.Second
	}
	var claimStore scanClaimStore
	if srv.store != nil {
		claimStore = srv.store
	}
	return &ScanWorker{
		srv:   srv,
		store: claimStore,
		log:   srv.log,
		owner: owner,
		slots: slots,
		every: every,
		lease: lease,
		sem:   make(chan struct{}, slots),
	}
}

// Run polls until ctx is cancelled, then waits for in-flight scans to release.
func (w *ScanWorker) Run(ctx context.Context) {
	if w == nil || w.store == nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	defer cancel()

	t := time.NewTicker(w.every)
	defer t.Stop()
	w.tick(runCtx)
	for {
		select {
		case <-runCtx.Done():
			w.wg.Wait()
			return
		case <-t.C:
			w.tick(runCtx)
		}
	}
}

func (w *ScanWorker) tick(ctx context.Context) {
	available := w.slots - len(w.sem)
	if available <= 0 {
		return
	}
	scans, err := w.store.ClaimNextScans(ctx, w.owner, w.lease, available)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		w.log.Warn("scan claim failed", "err", err)
		return
	}
	for _, scan := range scans {
		select {
		case w.sem <- struct{}{}:
		case <-ctx.Done():
			_ = w.store.ReleaseScanClaim(context.Background(), scan.ID, w.owner)
			return
		}
		w.wg.Add(1)
		go func(sc store.Scan) {
			defer w.wg.Done()
			defer func() { <-w.sem }()
			w.execute(ctx, sc)
		}(scan)
	}
}

func (w *ScanWorker) execute(parent context.Context, scan store.Scan) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	hbStop := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		// Heartbeat at half the lease TTL so a healthy worker is never stolen.
		interval := w.lease / 2
		if interval < time.Second {
			interval = time.Second
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-hbStop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := w.store.HeartbeatScanClaim(context.Background(), scan.ID, w.owner); err != nil {
					w.log.Warn("scan heartbeat failed", "scan_id", scan.ID.String(), "err", err)
				}
			}
		}
	}()

	runner := scanrunner.New(w.srv.store, w.srv.scanner, w.srv.log, w.srv.cfg.LogLevel, w.srv.cfg.AllowPrivateRanges)
	err := runner.Run(ctx, scanrunner.Job{
		ScanID:      scan.ID,
		CIDRs:       scan.CIDRs,
		Hostnames:   scan.Hostnames,
		Ports:       scan.Ports,
		Concurrency: scan.Concurrency,
	})
	close(hbStop)
	hbWG.Wait()

	if ctx.Err() != nil {
		_ = w.store.ReleaseScanClaim(context.Background(), scan.ID, w.owner)
		return
	}
	if err == nil {
		w.srv.maybeRecomputePostureAfterScan(context.Background(), scan.ID)
		w.srv.maybeReconcileAfterScan(context.Background(), scan.ID)
	}
}
