package lifecyclejobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// JobStore is the durable job surface the worker needs.
type JobStore interface {
	ClaimLifecycleJobs(ctx context.Context, owner string, leaseTTL time.Duration, limit int) ([]store.LifecycleJob, error)
	ClaimDueVerifyJobs(ctx context.Context, now time.Time, limit int, leaseTTL time.Duration) ([]store.LifecycleJob, error)
	GetCertificate(ctx context.Context, id uuid.UUID) (store.Certificate, error)
	ListCertificates(ctx context.Context, f store.CertificateFilter) ([]store.Certificate, int, error)
	SetLifecycleAAPRef(ctx context.Context, id uuid.UUID, aapJobID int, workflow bool, status string) error
	UpdateLifecycleStatus(ctx context.Context, id uuid.UUID, p store.UpdateLifecycleStatusParams) error
	ScheduleNextVerify(ctx context.Context, id uuid.UUID, attempt int, next time.Time) error
	ExpireTimedOutVerifyJobs(ctx context.Context, now time.Time) ([]store.LifecycleJob, error)
	AppendLifecycleJobEvent(ctx context.Context, jobID uuid.UUID, eventType string, payload json.RawMessage) error
	AppendRenewalOutboxEvent(ctx context.Context, eventType string, certID *uuid.UUID, payload json.RawMessage) error
}

// Renewer launches AAP renewals for batch-enqueued jobs (no aap_job_id yet).
type Renewer interface {
	Renew(ctx context.Context, extraVars map[string]any) (jobID int, workflow bool, err error)
}

// AAPPoller polls Controller job status (WaitForJob / JobStatus).
type AAPPoller interface {
	WaitForJob(ctx context.Context, jobID int, workflow bool, interval time.Duration) (aap.Status, error)
}

// Config holds worker settings.
type Config struct {
	Owner     string
	Interval  time.Duration
	LeaseTTL  time.Duration
	BatchSize int
	PollEvery time.Duration
	Now       func() time.Time // optional clock for tests
}

// Worker claims durable lifecycle jobs, launches AAP when needed, polls, and verifies.
type Worker struct {
	cfg     Config
	store   JobStore
	renewer Renewer
	aap     AAPPoller
	log     *slog.Logger
}

// New builds a worker. Renewer/AAP may be nil (noop ticks) when AAP is unset.
func New(cfg Config, st JobStore, renewer Renewer, poller AAPPoller, log *slog.Logger) *Worker {
	if cfg.Owner == "" {
		cfg.Owner = "lifecycle-worker"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 2 * time.Minute
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 5 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Worker{cfg: cfg, store: st, renewer: renewer, aap: poller, log: log}
}

// Run polls until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	now := w.cfg.Now().UTC()
	if err := w.expireTimedOut(ctx, now); err != nil {
		w.log.Warn("lifecycle timeout sweep failed", "err", err)
	}
	jobs, err := w.store.ClaimLifecycleJobs(ctx, w.cfg.Owner, w.cfg.LeaseTTL, w.cfg.BatchSize)
	if err != nil {
		w.log.Warn("lifecycle claim failed", "err", err)
		return
	}
	for _, job := range jobs {
		if err := w.process(ctx, job); err != nil {
			w.log.Warn("lifecycle job failed", "job_id", job.ID.String(), "status", job.Status, "err", err)
		}
	}
	due, err := w.store.ClaimDueVerifyJobs(ctx, now, w.cfg.BatchSize, w.cfg.LeaseTTL)
	if err != nil {
		w.log.Warn("lifecycle verify claim failed", "err", err)
		return
	}
	for _, job := range due {
		if err := w.verifyPending(ctx, job, now); err != nil {
			w.log.Warn("lifecycle verify failed", "job_id", job.ID.String(), "err", err)
		}
	}
}

func (w *Worker) expireTimedOut(ctx context.Context, now time.Time) error {
	expired, err := w.store.ExpireTimedOutVerifyJobs(ctx, now)
	if err != nil {
		return err
	}
	for _, job := range expired {
		payload, _ := json.Marshal(map[string]any{"timeout_at": job.TimeoutAt.UTC().Format(time.RFC3339)})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.timed_out", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.timed_out", job.PredecessorCertID, payload)
	}
	return nil
}

func (w *Worker) process(ctx context.Context, job store.LifecycleJob) error {
	switch job.Status {
	case store.LifecycleLaunching:
		return w.launch(ctx, job)
	case store.LifecycleAAPPending, store.LifecycleAAPRunning:
		return w.pollAAP(ctx, job)
	case store.LifecycleAAPSuccessful:
		return w.enterPendingVerify(ctx, job)
	case store.LifecycleVerifying:
		// Legacy M2 path: treat as an immediate pending_verify probe.
		return w.verifyPending(ctx, job, w.cfg.Now().UTC())
	case store.LifecyclePendingVerify:
		now := w.cfg.Now().UTC()
		if job.NextVerifyAt != nil && job.NextVerifyAt.After(now) {
			_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{ClearLease: true})
			return nil
		}
		return w.verifyPending(ctx, job, now)
	default:
		reason := "unexpected status"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		return nil
	}
}

func (w *Worker) launch(ctx context.Context, job store.LifecycleJob) error {
	// Restart recovery: never double-launch when AAP id is already set.
	if job.AAPJobID != nil && *job.AAPJobID > 0 {
		return w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleAAPPending, ClearLease: true,
		})
	}
	if w.renewer == nil || job.PredecessorCertID == nil {
		reason := "aap renewer not configured or missing predecessor"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		return fmt.Errorf("%s", reason)
	}
	cert, err := w.store.GetCertificate(ctx, *job.PredecessorCertID)
	if err != nil {
		return err
	}
	if cert.RenewalConfig == nil {
		reason := "missing renewal config"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		return fmt.Errorf("%s", reason)
	}
	cn := ""
	if cert.SubjectCN != nil {
		cn = *cert.SubjectCN
	}
	cfg := *cert.RenewalConfig
	extra := map[string]any{
		"cert_common_name_override": cn,
		"vault_pki_mount":           cfg.Mount,
		"vault_pki_role":            cfg.Role,
	}
	if cfg.Service != "" {
		extra["cert_service_type"] = cfg.Service
	}
	if cfg.TargetHosts != "" {
		extra["target_hosts"] = cfg.TargetHosts
	}
	if cfg.TTL != "" {
		extra["vault_cert_ttl"] = cfg.TTL
	}
	if cfg.AltNames != "" {
		extra["cert_alt_names_override"] = cfg.AltNames
	}
	jobID, workflow, err := w.renewer.Renew(ctx, extra)
	if err != nil {
		reason := "aap launch failed: " + err.Error()
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		payload, _ := json.Marshal(map[string]any{"error": err.Error()})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.failed", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.failed", job.PredecessorCertID, payload)
		return err
	}
	if err := w.store.SetLifecycleAAPRef(ctx, job.ID, jobID, workflow, store.LifecycleAAPPending); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"aap_job_id": jobID, "workflow": workflow})
	_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.launched", payload)
	_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.launched", job.PredecessorCertID, payload)
	_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{ClearLease: true})
	return nil
}

func (w *Worker) pollAAP(ctx context.Context, job store.LifecycleJob) error {
	if job.AAPJobID == nil || w.aap == nil {
		reason := "missing aap job id or poller"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		return fmt.Errorf("%s", reason)
	}
	// Bound wait to lease window so we re-claim on restart instead of blocking forever.
	waitCtx, cancel := context.WithTimeout(ctx, w.cfg.LeaseTTL)
	defer cancel()
	st, err := w.aap.WaitForJob(waitCtx, *job.AAPJobID, job.AAPWorkflow, w.cfg.PollEvery)
	if err != nil {
		// Timeout / cancel: leave status, clear lease so another tick can resume.
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{ClearLease: true})
		return err
	}
	mapped := MapAAPStatus(st)
	if mapped == store.LifecycleFailed {
		reason := "aap job " + string(st)
		payload, _ := json.Marshal(map[string]any{"aap_status": string(st)})
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.failed", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.failed", job.PredecessorCertID, payload)
		return nil
	}
	if mapped == store.LifecycleAAPSuccessful {
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.aap_successful", json.RawMessage(`{}`))
		return w.enterPendingVerify(ctx, job)
	}
	_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
		Status: mapped, ClearLease: true,
	})
	return nil
}

func (w *Worker) enterPendingVerify(ctx context.Context, job store.LifecycleJob) error {
	now := w.cfg.Now().UTC()
	timeoutAt := job.TimeoutAt
	if timeoutAt.IsZero() {
		timeoutAt = now.Add(24 * time.Hour)
	}
	next, _ := NextVerifyAt(now, 1, timeoutAt)
	if err := w.store.ScheduleNextVerify(ctx, job.ID, 0, next); err != nil {
		return err
	}
	return nil
}

func (w *Worker) verifyPending(ctx context.Context, job store.LifecycleJob, now time.Time) error {
	timeoutAt := job.TimeoutAt
	if timeoutAt.IsZero() {
		timeoutAt = now.Add(24 * time.Hour)
	}
	if !now.Before(timeoutAt) {
		reason := "verify timeout"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleTimedOut, FailureReason: &reason, ClearLease: true,
		})
		payload, _ := json.Marshal(map[string]any{"timeout_at": timeoutAt.UTC().Format(time.RFC3339)})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.timed_out", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.timed_out", job.PredecessorCertID, payload)
		return nil
	}

	expected, err := UnmarshalExpected(job.Expected)
	if err != nil {
		reason := "invalid expected payload"
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleFailed, FailureReason: &reason, ClearLease: true,
		})
		return err
	}
	observed, err := w.observeSuccessor(ctx, expected)
	if err != nil {
		return err
	}
	obsJSON, _ := json.Marshal(observed)
	result := VerifyWire(expected, observed)
	if result.OK {
		var successorID *uuid.UUID
		if observed.SuccessorCertID != "" {
			if id, err := uuid.Parse(observed.SuccessorCertID); err == nil {
				successorID = &id
			}
		}
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleVerified, Observed: obsJSON, SuccessorCertID: successorID, ClearLease: true,
		})
		payload, _ := json.Marshal(map[string]any{"observed": observed})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.verified", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.verified", job.PredecessorCertID, payload)
		return nil
	}

	attempt := job.VerifyAttempt + 1
	next, last := NextVerifyAt(now, attempt, timeoutAt)
	if last && !next.After(now) {
		reason := result.Reason
		_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
			Status: store.LifecycleTimedOut, FailureReason: &reason, Observed: obsJSON, ClearLease: true,
		})
		payload, _ := json.Marshal(map[string]any{"reason": reason, "observed": observed})
		_ = w.store.AppendLifecycleJobEvent(ctx, job.ID, "job.timed_out", payload)
		_ = w.store.AppendRenewalOutboxEvent(ctx, "renewal.timed_out", job.PredecessorCertID, payload)
		return nil
	}
	_ = w.store.UpdateLifecycleStatus(ctx, job.ID, store.UpdateLifecycleStatusParams{
		Observed: obsJSON,
	})
	return w.store.ScheduleNextVerify(ctx, job.ID, attempt, next)
}

func (w *Worker) observeSuccessor(ctx context.Context, expected ExpectedWire) (ObservedWire, error) {
	if expected.CommonName == "" {
		return ObservedWire{}, nil
	}
	certs, _, err := w.store.ListCertificates(ctx, store.CertificateFilter{
		Search: expected.CommonName,
		Limit:  50,
	})
	if err != nil {
		return ObservedWire{}, err
	}
	var best *store.Certificate
	for i := range certs {
		c := &certs[i]
		if c.SubjectCN == nil || *c.SubjectCN != expected.CommonName {
			continue
		}
		if c.FingerprintSHA256 == expected.PredecessorFP {
			continue
		}
		if best == nil || c.NotAfter.After(best.NotAfter) {
			best = c
		}
	}
	if best == nil {
		return ObservedWire{CommonName: expected.CommonName}, nil
	}
	return ObservedWire{
		CommonName:      *best.SubjectCN,
		Fingerprint:     best.FingerprintSHA256,
		NotAfter:        best.NotAfter,
		SuccessorCertID: best.ID.String(),
		ManagedInVault:  best.ManagedStatus == "managed_in_vault",
	}, nil
}
