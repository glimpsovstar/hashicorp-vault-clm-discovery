package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Lifecycle job statuses (CLM-side). AAP statuses map into aap_* / failed.
const (
	LifecyclePendingApproval = "pending_approval"
	LifecycleLaunching       = "launching"
	LifecycleAAPPending      = "aap_pending"
	LifecycleAAPRunning      = "aap_running"
	LifecycleAAPSuccessful   = "aap_successful"
	LifecycleVerifying       = "verifying"
	LifecyclePendingVerify   = "pending_verify"
	LifecycleVerified        = "verified"
	LifecycleVerifyFailed    = "verify_failed"
	LifecycleTimedOut        = "timed_out"
	LifecycleFailed          = "failed"
)

// Job kinds on lifecycle_jobs.kind.
const (
	JobKindRenew   = "renew"
	JobKindMigrate = "migrate"
)

// ErrLifecycleAAPRefConflict is returned when ClaimByIdempotency sees a different aap_job_id.
var ErrLifecycleAAPRefConflict = errors.New("lifecycle job aap_job_id conflict")

// ErrLifecycleJobNotFound is returned when a lifecycle job id is unknown.
var ErrLifecycleJobNotFound = errors.New("lifecycle job not found")

// ErrLifecycleIdempotencyConflict is returned when InsertJob hits a duplicate key.
var ErrLifecycleIdempotencyConflict = errors.New("lifecycle job idempotency conflict")

// LifecycleJob is a durable renewal/migrate job tracked across restarts.
type LifecycleJob struct {
	ID                uuid.UUID       `json:"id"`
	Kind              string          `json:"kind"`
	Status            string          `json:"status"`
	PredecessorCertID *uuid.UUID      `json:"predecessor_cert_id,omitempty"`
	SuccessorCertID   *uuid.UUID      `json:"successor_cert_id,omitempty"`
	AAPJobID          *int            `json:"aap_job_id,omitempty"`
	AAPWorkflow       bool            `json:"aap_workflow"`
	IdempotencyKey    string          `json:"idempotency_key"`
	Expected          json.RawMessage `json:"expected"`
	Observed          json.RawMessage `json:"observed"`
	FailureReason     *string         `json:"failure_reason,omitempty"`
	LeaseOwner        *string         `json:"lease_owner,omitempty"`
	LeaseExpiresAt    *time.Time      `json:"lease_expires_at,omitempty"`
	NextVerifyAt      *time.Time      `json:"next_verify_at,omitempty"`
	TimeoutAt         time.Time       `json:"timeout_at"`
	VerifyAttempt     int             `json:"verify_attempt"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// UserStatus maps durable job statuses to operator-facing badges.
func UserStatus(status string) string {
	switch status {
	case LifecycleVerified:
		return "Verified"
	case LifecycleTimedOut:
		return "Timed out"
	case LifecycleFailed, LifecycleVerifyFailed:
		return "Failed"
	case LifecycleLaunching, LifecycleAAPPending, LifecycleAAPRunning, LifecycleAAPSuccessful,
		LifecycleVerifying, LifecyclePendingVerify, LifecyclePendingApproval:
		return "Pending"
	default:
		return "Pending"
	}
}

// LifecycleJobEvent is an append-only timeline entry for a lifecycle job.
type LifecycleJobEvent struct {
	ID        uuid.UUID       `json:"id"`
	JobID     uuid.UUID       `json:"job_id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

// InsertLifecycleJobParams creates a new durable job row.
type InsertLifecycleJobParams struct {
	Kind              string
	Status            string
	PredecessorCertID *uuid.UUID
	IdempotencyKey    string
	Expected          json.RawMessage
	AAPJobID          *int
	AAPWorkflow       bool
}

// RenewIdempotencyKey builds a stable key so the same cert renew is not launched twice.
func RenewIdempotencyKey(certID uuid.UUID, fingerprint string) string {
	return fmt.Sprintf("renew:%s:%s", certID.String(), fingerprint)
}

// MigrateIdempotencyKey builds a stable key for Mode C migrate jobs.
func MigrateIdempotencyKey(certID uuid.UUID, fingerprint string) string {
	return fmt.Sprintf("migrate:%s:%s", certID.String(), fingerprint)
}

// InsertLifecycleJob inserts a job row. On unique idempotency conflict it returns
// ErrLifecycleIdempotencyConflict (caller may Get by key).
func (s *Store) InsertLifecycleJob(ctx context.Context, p InsertLifecycleJobParams) (LifecycleJob, error) {
	if p.Kind == "" {
		p.Kind = "renew"
	}
	if p.Status == "" {
		p.Status = LifecycleLaunching
	}
	if len(p.Expected) == 0 {
		p.Expected = json.RawMessage(`{}`)
	}
	var job LifecycleJob
	err := s.pool.QueryRow(ctx, `
		INSERT INTO lifecycle_jobs (
			kind, status, predecessor_cert_id, idempotency_key, expected,
			aap_job_id, aap_workflow
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, kind, status, predecessor_cert_id, successor_cert_id,
			aap_job_id, aap_workflow, idempotency_key, expected, observed,
			failure_reason, lease_owner, lease_expires_at,
			next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	`, p.Kind, p.Status, p.PredecessorCertID, p.IdempotencyKey, p.Expected,
		p.AAPJobID, p.AAPWorkflow).Scan(
		&job.ID, &job.Kind, &job.Status, &job.PredecessorCertID, &job.SuccessorCertID,
		&job.AAPJobID, &job.AAPWorkflow, &job.IdempotencyKey, &job.Expected, &job.Observed,
		&job.FailureReason, &job.LeaseOwner, &job.LeaseExpiresAt,
		&job.NextVerifyAt, &job.TimeoutAt, &job.VerifyAttempt, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return LifecycleJob{}, ErrLifecycleIdempotencyConflict
		}
		return LifecycleJob{}, err
	}
	return job, nil
}

// GetLifecycleJobByIdempotency returns the job for a key, or ErrLifecycleJobNotFound.
func (s *Store) GetLifecycleJobByIdempotency(ctx context.Context, key string) (LifecycleJob, error) {
	return s.scanLifecycleJob(s.pool.QueryRow(ctx, lifecycleJobSelect+` WHERE idempotency_key = $1`, key))
}

// GetLifecycleJob returns a job by id.
func (s *Store) GetLifecycleJob(ctx context.Context, id uuid.UUID) (LifecycleJob, error) {
	return s.scanLifecycleJob(s.pool.QueryRow(ctx, lifecycleJobSelect+` WHERE id = $1`, id))
}

// ListLifecycleJobsByCert returns jobs for a predecessor certificate (newest first).
func (s *Store) ListLifecycleJobsByCert(ctx context.Context, certID uuid.UUID, limit int) ([]LifecycleJob, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, lifecycleJobSelect+`
		WHERE predecessor_cert_id = $1
		ORDER BY created_at DESC LIMIT $2
	`, certID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LifecycleJob{}
	for rows.Next() {
		job, err := scanLifecycleJobRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// SetLifecycleAAPRef stores the Controller job id after a successful launch.
func (s *Store) SetLifecycleAAPRef(ctx context.Context, id uuid.UUID, aapJobID int, workflow bool, status string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE lifecycle_jobs SET
			aap_job_id = $2,
			aap_workflow = $3,
			status = $4,
			updated_at = NOW()
		WHERE id = $1
	`, id, aapJobID, workflow, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLifecycleJobNotFound
	}
	return nil
}

// UpdateLifecycleStatus updates status and optional failure reason / JSON blobs.
type UpdateLifecycleStatusParams struct {
	Status          string
	FailureReason   *string
	Expected        json.RawMessage
	Observed        json.RawMessage
	SuccessorCertID *uuid.UUID
	ClearLease      bool
}

// UpdateLifecycleStatus sets status fields on a job. Empty Status leaves the
// current status unchanged (used to clear a lease after a partial step).
func (s *Store) UpdateLifecycleStatus(ctx context.Context, id uuid.UUID, p UpdateLifecycleStatusParams) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE lifecycle_jobs SET
			status = CASE WHEN $2 = '' THEN status ELSE $2 END,
			failure_reason = COALESCE($3, failure_reason),
			expected = COALESCE($4, expected),
			observed = COALESCE($5, observed),
			successor_cert_id = COALESCE($6, successor_cert_id),
			lease_owner = CASE WHEN $7 THEN NULL ELSE lease_owner END,
			lease_expires_at = CASE WHEN $7 THEN NULL ELSE lease_expires_at END,
			updated_at = NOW()
		WHERE id = $1
	`, id, p.Status, p.FailureReason, nullJSON(p.Expected), nullJSON(p.Observed),
		p.SuccessorCertID, p.ClearLease)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLifecycleJobNotFound
	}
	return nil
}

// AppendRenewalOutboxEvent writes a renewal.* event to the EDA outbox.
func (s *Store) AppendRenewalOutboxEvent(ctx context.Context, eventType string, certID *uuid.UUID, payload json.RawMessage) error {
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	return appendEventStandalone(ctx, s, eventType, certID, payload)
}

// AppendLifecycleJobEvent appends a timeline row for the job.
func (s *Store) AppendLifecycleJobEvent(ctx context.Context, jobID uuid.UUID, eventType string, payload json.RawMessage) error {
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO lifecycle_job_events (job_id, event_type, payload)
		VALUES ($1, $2, $3)
	`, jobID, eventType, payload)
	return err
}

// InsertLifecycleApproval records an approval decision for a job.
func (s *Store) InsertLifecycleApproval(ctx context.Context, jobID uuid.UUID, actor, decision string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO lifecycle_approvals (job_id, actor, decision)
		VALUES ($1, $2, $3)
	`, jobID, actor, decision)
	return err
}

// ClaimLifecycleJobs claims up to limit jobs whose lease is expired or unset and
// whose status is still in-flight. Uses FOR UPDATE SKIP LOCKED.
func (s *Store) ClaimLifecycleJobs(ctx context.Context, owner string, leaseTTL time.Duration, limit int) ([]LifecycleJob, error) {
	if leaseTTL <= 0 {
		leaseTTL = 2 * time.Minute
	}
	if limit <= 0 {
		limit = 10
	}
	expires := time.Now().UTC().Add(leaseTTL)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id FROM lifecycle_jobs
		WHERE status IN (
			'launching', 'aap_pending', 'aap_running', 'aap_successful', 'verifying', 'pending_verify'
		)
		AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []LifecycleJob{}, tx.Commit(ctx)
	}

	_, err = tx.Exec(ctx, `
		UPDATE lifecycle_jobs SET
			lease_owner = $2,
			lease_expires_at = $3,
			updated_at = NOW()
		WHERE id = ANY($1)
	`, ids, owner, expires)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	out := make([]LifecycleJob, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetLifecycleJob(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, nil
}

// PersistRenewLaunch writes renewal config, inserts a lifecycle job with AAP ref,
// appends job timeline + outbox renewal.launched in one transaction.
func (s *Store) PersistRenewLaunch(ctx context.Context, certID uuid.UUID, cfg RenewalConfig, fingerprint string, aapJobID int, workflow bool, expected json.RawMessage) (LifecycleJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LifecycleJob{}, err
	}
	defer tx.Rollback(ctx)

	data, err := json.Marshal(cfg)
	if err != nil {
		return LifecycleJob{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE certificates SET renewal_config = $2, updated_at = NOW() WHERE id = $1
	`, certID, data)
	if err != nil {
		return LifecycleJob{}, err
	}
	if tag.RowsAffected() == 0 {
		return LifecycleJob{}, ErrCertificateNotFound
	}

	key := RenewIdempotencyKey(certID, fingerprint)
	if len(expected) == 0 {
		expected = json.RawMessage(`{}`)
	}
	var job LifecycleJob
	err = tx.QueryRow(ctx, `
		INSERT INTO lifecycle_jobs (
			kind, status, predecessor_cert_id, idempotency_key, expected,
			aap_job_id, aap_workflow
		) VALUES ('renew', $1, $2, $3, $4, $5, $6)
		RETURNING id, kind, status, predecessor_cert_id, successor_cert_id,
			aap_job_id, aap_workflow, idempotency_key, expected, observed,
			failure_reason, lease_owner, lease_expires_at,
			next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	`, LifecycleAAPPending, certID, key, expected, aapJobID, workflow).Scan(
		&job.ID, &job.Kind, &job.Status, &job.PredecessorCertID, &job.SuccessorCertID,
		&job.AAPJobID, &job.AAPWorkflow, &job.IdempotencyKey, &job.Expected, &job.Observed,
		&job.FailureReason, &job.LeaseOwner, &job.LeaseExpiresAt,
		&job.NextVerifyAt, &job.TimeoutAt, &job.VerifyAttempt, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return LifecycleJob{}, ErrLifecycleIdempotencyConflict
		}
		return LifecycleJob{}, err
	}

	payload, _ := json.Marshal(map[string]any{
		"aap_job_id": aapJobID, "workflow": workflow, "certificate_id": certID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_job_events (job_id, event_type, payload)
		VALUES ($1, 'job.launched', $2)
	`, job.ID, payload); err != nil {
		return LifecycleJob{}, err
	}
	if err := appendEventTx(ctx, tx, "renewal.launched", &certID, payload); err != nil {
		return LifecycleJob{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_approvals (job_id, actor, decision)
		VALUES ($1, 'consent', 'auto_approved')
	`, job.ID); err != nil {
		return LifecycleJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleJob{}, err
	}
	return job, nil
}

// InsertLifecycleJobPending inserts a batch renew job without an AAP id (worker launches).
func (s *Store) InsertLifecycleJobPending(ctx context.Context, certID uuid.UUID, fingerprint string, expected json.RawMessage) (LifecycleJob, error) {
	key := RenewIdempotencyKey(certID, fingerprint)
	job, err := s.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind:              "renew",
		Status:            LifecycleLaunching,
		PredecessorCertID: &certID,
		IdempotencyKey:    key,
		Expected:          expected,
	})
	if err != nil {
		return LifecycleJob{}, err
	}
	_ = s.InsertLifecycleApproval(ctx, job.ID, "consent", "auto_approved")
	payload, _ := json.Marshal(map[string]any{"certificate_id": certID})
	_ = s.AppendLifecycleJobEvent(ctx, job.ID, "job.enqueued", payload)
	_ = appendEventStandalone(ctx, s, "renewal.requested", &certID, payload)
	return job, nil
}

// PersistMigrateLaunch writes renewal config, inserts a migrate job in pending_verify
// with AAP ref, and emits renewal.requested then renewal.launched before return.
func (s *Store) PersistMigrateLaunch(ctx context.Context, certID uuid.UUID, cfg RenewalConfig, fingerprint string, aapJobID int, workflow bool, expected json.RawMessage, timeout time.Duration, nextVerifyAt time.Time) (LifecycleJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LifecycleJob{}, err
	}
	defer tx.Rollback(ctx)

	data, err := json.Marshal(cfg)
	if err != nil {
		return LifecycleJob{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE certificates SET renewal_config = $2, updated_at = NOW() WHERE id = $1
	`, certID, data)
	if err != nil {
		return LifecycleJob{}, err
	}
	if tag.RowsAffected() == 0 {
		return LifecycleJob{}, ErrCertificateNotFound
	}

	key := MigrateIdempotencyKey(certID, fingerprint)
	if len(expected) == 0 {
		expected = json.RawMessage(`{}`)
	}
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	timeoutAt := time.Now().UTC().Add(timeout)
	if nextVerifyAt.IsZero() {
		nextVerifyAt = time.Now().UTC().Add(10 * time.Second)
	}
	var job LifecycleJob
	err = tx.QueryRow(ctx, `
		INSERT INTO lifecycle_jobs (
			kind, status, predecessor_cert_id, idempotency_key, expected,
			aap_job_id, aap_workflow, next_verify_at, timeout_at, verify_attempt
		) VALUES ('migrate', $1, $2, $3, $4, $5, $6, $7, $8, 0)
		RETURNING id, kind, status, predecessor_cert_id, successor_cert_id,
			aap_job_id, aap_workflow, idempotency_key, expected, observed,
			failure_reason, lease_owner, lease_expires_at,
			next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	`, LifecyclePendingVerify, certID, key, expected, aapJobID, workflow, nextVerifyAt.UTC(), timeoutAt).Scan(
		&job.ID, &job.Kind, &job.Status, &job.PredecessorCertID, &job.SuccessorCertID,
		&job.AAPJobID, &job.AAPWorkflow, &job.IdempotencyKey, &job.Expected, &job.Observed,
		&job.FailureReason, &job.LeaseOwner, &job.LeaseExpiresAt,
		&job.NextVerifyAt, &job.TimeoutAt, &job.VerifyAttempt, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return LifecycleJob{}, ErrLifecycleIdempotencyConflict
		}
		return LifecycleJob{}, err
	}

	reqPayload, _ := json.Marshal(map[string]any{"certificate_id": certID, "kind": "migrate"})
	if err := appendEventTx(ctx, tx, "renewal.requested", &certID, reqPayload); err != nil {
		return LifecycleJob{}, err
	}
	launchPayload, _ := json.Marshal(map[string]any{
		"aap_job_id": aapJobID, "workflow": workflow, "certificate_id": certID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_job_events (job_id, event_type, payload)
		VALUES ($1, 'job.launched', $2)
	`, job.ID, launchPayload); err != nil {
		return LifecycleJob{}, err
	}
	if err := appendEventTx(ctx, tx, "renewal.launched", &certID, launchPayload); err != nil {
		return LifecycleJob{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_approvals (job_id, actor, decision)
		VALUES ($1, 'consent', 'auto_approved')
	`, job.ID); err != nil {
		return LifecycleJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleJob{}, err
	}
	return job, nil
}

// InsertMigrateJobPending inserts a batch migrate job (EDA launches AAP).
func (s *Store) InsertMigrateJobPending(ctx context.Context, certID uuid.UUID, fingerprint string, expected json.RawMessage, timeout time.Duration, nextVerifyAt time.Time) (LifecycleJob, error) {
	key := MigrateIdempotencyKey(certID, fingerprint)
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	if nextVerifyAt.IsZero() {
		nextVerifyAt = time.Now().UTC().Add(10 * time.Second)
	}
	timeoutAt := time.Now().UTC().Add(timeout)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LifecycleJob{}, err
	}
	defer tx.Rollback(ctx)
	if len(expected) == 0 {
		expected = json.RawMessage(`{}`)
	}
	var job LifecycleJob
	err = tx.QueryRow(ctx, `
		INSERT INTO lifecycle_jobs (
			kind, status, predecessor_cert_id, idempotency_key, expected,
			next_verify_at, timeout_at, verify_attempt
		) VALUES ('migrate', $1, $2, $3, $4, $5, $6, 0)
		RETURNING id, kind, status, predecessor_cert_id, successor_cert_id,
			aap_job_id, aap_workflow, idempotency_key, expected, observed,
			failure_reason, lease_owner, lease_expires_at,
			next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	`, LifecyclePendingVerify, certID, key, expected, nextVerifyAt.UTC(), timeoutAt).Scan(
		&job.ID, &job.Kind, &job.Status, &job.PredecessorCertID, &job.SuccessorCertID,
		&job.AAPJobID, &job.AAPWorkflow, &job.IdempotencyKey, &job.Expected, &job.Observed,
		&job.FailureReason, &job.LeaseOwner, &job.LeaseExpiresAt,
		&job.NextVerifyAt, &job.TimeoutAt, &job.VerifyAttempt, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return LifecycleJob{}, ErrLifecycleIdempotencyConflict
		}
		return LifecycleJob{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_approvals (job_id, actor, decision)
		VALUES ($1, 'consent', 'auto_approved')
	`, job.ID); err != nil {
		return LifecycleJob{}, err
	}
	payload, _ := json.Marshal(map[string]any{"certificate_id": certID, "kind": "migrate"})
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_job_events (job_id, event_type, payload)
		VALUES ($1, 'job.enqueued', $2)
	`, job.ID, payload); err != nil {
		return LifecycleJob{}, err
	}
	if err := appendEventTx(ctx, tx, "renewal.requested", &certID, payload); err != nil {
		return LifecycleJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LifecycleJob{}, err
	}
	return job, nil
}

func appendEventStandalone(ctx context.Context, s *Store, eventType string, certID *uuid.UUID, payload []byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := appendEventTx(ctx, tx, eventType, certID, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const lifecycleJobSelect = `
	SELECT id, kind, status, predecessor_cert_id, successor_cert_id,
		aap_job_id, aap_workflow, idempotency_key, expected, observed,
		failure_reason, lease_owner, lease_expires_at,
		next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	FROM lifecycle_jobs
`

type scannable interface {
	Scan(dest ...any) error
}

func (s *Store) scanLifecycleJob(row scannable) (LifecycleJob, error) {
	job, err := scanLifecycleJobRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return LifecycleJob{}, ErrLifecycleJobNotFound
	}
	return job, err
}

func scanLifecycleJobRow(row scannable) (LifecycleJob, error) {
	var job LifecycleJob
	err := row.Scan(
		&job.ID, &job.Kind, &job.Status, &job.PredecessorCertID, &job.SuccessorCertID,
		&job.AAPJobID, &job.AAPWorkflow, &job.IdempotencyKey, &job.Expected, &job.Observed,
		&job.FailureReason, &job.LeaseOwner, &job.LeaseExpiresAt,
		&job.NextVerifyAt, &job.TimeoutAt, &job.VerifyAttempt, &job.CreatedAt, &job.UpdatedAt,
	)
	return job, err
}

// ClaimDueVerifyJobs claims pending_verify jobs whose next_verify_at is due.
func (s *Store) ClaimDueVerifyJobs(ctx context.Context, now time.Time, limit int, leaseTTL time.Duration) ([]LifecycleJob, error) {
	if leaseTTL <= 0 {
		leaseTTL = 2 * time.Minute
	}
	if limit <= 0 {
		limit = 10
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expires := now.Add(leaseTTL)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id FROM lifecycle_jobs
		WHERE status = 'pending_verify'
		  AND next_verify_at IS NOT NULL
		  AND next_verify_at <= $1
		  AND timeout_at > $1
		  AND (lease_expires_at IS NULL OR lease_expires_at < $1)
		ORDER BY next_verify_at
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []LifecycleJob{}, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `
		UPDATE lifecycle_jobs SET
			lease_owner = 'verify-worker',
			lease_expires_at = $2,
			updated_at = NOW()
		WHERE id = ANY($1)
	`, ids, expires)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	out := make([]LifecycleJob, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetLifecycleJob(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, nil
}

// ScheduleNextVerify sets pending_verify with the next backoff attempt.
func (s *Store) ScheduleNextVerify(ctx context.Context, id uuid.UUID, attempt int, next time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE lifecycle_jobs SET
			status = $2,
			verify_attempt = $3,
			next_verify_at = $4,
			lease_owner = NULL,
			lease_expires_at = NULL,
			updated_at = NOW()
		WHERE id = $1
	`, id, LifecyclePendingVerify, attempt, next.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLifecycleJobNotFound
	}
	return nil
}

// ExpireTimedOutVerifyJobs marks overdue pending_verify jobs as timed_out and
// returns them so the worker can emit renewal.timed_out.
func (s *Store) ExpireTimedOutVerifyJobs(ctx context.Context, now time.Time) ([]LifecycleJob, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE lifecycle_jobs SET
			status = $2,
			lease_owner = NULL,
			lease_expires_at = NULL,
			failure_reason = COALESCE(failure_reason, 'verify timeout'),
			updated_at = NOW()
		WHERE status = 'pending_verify'
		  AND timeout_at <= $1
		RETURNING id, kind, status, predecessor_cert_id, successor_cert_id,
			aap_job_id, aap_workflow, idempotency_key, expected, observed,
			failure_reason, lease_owner, lease_expires_at,
			next_verify_at, timeout_at, verify_attempt, created_at, updated_at
	`, now, LifecycleTimedOut)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LifecycleJob
	for rows.Next() {
		job, err := scanLifecycleJobRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// ClaimByIdempotency attaches an AAP job id to an existing outbox-driven job
// (policy/batch path). Same aap_job_id is idempotent; a different id conflicts.
func (s *Store) ClaimByIdempotency(ctx context.Context, key string, aapJobID int) (LifecycleJob, error) {
	job, err := s.GetLifecycleJobByIdempotency(ctx, key)
	if err != nil {
		return LifecycleJob{}, err
	}
	if job.AAPJobID != nil {
		if *job.AAPJobID == aapJobID {
			return job, nil
		}
		return LifecycleJob{}, ErrLifecycleAAPRefConflict
	}
	if err := s.SetLifecycleAAPRef(ctx, job.ID, aapJobID, job.AAPWorkflow, LifecycleAAPPending); err != nil {
		return LifecycleJob{}, err
	}
	return s.GetLifecycleJob(ctx, job.ID)
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func isUniqueViolation(err error) bool {
	// pgx wraps pgconn.PgError; string match avoids importing pgconn in every call site.
	return err != nil && (strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "23505"))
}
