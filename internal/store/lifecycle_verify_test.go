package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUserStatus_PendingIncludesPendingVerify(t *testing.T) {
	t.Parallel()
	for _, st := range []string{
		LifecycleLaunching, LifecycleAAPPending, LifecycleAAPRunning,
		LifecycleAAPSuccessful, LifecyclePendingVerify, LifecycleVerifying,
	} {
		if got := UserStatus(st); got != "Pending" {
			t.Fatalf("UserStatus(%q)=%q want Pending", st, got)
		}
	}
	if UserStatus(LifecycleVerified) != "Verified" {
		t.Fatal("verified")
	}
	if UserStatus(LifecycleTimedOut) != "Timed out" {
		t.Fatal("timed_out")
	}
	if UserStatus(LifecycleFailed) != "Failed" {
		t.Fatal("failed")
	}
}

func TestClaimDueVerifyJobs_OnlyPendingAndDue(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	due, err := st.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind: JobKindMigrate, Status: LifecyclePendingVerify,
		IdempotencyKey: "verify-due-" + uuid.New().String(),
		Expected:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	future, err := st.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind: JobKindMigrate, Status: LifecyclePendingVerify,
		IdempotencyKey: "verify-future-" + uuid.New().String(),
		Expected:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := st.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind: JobKindRenew, Status: LifecycleVerified,
		IdempotencyKey: "verify-done-" + uuid.New().String(),
		Expected:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM lifecycle_jobs WHERE id = ANY($1)`,
			[]uuid.UUID{due.ID, future.ID, verified.ID})
	})

	if err := st.ScheduleNextVerify(ctx, due.ID, 1, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.ScheduleNextVerify(ctx, future.ID, 1, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _ = st.pool.Exec(ctx, `UPDATE lifecycle_jobs SET next_verify_at = $2 WHERE id = $1`, verified.ID, now.Add(-time.Minute))

	got, err := st.ClaimDueVerifyJobs(ctx, now, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != due.ID {
		t.Fatalf("claimed %#v, want only due %s", got, due.ID)
	}
}

func TestScheduleNextVerify_PersistsAttemptAndNext(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	job, err := st.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind: JobKindMigrate, Status: LifecycleAAPSuccessful,
		IdempotencyKey: "sched-" + uuid.New().String(),
		Expected:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM lifecycle_jobs WHERE id = $1`, job.ID)
	})

	next := time.Now().UTC().Add(30 * time.Second).Truncate(time.Second)
	if err := st.ScheduleNextVerify(ctx, job.ID, 2, next); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetLifecycleJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != LifecyclePendingVerify {
		t.Fatalf("status = %s", got.Status)
	}
	if got.VerifyAttempt != 2 {
		t.Fatalf("attempt = %d", got.VerifyAttempt)
	}
	if got.NextVerifyAt == nil || !got.NextVerifyAt.Equal(next) {
		t.Fatalf("next = %v want %v", got.NextVerifyAt, next)
	}
}

func TestClaimByIdempotency_SetsAAPRefOnce(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	key := "claim-" + uuid.New().String()
	job, err := st.InsertLifecycleJob(ctx, InsertLifecycleJobParams{
		Kind: JobKindMigrate, Status: LifecycleLaunching,
		IdempotencyKey: key, Expected: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM lifecycle_jobs WHERE id = $1`, job.ID)
	})

	got, err := st.ClaimByIdempotency(ctx, key, 42)
	if err != nil {
		t.Fatal(err)
	}
	if got.AAPJobID == nil || *got.AAPJobID != 42 {
		t.Fatalf("aap_job_id = %v", got.AAPJobID)
	}
	again, err := st.ClaimByIdempotency(ctx, key, 42)
	if err != nil {
		t.Fatal(err)
	}
	if again.AAPJobID == nil || *again.AAPJobID != 42 {
		t.Fatalf("second claim aap = %v", again.AAPJobID)
	}
	_, err = st.ClaimByIdempotency(ctx, key, 99)
	if err != ErrLifecycleAAPRefConflict {
		t.Fatalf("err = %v, want conflict", err)
	}
}
