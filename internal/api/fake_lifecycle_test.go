package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeLifecycleStore struct {
	job            store.LifecycleJob
	jobs           []store.LifecycleJob
	persistErr     error
	migrateErr     error
	pendingErr     error
	migratePending error
	getErr         error
	listErr        error
	byKeyErr       error
	claimErr       error
	gotPersist     bool
	gotMigrate     bool
	gotPending     int
	gotMigratePend int
	gotClaim       int
	gotRenewalCfg  *store.RenewalConfig
	lastAAPJobID   int
	launchedEvents int
	renewCalls     int
}

func (f *fakeLifecycleStore) PersistRenewLaunch(_ context.Context, certID uuid.UUID, cfg store.RenewalConfig, _ string, aapJobID int, workflow bool, expected json.RawMessage) (store.LifecycleJob, error) {
	f.gotPersist = true
	f.gotRenewalCfg = &cfg
	f.lastAAPJobID = aapJobID
	if f.persistErr != nil {
		return store.LifecycleJob{}, f.persistErr
	}
	id := f.job.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return store.LifecycleJob{
		ID: id, Status: store.LifecycleAAPPending, PredecessorCertID: &certID,
		AAPJobID: &aapJobID, AAPWorkflow: workflow, Expected: expected, Kind: store.JobKindRenew,
	}, nil
}

func (f *fakeLifecycleStore) PersistMigrateLaunch(_ context.Context, certID uuid.UUID, cfg store.RenewalConfig, _ string, aapJobID int, workflow bool, expected json.RawMessage, timeout time.Duration, nextVerifyAt time.Time) (store.LifecycleJob, error) {
	f.gotMigrate = true
	f.gotRenewalCfg = &cfg
	f.lastAAPJobID = aapJobID
	if f.migrateErr != nil {
		return store.LifecycleJob{}, f.migrateErr
	}
	id := f.job.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	timeoutAt := time.Now().UTC().Add(timeout)
	if timeout <= 0 {
		timeoutAt = time.Now().UTC().Add(24 * time.Hour)
	}
	nv := nextVerifyAt
	return store.LifecycleJob{
		ID: id, Kind: store.JobKindMigrate, Status: store.LifecyclePendingVerify,
		PredecessorCertID: &certID, AAPJobID: &aapJobID, AAPWorkflow: workflow,
		Expected: expected, TimeoutAt: timeoutAt, NextVerifyAt: &nv,
	}, nil
}

func (f *fakeLifecycleStore) InsertLifecycleJobPending(_ context.Context, certID uuid.UUID, _ string, expected json.RawMessage) (store.LifecycleJob, error) {
	f.gotPending++
	if f.pendingErr != nil {
		return store.LifecycleJob{}, f.pendingErr
	}
	id := uuid.New()
	return store.LifecycleJob{
		ID: id, Status: store.LifecycleLaunching, PredecessorCertID: &certID, Expected: expected,
	}, nil
}

func (f *fakeLifecycleStore) InsertMigrateJobPending(_ context.Context, certID uuid.UUID, _ string, expected json.RawMessage, timeout time.Duration, nextVerifyAt time.Time) (store.LifecycleJob, error) {
	f.gotMigratePend++
	if f.migratePending != nil {
		return store.LifecycleJob{}, f.migratePending
	}
	id := uuid.New()
	nv := nextVerifyAt
	timeoutAt := time.Now().UTC().Add(timeout)
	return store.LifecycleJob{
		ID: id, Kind: store.JobKindMigrate, Status: store.LifecyclePendingVerify,
		PredecessorCertID: &certID, Expected: expected, TimeoutAt: timeoutAt, NextVerifyAt: &nv,
	}, nil
}

func (f *fakeLifecycleStore) GetLifecycleJob(_ context.Context, id uuid.UUID) (store.LifecycleJob, error) {
	if f.getErr != nil {
		return store.LifecycleJob{}, f.getErr
	}
	j := f.job
	if j.ID == uuid.Nil {
		j.ID = id
	}
	return j, nil
}

func (f *fakeLifecycleStore) ListLifecycleJobsByCert(context.Context, uuid.UUID, int) ([]store.LifecycleJob, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.jobs == nil {
		return []store.LifecycleJob{}, nil
	}
	return f.jobs, nil
}

func (f *fakeLifecycleStore) GetLifecycleJobByIdempotency(context.Context, string) (store.LifecycleJob, error) {
	if f.byKeyErr != nil {
		return store.LifecycleJob{}, f.byKeyErr
	}
	return f.job, nil
}

func (f *fakeLifecycleStore) ClaimByIdempotency(_ context.Context, _ string, aapJobID int) (store.LifecycleJob, error) {
	f.gotClaim++
	if f.claimErr != nil {
		return store.LifecycleJob{}, f.claimErr
	}
	j := f.job
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	if j.AAPJobID != nil && *j.AAPJobID != aapJobID {
		return store.LifecycleJob{}, store.ErrLifecycleAAPRefConflict
	}
	j.AAPJobID = &aapJobID
	j.Status = store.LifecycleAAPPending
	f.job = j
	return j, nil
}

func (f *fakeLifecycleStore) AppendRenewalOutboxEvent(_ context.Context, eventType string, _ *uuid.UUID, _ json.RawMessage) error {
	if eventType == "renewal.launched" {
		f.launchedEvents++
	}
	return nil
}
