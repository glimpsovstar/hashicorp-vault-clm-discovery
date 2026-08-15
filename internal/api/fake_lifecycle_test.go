package api

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeLifecycleStore struct {
	job            store.LifecycleJob
	jobs           []store.LifecycleJob
	persistErr     error
	pendingErr     error
	getErr         error
	listErr        error
	byKeyErr       error
	gotPersist     bool
	gotPending     int
	gotRenewalCfg  *store.RenewalConfig
	lastAAPJobID   int
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
		AAPJobID: &aapJobID, AAPWorkflow: workflow, Expected: expected,
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
