package lifecyclejobs

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type memStore struct {
	jobs   map[uuid.UUID]store.LifecycleJob
	certs  map[uuid.UUID]store.Certificate
	events []string
}

func newMem() *memStore {
	return &memStore{jobs: map[uuid.UUID]store.LifecycleJob{}, certs: map[uuid.UUID]store.Certificate{}}
}

func (m *memStore) ClaimLifecycleJobs(context.Context, string, time.Duration, int) ([]store.LifecycleJob, error) {
	out := make([]store.LifecycleJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j)
	}
	return out, nil
}
func (m *memStore) GetCertificate(_ context.Context, id uuid.UUID) (store.Certificate, error) {
	c, ok := m.certs[id]
	if !ok {
		return store.Certificate{}, store.ErrCertificateNotFound
	}
	return c, nil
}
func (m *memStore) ListCertificates(context.Context, store.CertificateFilter) ([]store.Certificate, int, error) {
	out := make([]store.Certificate, 0, len(m.certs))
	for _, c := range m.certs {
		out = append(out, c)
	}
	return out, len(out), nil
}
func (m *memStore) SetLifecycleAAPRef(_ context.Context, id uuid.UUID, aapJobID int, workflow bool, status string) error {
	j := m.jobs[id]
	j.AAPJobID = &aapJobID
	j.AAPWorkflow = workflow
	j.Status = status
	m.jobs[id] = j
	return nil
}
func (m *memStore) UpdateLifecycleStatus(_ context.Context, id uuid.UUID, p store.UpdateLifecycleStatusParams) error {
	j := m.jobs[id]
	if p.Status != "" {
		j.Status = p.Status
	}
	if p.FailureReason != nil {
		j.FailureReason = p.FailureReason
	}
	if len(p.Observed) > 0 {
		j.Observed = p.Observed
	}
	if p.SuccessorCertID != nil {
		j.SuccessorCertID = p.SuccessorCertID
	}
	m.jobs[id] = j
	return nil
}
func (m *memStore) AppendLifecycleJobEvent(context.Context, uuid.UUID, string, json.RawMessage) error {
	return nil
}
func (m *memStore) AppendRenewalOutboxEvent(_ context.Context, eventType string, _ *uuid.UUID, _ json.RawMessage) error {
	m.events = append(m.events, eventType)
	return nil
}

type fakeRenewer struct {
	jobID int
	calls int
}

func (f *fakeRenewer) Renew(context.Context, map[string]any) (int, bool, error) {
	f.calls++
	return f.jobID, false, nil
}

type fakePoller struct {
	status aap.Status
}

func (f *fakePoller) WaitForJob(context.Context, int, bool, time.Duration) (aap.Status, error) {
	return f.status, nil
}

func TestWorker_DoesNotDoubleLaunchWhenAAPSet(t *testing.T) {
	t.Parallel()
	m := newMem()
	id := uuid.New()
	aapID := 99
	m.jobs[id] = store.LifecycleJob{
		ID: id, Status: store.LifecycleLaunching, AAPJobID: &aapID,
	}
	fr := &fakeRenewer{jobID: 1}
	w := New(Config{}, m, fr, &fakePoller{}, slog.Default())
	if err := w.launch(context.Background(), m.jobs[id]); err != nil {
		t.Fatal(err)
	}
	if fr.calls != 0 {
		t.Fatalf("expected no renew launch, got %d", fr.calls)
	}
	if m.jobs[id].Status != store.LifecycleAAPPending {
		t.Fatalf("status = %q", m.jobs[id].Status)
	}
}

func TestWorker_VerifyEmitsCompletedOnlyWhenWireMatches(t *testing.T) {
	t.Parallel()
	m := newMem()
	predID := uuid.New()
	succID := uuid.New()
	cn := "app.example.com"
	predAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.certs[predID] = store.Certificate{
		ID: predID, SubjectCN: &cn, FingerprintSHA256: "fp-old", NotAfter: predAfter,
	}
	m.certs[succID] = store.Certificate{
		ID: succID, SubjectCN: &cn, FingerprintSHA256: "fp-new",
		NotAfter: predAfter.Add(48 * time.Hour), ManagedStatus: "managed_in_vault",
	}
	jobID := uuid.New()
	m.jobs[jobID] = store.LifecycleJob{
		ID: jobID, Status: store.LifecycleVerifying, PredecessorCertID: &predID,
		Expected: MarshalExpected(ExpectedWire{
			CommonName: cn, PredecessorFP: "fp-old", PredecessorNotAfter: predAfter,
		}),
	}
	w := New(Config{}, m, nil, nil, slog.Default())
	if err := w.verify(context.Background(), m.jobs[jobID]); err != nil {
		t.Fatal(err)
	}
	if m.jobs[jobID].Status != store.LifecycleVerified {
		t.Fatalf("status = %q, want verified", m.jobs[jobID].Status)
	}
	found := false
	for _, e := range m.events {
		if e == "renewal.completed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("events = %#v, want renewal.completed", m.events)
	}
}

func TestWorker_AAPSuccessAloneDoesNotComplete(t *testing.T) {
	t.Parallel()
	m := newMem()
	predID := uuid.New()
	cn := "app.example.com"
	predAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.certs[predID] = store.Certificate{
		ID: predID, SubjectCN: &cn, FingerprintSHA256: "fp-old", NotAfter: predAfter,
	}
	aapID := 7
	jobID := uuid.New()
	m.jobs[jobID] = store.LifecycleJob{
		ID: jobID, Status: store.LifecycleAAPRunning, AAPJobID: &aapID, PredecessorCertID: &predID,
		Expected: MarshalExpected(ExpectedWire{
			CommonName: cn, PredecessorFP: "fp-old", PredecessorNotAfter: predAfter,
		}),
	}
	w := New(Config{LeaseTTL: time.Second}, m, nil, &fakePoller{status: aap.StatusSuccessful}, slog.Default())
	if err := w.pollAAP(context.Background(), m.jobs[jobID]); err != nil {
		t.Fatal(err)
	}
	// No successor in inventory → verify_failed, never renewal.completed
	if m.jobs[jobID].Status != store.LifecycleVerifyFailed {
		t.Fatalf("status = %q, want verify_failed", m.jobs[jobID].Status)
	}
	for _, e := range m.events {
		if e == "renewal.completed" {
			t.Fatal("must not emit renewal.completed without wire verify")
		}
	}
}
