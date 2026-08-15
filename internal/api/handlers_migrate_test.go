package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestMigrate_RejectsCA(t *testing.T) {
	t.Parallel()
	cn := "ca.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 1}}
	fl := &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{SubjectCN: &cn, IsCA: true, ObservationCount: 1}})
	srv.renewer = fr
	srv.lifecycle = fl
	srv.cfg.LifecycleVerifyTimeout = 24 * time.Hour

	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"role":"web"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fr.calls != 0 {
		t.Fatal("must not launch AAP for CA")
	}
}

func TestMigrate_RejectsManagedInVault(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 1}}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{
		SubjectCN: &cn, ManagedStatus: "managed_in_vault", ObservationCount: 1,
	}})
	srv.renewer = fr
	srv.lifecycle = &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"role":"web"}`))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "/renew") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fr.calls != 0 {
		t.Fatal("must not launch")
	}
}

func TestMigrate_ConsentRequired(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{SubjectCN: &cn, ObservationCount: 1}})
	srv.renewer = &fakeRenewer{ref: RenewRef{JobID: 1}}
	srv.lifecycle = &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":false,"role":"web"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMigrate_NoAAP_503(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{SubjectCN: &cn, ObservationCount: 1}})
	srv.lifecycle = &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"role":"web"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMigrate_AcceptedPersistsJobAndEvents(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 42}}
	fl := &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{
		SubjectCN: &cn, FingerprintSHA256: "fp1", ObservationCount: 1,
		NotAfter: time.Now().UTC().Add(30 * 24 * time.Hour),
	}})
	srv.cfg.AAPDefaultMount = "pki"
	srv.cfg.LifecycleVerifyTimeout = 24 * time.Hour
	srv.renewer = fr
	srv.lifecycle = fl

	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"role":"web"}`))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !fl.gotMigrate {
		t.Fatal("expected PersistMigrateLaunch")
	}
	if fr.calls != 1 {
		t.Fatalf("renew calls=%d", fr.calls)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != store.LifecyclePendingVerify {
		t.Fatalf("status=%v", body["status"])
	}
	if body["lifecycle_job_id"] == nil {
		t.Fatal("missing lifecycle_job_id")
	}
}

func TestMigrate_RejectsPEM(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 1}}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{SubjectCN: &cn, ObservationCount: 1}})
	srv.renewer = fr
	srv.lifecycle = &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	rec := httptest.NewRecorder()
	srv.handleMigrateCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"role":"web","pem":"-----BEGIN CERTIFICATE-----"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
	if fr.calls != 0 {
		t.Fatal("must not launch when PEM present")
	}
}

func TestMigrateEligible_DoesNotLaunchAAP(t *testing.T) {
	t.Parallel()
	cn := "a.example.com"
	cn2 := "b.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 9}}
	fl := &fakeLifecycleStore{byKeyErr: store.ErrLifecycleJobNotFound}
	srv := newResourceServer(&fakeResourceStore{certs: []store.Certificate{
		{ID: uuid.New(), SubjectCN: &cn, FingerprintSHA256: "a", ObservationCount: 1, NotAfter: time.Now().Add(time.Hour)},
		{ID: uuid.New(), SubjectCN: &cn2, FingerprintSHA256: "b", ObservationCount: 1, NotAfter: time.Now().Add(time.Hour)},
	}})
	srv.renewer = fr
	srv.lifecycle = fl
	srv.cfg.LifecycleVerifyTimeout = 24 * time.Hour
	srv.cfg.EDAWebhookURL = "http://eda.example"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/migrate-eligible", strings.NewReader(`{"consent":true}`))
	srv.handleMigrateEligible(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fr.calls != 0 {
		t.Fatal("batch must not call Renew")
	}
	if fl.gotMigratePend != 2 {
		t.Fatalf("enqueued=%d", fl.gotMigratePend)
	}
}

func TestClaim_SetsAAPJobAndLaunched(t *testing.T) {
	t.Parallel()
	fl := &fakeLifecycleStore{
		job: store.LifecycleJob{ID: uuid.New(), Status: store.LifecyclePendingVerify},
	}
	srv := newResourceServer(&fakeResourceStore{})
	srv.lifecycle = fl

	body := `{"idempotency_key":"migrate:x","aap_job_id":99}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/lifecycle-jobs/claim", strings.NewReader(body))
	srv.handleClaimLifecycleJob(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fl.gotClaim != 1 || fl.launchedEvents != 1 {
		t.Fatalf("claim=%d launched=%d", fl.gotClaim, fl.launchedEvents)
	}

	// same id again — no second launched
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/lifecycle-jobs/claim", strings.NewReader(body))
	srv.handleClaimLifecycleJob(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status=%d", rec2.Code)
	}
	if fl.launchedEvents != 1 {
		t.Fatalf("launched events=%d want 1", fl.launchedEvents)
	}

	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/lifecycle-jobs/claim", strings.NewReader(`{"idempotency_key":"migrate:x","aap_job_id":100}`))
	srv.handleClaimLifecycleJob(rec3, req3)
	if rec3.Code != http.StatusConflict {
		t.Fatalf("status=%d", rec3.Code)
	}
}
