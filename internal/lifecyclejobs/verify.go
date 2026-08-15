package lifecyclejobs

import (
	"encoding/json"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// MapAAPStatus maps Controller job status onto CLM lifecycle_jobs.status.
// Terminal failure statuses collapse to LifecycleFailed; success stays
// aap_successful so the worker can enter verifying.
func MapAAPStatus(st aap.Status) string {
	switch st {
	case aap.StatusPending:
		return store.LifecycleAAPPending
	case aap.StatusRunning:
		return store.LifecycleAAPRunning
	case aap.StatusSuccessful:
		return store.LifecycleAAPSuccessful
	case aap.StatusFailed, aap.StatusError, aap.StatusCanceled:
		return store.LifecycleFailed
	default:
		return store.LifecycleAAPPending
	}
}

// ExpectedWire is stored on the job at launch time for later verification.
type ExpectedWire struct {
	CommonName          string    `json:"common_name"`
	PredecessorFP       string    `json:"predecessor_fingerprint"`
	PredecessorNotAfter time.Time `json:"predecessor_not_after"`
	TargetHosts         string    `json:"target_hosts,omitempty"`
}

// ObservedWire is filled after a targeted scan / inventory lookup.
type ObservedWire struct {
	CommonName      string    `json:"common_name,omitempty"`
	Fingerprint     string    `json:"fingerprint,omitempty"`
	NotAfter        time.Time `json:"not_after,omitempty"`
	SuccessorCertID string    `json:"successor_cert_id,omitempty"`
	ManagedInVault  bool      `json:"managed_in_vault,omitempty"`
}

// VerifyResult is the outcome of expected-vs-observed matching.
type VerifyResult struct {
	OK     bool
	Reason string
}

// VerifyWire checks the M2 predicate: same CN, new fingerprint, later not_after.
func VerifyWire(expected ExpectedWire, observed ObservedWire) VerifyResult {
	if observed.CommonName == "" || observed.Fingerprint == "" {
		return VerifyResult{OK: false, Reason: "no successor certificate observed"}
	}
	if expected.CommonName != "" && observed.CommonName != expected.CommonName {
		return VerifyResult{OK: false, Reason: "common name mismatch"}
	}
	if observed.Fingerprint == expected.PredecessorFP {
		return VerifyResult{OK: false, Reason: "fingerprint unchanged (predecessor still on wire)"}
	}
	if !observed.NotAfter.After(expected.PredecessorNotAfter) {
		return VerifyResult{OK: false, Reason: "not_after not later than predecessor"}
	}
	return VerifyResult{OK: true}
}

// MarshalExpected encodes ExpectedWire as JSONB payload.
func MarshalExpected(e ExpectedWire) json.RawMessage {
	b, _ := json.Marshal(e)
	return b
}

// UnmarshalExpected decodes ExpectedWire from job.Expected.
func UnmarshalExpected(raw json.RawMessage) (ExpectedWire, error) {
	var e ExpectedWire
	if len(raw) == 0 {
		return e, nil
	}
	err := json.Unmarshal(raw, &e)
	return e, err
}
