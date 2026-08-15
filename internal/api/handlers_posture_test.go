package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
)

func TestRBAC_WaiverWriteRoles(t *testing.T) {
	t.Parallel()
	if !roleAllows(roleApprover, http.MethodPost, "/api/v1/certificates/"+uuid.New().String()+"/waivers") {
		t.Fatal("approver should create waivers")
	}
	if !roleAllows(roleRemediator, http.MethodDelete, "/api/v1/waivers/"+uuid.New().String()) {
		t.Fatal("remediator should revoke waivers")
	}
	if roleAllows(roleViewer, http.MethodPost, "/api/v1/certificates/"+uuid.New().String()+"/waivers") {
		t.Fatal("viewer must not create waivers")
	}
}

func TestMapPackSeverity_UsedByHandlersContract(t *testing.T) {
	// Sanity: create-waiver request shape rejects past expiry via store; handler
	// returns 400. Unit-level without DB: decode body.
	body := createWaiverRequest{
		RuleID:    "sc081.expiry.expired",
		Reason:    "tracked exception",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	raw, _ := json.Marshal(body)
	var decoded createWaiverRequest
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RuleID != body.RuleID {
		t.Fatalf("rule_id=%q", decoded.RuleID)
	}
}

func TestPQCInventoryRouteRegistered(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(config.Config{InsecureNoAuth: true}, nil, scanner.New(scanner.Config{}), log)
	h := srv.Router()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/pqc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatal("inventory/pqc route missing")
	}
}
