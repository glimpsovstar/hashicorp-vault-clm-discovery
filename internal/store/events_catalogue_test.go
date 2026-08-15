package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

func TestEmitDiscoveryCatalogueEvents_Insert(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	scan, err := st.CreateScan(ctx, []string{"203.0.113.50/32"}, nil, []int{443}, 1, 0)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteScan(context.Background(), scan.ID) })

	parsed := cert.ParsedCertificate{
		SerialNumber:       "abc123",
		FingerprintSHA256:  "fp-m5-" + uuid.New().String(),
		SubjectCN:          "m5.example.com",
		SubjectAltNames:    []string{"m5.example.com"},
		IssuerDN:           "CN=Test CA",
		NotBefore:          time.Now().UTC().Add(-24 * time.Hour),
		NotAfter:           time.Now().UTC().Add(10 * 24 * time.Hour),
		KeyType:            "RSA",
		KeyBits:            2048,
		SignatureAlgorithm: "SHA256-RSA",
		PEM:                "-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----",
		ChainStatus:        cert.ChainComplete,
		HostnameMatchesSAN: true,
		PQCTag:             cert.PQCTagClassic,
	}
	obs := cert.Observation{IP: "203.0.113.50", Port: 443, ObservedAt: time.Now().UTC()}

	certID, err := st.UpsertCertificate(ctx, scan.ID, parsed, obs)
	if err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM events WHERE certificate_id = $1`, certID)
		_ = st.DeleteCertificate(context.Background(), certID)
	})

	events, err := st.ListEvents(ctx, EventFilter{Limit: 50, CertificateID: &certID})
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, e := range events {
		types[e.EventType]++
	}
	if types["cert.discovered"] != 1 {
		t.Fatalf("cert.discovered count=%d want 1 (got %#v)", types["cert.discovered"], types)
	}
	if types["blind_spot.detected"] != 1 {
		t.Fatalf("blind_spot.detected count=%d want 1", types["blind_spot.detected"])
	}
	if types["cert.expiring"] != 1 {
		t.Fatalf("cert.expiring count=%d want 1 for 10d remaining", types["cert.expiring"])
	}

	if _, err := st.UpsertCertificate(ctx, scan.ID, parsed, obs); err != nil {
		t.Fatal(err)
	}
	events2, err := st.ListEvents(ctx, EventFilter{Limit: 50, CertificateID: &certID})
	if err != nil {
		t.Fatal(err)
	}
	types2 := map[string]int{}
	for _, e := range events2 {
		types2[e.EventType]++
	}
	if types2["cert.discovered"] != 1 {
		t.Fatalf("after re-upsert cert.discovered=%d want 1", types2["cert.discovered"])
	}
}

func TestListEvents_FilterByEventType(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	marker := "cert.discovered.test." + uuid.New().String()
	_, err := st.pool.Exec(ctx, `
		INSERT INTO events (event_type, certificate_id, payload) VALUES
		('cert.revoked', NULL, '{}'),
		($1, NULL, '{}')
	`, marker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM events WHERE event_type = $1 OR (event_type = 'cert.revoked' AND payload = '{}'::jsonb AND certificate_id IS NULL AND created_at > NOW() - INTERVAL '1 minute')`, marker)
	})
	got, err := st.ListEvents(ctx, EventFilter{Limit: 20, EventType: marker})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one filtered event")
	}
	for _, e := range got {
		if e.EventType != marker {
			t.Fatalf("got %s", e.EventType)
		}
	}
}

func TestCataloguePayloadShapes(t *testing.T) {
	payload, err := cataloguePayload(uuid.New(), "fp", "cn.example", "expiring_soon", 5, "unmanaged", "external")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint_sha256", "subject_cn", "status", "days_until_expiry", "managed_status", "cert_scope"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
}
