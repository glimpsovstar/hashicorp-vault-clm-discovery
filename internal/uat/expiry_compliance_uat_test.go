//go:build uat

package uat

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// genSelfSigned mints a self-signed RSA-2048/SHA-256 cert valid over [nb, na].
func genSelfSigned(t *testing.T, cn string, nb, na time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS starts an in-process HTTPS server presenting cert and returns host, port.
func serveTLS(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h, p, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	pi, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return h, pi
}

// probe drives the real scanner against host:port.
func probe(t *testing.T, host string, port int) scanner.ProbeResult {
	t.Helper()
	sc := scanner.New(scanner.Config{Timeout: 5 * time.Second, AllowPrivateRanges: true})
	pr := sc.Probe(context.Background(), scanner.Target{IP: host, Port: port})
	if pr.Error != nil {
		t.Fatalf("probe: %v", pr.Error)
	}
	return pr
}

// toStoreCert maps a probed cert into the store shape the evaluator consumes.
func toStoreCert(pr scanner.ProbeResult, scope string, env *string) store.Certificate {
	c := pr.Certificate
	cn := c.SubjectCN
	return store.Certificate{
		ID:                 uuid.New(),
		FingerprintSHA256:  c.FingerprintSHA256,
		SubjectCN:          &cn,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		KeyType:            c.KeyType,
		KeyBits:            c.KeyBits,
		SignatureAlgorithm: c.SignatureAlgorithm,
		CertScope:          scope,
		Environment:        env,
	}
}

func sc081Finding(sum compliance.ComplianceSummary, prefix string) (compliance.Finding, bool) {
	for _, f := range sum.Findings {
		if f.Pack == "sc081" && strings.HasPrefix(f.RuleID, prefix) {
			return f, true
		}
	}
	return compliance.Finding{}, false
}

func TestUAT_ExpiryValidityMatrix(t *testing.T) {
	now := time.Now().UTC()
	// +12h buffer so floor((NotAfter-now)/24h) lands exactly on n days despite
	// elapsed evaluation time.
	at := func(days int) time.Time { return now.Add(time.Duration(days)*24*time.Hour + 12*time.Hour) }
	prod := "prod"

	type row struct {
		id           string
		nb, na       time.Time
		expiryRule   string // "" == expect no expiry finding
		internalSev  string // severity when internal (expected "info" when expiryRule set)
		prodSev      string // severity when prod-enriched
		validityCrit bool   // expect a critical sc081.validity.* finding (scope-independent)
		internalViol int
		prodViol     int
	}
	rows := []row{
		{"expired", now.Add(-30 * 24 * time.Hour), now.Add(-1 * 24 * time.Hour), "sc081.expiry.expired", "info", "critical", false, 0, 1},
		{"exp-7", now, at(7), "sc081.expiry.critical", "info", "critical", false, 0, 1},
		{"exp-14", now, at(14), "sc081.expiry.critical", "info", "critical", false, 0, 1},
		{"exp-15", now, at(15), "sc081.expiry.warning", "info", "warning", false, 0, 1},
		{"exp-30", now, at(30), "sc081.expiry.warning", "info", "warning", false, 0, 1},
		{"exp-45", now, at(45), "sc081.expiry.warning", "info", "warning", false, 0, 1},
		{"exp-60", now, at(60), "sc081.expiry.warning", "info", "warning", false, 0, 1},
		{"exp-61", now, at(61), "", "", "", false, 0, 0},
		{"valid-99", now, at(99), "", "", "", false, 0, 0},
		{"valid-400", now, at(400), "", "", "", true, 1, 1},
	}

	for _, r := range rows {
		t.Run(r.id, func(t *testing.T) {
			host, port := serveTLS(t, genSelfSigned(t, r.id+".uat.test", r.nb, r.na))
			pr := probe(t, host, port)

			// Parsed NotAfter must round-trip within a second.
			if d := pr.Certificate.NotAfter.Sub(r.na); d > time.Second || d < -time.Second {
				t.Fatalf("parsed NotAfter=%v want~%v", pr.Certificate.NotAfter, r.na)
			}

			scope := governance.ClassifyScope(string(pr.Certificate.ChainStatus), pr.Certificate.IssuerDN, r.id+".uat.test", "")
			if scope != governance.ScopeInternal {
				t.Fatalf("scope=%q want internal (self-signed)", scope)
			}

			// As-discovered (internal, non-prod).
			in := compliance.EvaluateCerts([]store.Certificate{toStoreCert(pr, scope, nil)})
			if r.expiryRule != "" {
				f, ok := sc081Finding(in, r.expiryRule)
				if !ok {
					t.Fatalf("internal: missing %s in %+v", r.expiryRule, in.Findings)
				}
				if f.Severity != r.internalSev {
					t.Fatalf("internal: %s severity=%q want %q", r.expiryRule, f.Severity, r.internalSev)
				}
			} else if f, ok := sc081Finding(in, "sc081.expiry"); ok {
				t.Fatalf("internal: unexpected expiry finding %+v", f)
			}
			// valid-99's violation count depends on the active SC-081 validity
			// ceiling (its ~99d lifetime crosses the 99d ceiling on 2027-03-15),
			// so skip the date-sensitive count; its robust invariant (no expiry
			// finding) is asserted above.
			if r.id != "valid-99" && in.SC081ViolationCount != r.internalViol {
				t.Fatalf("internal: violations=%d want %d", in.SC081ViolationCount, r.internalViol)
			}

			// Prod-enriched (full severity).
			pd := compliance.EvaluateCerts([]store.Certificate{toStoreCert(pr, scope, &prod)})
			if r.expiryRule != "" {
				f, ok := sc081Finding(pd, r.expiryRule)
				if !ok {
					t.Fatalf("prod: missing %s in %+v", r.expiryRule, pd.Findings)
				}
				if f.Severity != r.prodSev {
					t.Fatalf("prod: %s severity=%q want %q", r.expiryRule, f.Severity, r.prodSev)
				}
			}
			if r.id != "valid-99" && pd.SC081ViolationCount != r.prodViol {
				t.Fatalf("prod: violations=%d want %d", pd.SC081ViolationCount, r.prodViol)
			}

			// Validity dimension (scope-independent, always critical when present).
			if r.validityCrit {
				f, ok := sc081Finding(pd, "sc081.validity")
				if !ok {
					t.Fatalf("expected a validity finding in %+v", pd.Findings)
				}
				if f.Severity != "critical" {
					t.Fatalf("validity severity=%q want critical", f.Severity)
				}
			}
		})
	}
}
