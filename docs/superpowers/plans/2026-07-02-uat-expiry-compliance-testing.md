# UAT & Expiry/Validity Compliance Testing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic Go integration test and a realistic docker-compose UAT that drive the real scan→parse→lifecycle→governance→SC-081 pipeline across controlled certificate expiry/validity windows, confirming the app's reactions match intent.

**Architecture:** Two independent deliverables sharing one scenario matrix. (1) A `//go:build uat` Go test in `internal/uat/` mints self-signed certs, serves them from in-process `httptest` TLS servers, drives `scanner.Probe`, and asserts the real `compliance.EvaluateCerts` output. (2) A `test/uat/` docker-compose stack serves the same matrix from real nginx HTTPS endpoints; a bash driver scans them via the API and asserts `/compliance` + `/blindspot`, with opt-in `vault` and `letsencrypt` profiles.

**Tech Stack:** Go 1.22 (`crypto/x509`, `crypto/tls`, `net/http/httptest`), the existing `internal/scanner`, `internal/compliance`, `internal/governance` packages; Docker Compose, nginx, bash + curl + jq, `lego` (ACME) for the LE lane.

## Global Constraints

- Go integration test file MUST carry `//go:build uat` and live in package `uat`; it MUST NOT run under the default `go test ./...`.
- Expiry day offsets MUST use a **+12h buffer** (`now.Add(nDays*24h + 12h)`) so `floor((NotAfter-now)/24h)` lands exactly on `n` despite elapsed evaluation time. `expired` is the only negative offset.
- Test certs use **RSA 2048 + SHA-256** so they trigger no `crypto` findings; the only SC-081 findings asserted are `sc081.expiry.*` and `sc081.validity.*` (filter findings by `Pack == "sc081"`).
- SC-081 severity downgrade rule (verbatim): internal + non-prod expiry → `info`; `info` findings are excluded from `SC081ViolationCount`. Validity findings are always `critical` and scope-independent.
- The maintainer ACME email MUST NOT be committed. Use env var `ACME_EMAIL`; committed files use `you@example.com`; the real value lives only in gitignored `test/uat/.env`.
- Module path: `github.com/glimpsovstar/hashicorp-vault-clm-discovery`.

---

## File Structure

- `internal/uat/expiry_compliance_uat_test.go` — Go integration test (build-tagged), all matrix rows + helpers.
- `test/uat/gen-certs/main.go` — Go cert generator (exact notBefore/notAfter with +12h buffer).
- `test/uat/nginx/endpoint.conf.tmpl` — nginx TLS server-block template (one listener per cert).
- `test/uat/docker-compose.uat.yml` — postgres, app, N nginx endpoints; `vault` + `letsencrypt` profiles.
- `test/uat/driver.sh` — bash+curl+jq; triggers scan, asserts matrix, exits non-zero on mismatch.
- `test/uat/.env.example` — committed placeholders.
- `test/uat/README.md` — how to run, env vars, expected-results matrix, intended behaviors.
- `.gitignore` — add `test/uat/.env` and generated certs.
- `.github/workflows/ci.yml` — add a `go test -tags uat` step.
- `CONTRIBUTING.md`, `docs/architecture.md` — testing-tier docs.

---

### Task 1: Go integration test — helpers + full matrix

**Files:**
- Create: `internal/uat/expiry_compliance_uat_test.go`

**Interfaces:**
- Consumes: `scanner.New(scanner.Config{Timeout time.Duration, AllowPrivateRanges bool}) *scanner.Scanner`; `(*scanner.Scanner).Probe(ctx, scanner.Target{IP string, Port int, Hostname string}) scanner.ProbeResult`; `scanner.ProbeResult{Certificate cert.ParsedCertificate, Error error}`; `cert.ParsedCertificate{NotBefore, NotAfter time.Time, IssuerDN, SubjectCN, KeyType string, KeyBits int, SignatureAlgorithm, FingerprintSHA256 string, ChainStatus cert.ChainStatus}`; `governance.ClassifyScope(chainStatus, issuerDN, hostname, environment string) string`; `store.Certificate{...}`; `compliance.EvaluateCerts([]store.Certificate) compliance.ComplianceSummary` with fields `Findings []compliance.Finding` and `SC081ViolationCount int`; `compliance.Finding{RuleID, Pack, Severity string}`.
- Produces: nothing consumed by later tasks (self-contained test).

- [ ] **Step 1: Write the test file (helpers + matrix + assertions)**

```go
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
			if in.SC081ViolationCount != r.internalViol {
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
			if pd.SC081ViolationCount != r.prodViol {
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
```

- [ ] **Step 2: Run and observe (UAT: pass confirms intended behavior)**

Run: `go test -tags uat ./internal/uat/... -v`
Expected: PASS for all 10 subtests. A FAIL is a genuine UAT finding — capture the actual vs expected, then triage as "bug vs intended" (do NOT edit the test to make it pass without understanding why).

- [ ] **Step 3: Confirm the default suite is unaffected**

Run: `go test ./... 2>&1 | tail -3`
Expected: all packages pass; `internal/uat` shows `[no test files]` (build tag excludes it).

- [ ] **Step 4: Commit**

```bash
git add internal/uat/expiry_compliance_uat_test.go
git commit -m "test(uat): expiry/validity compliance integration test (//go:build uat)"
```

---

### Task 2: CI step for the build-tagged integration test

**Files:**
- Modify: `.github/workflows/ci.yml` (the `go` job, after `go build ./...`)

**Interfaces:**
- Consumes: the `uat` build tag from Task 1.
- Produces: nothing.

- [ ] **Step 1: Add the step**

In `.github/workflows/ci.yml`, in the `go` job's `steps:`, immediately after the `- run: go build ./...` line, add:

```yaml
      - run: go test -tags uat ./internal/uat/...
```

- [ ] **Step 2: Verify locally the command the CI runs**

Run: `go test -tags uat ./internal/uat/...`
Expected: `ok  github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/uat`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run build-tagged uat integration test"
```

---

### Task 3: Cert generator (Go) + secrets scaffolding

**Files:**
- Create: `test/uat/gen-certs/main.go`
- Create: `test/uat/.env.example`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: writes `<outdir>/<id>.crt` + `<id>.key` PEM pairs for each matrix id; consumed by Task 4 (nginx) and Task 5 (driver reads the id list).

- [ ] **Step 1: Write the generator**

```go
// Command gen-certs mints the UAT self-signed certificate matrix with exact
// notBefore/notAfter (+12h buffer) into <outdir>/<id>.crt and <id>.key.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type spec struct {
	id     string
	nbDays int // days from now for NotBefore
	naDays int // days from now for NotAfter (12h buffer added, except when 0)
}

func main() {
	outdir := "certs"
	if len(os.Args) > 1 {
		outdir = os.Args[1]
	}
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	buf := 12 * time.Hour
	at := func(days int) time.Time {
		if days == 0 {
			return now
		}
		return now.Add(time.Duration(days)*24*time.Hour + buf)
	}
	specs := []spec{
		{"expired", -30, 0}, // na handled below (expired => now-1d)
		{"exp-7", 0, 7},
		{"exp-14", 0, 14},
		{"exp-15", 0, 15},
		{"exp-30", 0, 30},
		{"exp-45", 0, 45},
		{"exp-60", 0, 60},
		{"exp-61", 0, 61},
		{"valid-99", 0, 99},
		{"valid-400", 0, 400},
	}
	for _, s := range specs {
		nb := at(s.nbDays)
		na := at(s.naDays)
		if s.id == "expired" {
			nb = now.Add(-30 * 24 * time.Hour)
			na = now.Add(-1 * 24 * time.Hour)
		}
		writePair(outdir, s.id, nb, na)
	}
	log.Printf("wrote %d cert pairs to %s", len(specs), outdir)
}

func writePair(outdir, id string, nb, na time.Time) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id + ".uat.test"},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{id + ".uat.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	crt, _ := os.Create(filepath.Join(outdir, id+".crt"))
	defer crt.Close()
	_ = pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	kf, _ := os.Create(filepath.Join(outdir, id+".key"))
	defer kf.Close()
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
```

- [ ] **Step 2: Run it and verify output**

Run: `cd test/uat && go run ./gen-certs ./certs && ls certs && openssl x509 -in certs/exp-7.crt -noout -enddate`
Expected: 20 files (`.crt`/`.key` × 10); the `notAfter` on `exp-7.crt` is ~7.5 days out.

- [ ] **Step 3: Write `.env.example`**

```bash
# test/uat/.env.example — copy to test/uat/.env (gitignored) and fill in real values.
# ACME account email for the optional Let's Encrypt (staging) profile.
ACME_EMAIL=you@example.com
# Public domain you control, for the letsencrypt profile only.
LE_DOMAIN=uat.example.com
```

- [ ] **Step 4: Update `.gitignore`**

Append to `.gitignore`:

```gitignore
# UAT local secrets and generated certs
test/uat/.env
test/uat/certs/
```

- [ ] **Step 5: Commit**

```bash
git add test/uat/gen-certs/main.go test/uat/.env.example .gitignore
git commit -m "test(uat): Go cert generator for expiry matrix + secrets scaffolding"
```

---

### Task 4: Base docker-compose (postgres, app, nginx endpoints)

**Files:**
- Create: `test/uat/nginx/endpoint.conf.tmpl`
- Create: `test/uat/docker-compose.uat.yml`

**Interfaces:**
- Consumes: cert PEMs from Task 3 in `./certs`.
- Produces: HTTPS endpoints reachable from the app container as `https://uat-<id>:443`; the app API on `localhost:8080`. Consumed by Task 5 (driver).

- [ ] **Step 1: Write the nginx server-block template**

`test/uat/nginx/endpoint.conf.tmpl` (the entrypoint substitutes `__ID__`):

```nginx
server {
    listen 443 ssl;
    server_name __ID__.uat.test;
    ssl_certificate     /certs/__ID__.crt;
    ssl_certificate_key /certs/__ID__.key;
    location / { return 200 "uat __ID__\n"; }
}
```

- [ ] **Step 2: Write the compose file**

`test/uat/docker-compose.uat.yml`. One nginx service per matrix id keeps ports/isolation simple; all mount the shared `./certs`. `gen-certs` runs first to populate certs.

```yaml
name: clm-uat

services:
  gen-certs:
    image: golang:1.22
    working_dir: /src/test/uat
    volumes:
      - ../../:/src
    command: ["go", "run", "./gen-certs", "/src/test/uat/certs"]

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: clm
      POSTGRES_PASSWORD: clm
      POSTGRES_DB: clm
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U clm"]
      interval: 5s
      timeout: 5s
      retries: 10

  app:
    build:
      context: ../../
      dockerfile: deploy/Dockerfile
    environment:
      DATABASE_URL: postgres://clm:clm@postgres:5432/clm?sslmode=disable
      ALLOW_PRIVATE_RANGES: "true"
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"

  # One HTTPS endpoint per matrix cert. All share the certs volume and the
  # nginx entrypoint that renders /etc/nginx/conf.d/default.conf from the id.
  uat-expired:   { extends: { file: endpoints.yml, service: endpoint }, environment: { ID: expired } }
```

Note for the implementer: writing ten near-identical services by hand is noisy. Use a YAML anchor + one service per id. Replace the single `uat-expired` line above with the full set using this pattern (define the anchor once, reference it per id):

```yaml
x-endpoint: &endpoint
  image: nginx:1.27-alpine
  volumes:
    - ./certs:/certs:ro
    - ./nginx/endpoint.conf.tmpl:/etc/nginx/templates/default.conf.tmpl:ro
  depends_on:
    gen-certs:
      condition: service_completed_successfully

services:
  uat-expired:   { <<: *endpoint, environment: { NGINX_ENVSUBST_TEMPLATE_SUFFIX: ".tmpl", ID: expired } }
  uat-exp-7:     { <<: *endpoint, environment: { ID: exp-7 } }
  uat-exp-14:    { <<: *endpoint, environment: { ID: exp-14 } }
  uat-exp-15:    { <<: *endpoint, environment: { ID: exp-15 } }
  uat-exp-30:    { <<: *endpoint, environment: { ID: exp-30 } }
  uat-exp-45:    { <<: *endpoint, environment: { ID: exp-45 } }
  uat-exp-60:    { <<: *endpoint, environment: { ID: exp-60 } }
  uat-exp-61:    { <<: *endpoint, environment: { ID: exp-61 } }
  uat-valid-99:  { <<: *endpoint, environment: { ID: valid-99 } }
  uat-valid-400: { <<: *endpoint, environment: { ID: valid-400 } }
```

The nginx `envsubst` template feature only substitutes `${VAR}` tokens, so change the template to use `${ID}` and rename it `default.conf.tmpl` (nginx image renders `/etc/nginx/templates/*.tmpl` → `/etc/nginx/conf.d/` at boot using env vars). Update `endpoint.conf.tmpl` accordingly:

```nginx
server {
    listen 443 ssl;
    server_name ${ID}.uat.test;
    ssl_certificate     /certs/${ID}.crt;
    ssl_certificate_key /certs/${ID}.key;
    location / { return 200 "uat ${ID}\n"; }
}
```

- [ ] **Step 3: Bring the base stack up and confirm endpoints serve the right certs**

Run:
```bash
cd test/uat
docker compose -f docker-compose.uat.yml up -d --build
docker compose -f docker-compose.uat.yml exec app sh -c \
  'apk add --no-cache openssl >/dev/null 2>&1; echo | openssl s_client -connect uat-exp-7:443 -servername exp-7.uat.test 2>/dev/null | openssl x509 -noout -enddate'
```
Expected: the app is healthy on `:8080`; `uat-exp-7` presents a cert expiring ~7.5 days out.

- [ ] **Step 4: Commit**

```bash
git add test/uat/nginx/endpoint.conf.tmpl test/uat/docker-compose.uat.yml
git commit -m "test(uat): docker-compose base stack with per-cert HTTPS endpoints"
```

---

### Task 5: Driver — scan + assert the matrix (default profile)

**Files:**
- Create: `test/uat/driver.sh`

**Interfaces:**
- Consumes: the app API at `${API:-http://localhost:8080}`; endpoint hostnames `uat-<id>` on port 443 (from the app container's network — the driver runs inside the app container so it shares the compose network DNS).
- Produces: exit 0 on full match; non-zero + a printed expected-vs-actual table on mismatch.

- [ ] **Step 1: Write the driver**

`test/uat/driver.sh` (run inside the app container so `uat-*` DNS resolves). It scans all endpoints by hostname, waits for completion, then asserts per-cert compliance findings via `/api/v1/scans/{id}/compliance`. It checks the internal (as-discovered) severities and violation count, then PATCHes each expiry cert to `environment=prod` and re-checks full severity.

```bash
#!/usr/bin/env sh
set -eu

API="${API:-http://localhost:8080}"
PORT=443
IDS="expired exp-7 exp-14 exp-15 exp-30 exp-45 exp-60 exp-61 valid-99 valid-400"

# Expected sc081 expiry rule per id ("" = none) and prod severity.
expiry_rule() { case "$1" in
  expired) echo "sc081.expiry.expired";; exp-7|exp-14) echo "sc081.expiry.critical";;
  exp-15|exp-30|exp-45|exp-60) echo "sc081.expiry.warning";; *) echo "";; esac; }
prod_sev() { case "$1" in
  expired|exp-7|exp-14) echo critical;; exp-15|exp-30|exp-45|exp-60) echo warning;; *) echo "";; esac; }
expect_validity() { [ "$1" = "valid-400" ]; }

hostnames_json() { printf '%s' "$IDS" | tr ' ' '\n' | sed 's/.*/"&.uat.test"/' | paste -sd, -; }

echo "==> triggering scan"
SCAN=$(curl -fsS -X POST "$API/api/v1/scans" -H 'Content-Type: application/json' \
  -d "{\"hostnames\":[$(hostnames_json)],\"ports\":[$PORT],\"consent\":true}")
SID=$(echo "$SCAN" | jq -r .id)

echo "==> waiting for scan $SID"
for _ in $(seq 1 60); do
  ST=$(curl -fsS "$API/api/v1/scans/$SID" | jq -r .status)
  [ "$ST" = completed ] && break
  [ "$ST" = failed ] && { echo "scan failed"; exit 1; }
  sleep 2
done
[ "$ST" = completed ] || { echo "scan did not complete"; exit 1; }

COMP=$(curl -fsS "$API/api/v1/scans/$SID/compliance")

fail=0
# find a cert id in inventory by subject CN
cert_id_for() { curl -fsS "$API/api/v1/scans/$SID/certificates" \
  | jq -r --arg cn "$1.uat.test" '.items[] | select(.subject_cn==$cn) | .id'; }
# severity of the sc081 expiry finding for a subject CN in the compliance doc
sev_for() { echo "$COMP" | jq -r --arg cn "$1.uat.test" \
  '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.expiry")) and .subject_cn==$cn)][0].severity // ""'; }
rule_for() { echo "$COMP" | jq -r --arg cn "$1.uat.test" \
  '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.expiry")) and .subject_cn==$cn)][0].rule_id // ""'; }
validity_sev() { echo "$COMP" | jq -r --arg cn "$1.uat.test" \
  '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.validity")) and .subject_cn==$cn)][0].severity // ""'; }

echo "==> asserting as-discovered (internal) severities"
for id in $IDS; do
  want_rule=$(expiry_rule "$id"); got_rule=$(rule_for "$id"); got_sev=$(sev_for "$id")
  if [ -n "$want_rule" ]; then
    [ "$got_rule" = "$want_rule" ] || { echo "FAIL $id: expiry rule got='$got_rule' want='$want_rule'"; fail=1; }
    [ "$got_sev" = "info" ] || { echo "FAIL $id: internal severity got='$got_sev' want='info'"; fail=1; }
  else
    [ -z "$got_rule" ] || { echo "FAIL $id: unexpected expiry finding '$got_rule'"; fail=1; }
  fi
  if expect_validity "$id"; then
    [ "$(validity_sev "$id")" = "critical" ] || { echo "FAIL $id: expected critical validity finding"; fail=1; }
  fi
done

echo "==> enriching expiry certs to prod and re-checking full severity"
for id in $IDS; do
  ws=$(prod_sev "$id"); [ -n "$ws" ] || continue
  cid=$(cert_id_for "$id"); [ -n "$cid" ] || { echo "FAIL $id: cert not found for PATCH"; fail=1; continue; }
  curl -fsS -X PATCH "$API/api/v1/certificates/$cid" -H 'Content-Type: application/json' \
    -d '{"environment":"prod"}' >/dev/null
done
COMP=$(curl -fsS "$API/api/v1/scans/$SID/compliance")
for id in $IDS; do
  ws=$(prod_sev "$id"); [ -n "$ws" ] || continue
  gs=$(sev_for "$id")
  [ "$gs" = "$ws" ] || { echo "FAIL $id: prod severity got='$gs' want='$ws'"; fail=1; }
done

echo "==> asserting shadow certs in blind-spot"
BS=$(curl -fsS "$API/api/v1/scans/$SID/blindspot")
[ "$(echo "$BS" | jq -r .vault_managed)" = "0" ] || { echo "FAIL: expected 0 vault_managed"; fail=1; }
[ "$(echo "$BS" | jq -r .shadow)" -ge 1 ] || { echo "FAIL: expected shadow>=1"; fail=1; }

[ "$fail" = 0 ] && echo "UAT PASS" || { echo "UAT FAIL"; exit 1; }
```

- [ ] **Step 2: Confirm the compliance API exposes `subject_cn` per finding**

Run: `sed -n '/type Finding struct/,/}/p' internal/compliance/types.go`
Expected: the `Finding` struct includes `SubjectCN` with a JSON tag `subject_cn`. If the JSON key differs, update the `jq` selectors in `driver.sh` to match the real key. (This is a read-only verification step — adjust the script, not the API.)

- [ ] **Step 3: Run the driver against the base stack**

Run:
```bash
cd test/uat
docker compose -f docker-compose.uat.yml up -d --build
chmod +x driver.sh
docker compose -f docker-compose.uat.yml exec -T app sh -c 'apk add --no-cache curl jq >/dev/null 2>&1' || true
docker compose -f docker-compose.uat.yml cp driver.sh app:/driver.sh
docker compose -f docker-compose.uat.yml exec -T app sh /driver.sh
```
Expected: `UAT PASS`. Any `FAIL <id>` line is a UAT finding to triage (bug vs intended), matching the expected-results table in the README.

- [ ] **Step 4: Commit**

```bash
git add test/uat/driver.sh
git commit -m "test(uat): driver asserts expiry/validity matrix + shadow certs"
```

---

### Task 6: `vault` profile — managed vs shadow

**Files:**
- Modify: `test/uat/docker-compose.uat.yml` (add a `vault` dev service under `profiles: [vault]`)

**Interfaces:**
- Consumes: the base app/postgres.
- Produces: `RECONCILE_ON_SCAN_COMPLETE`/`VAULT_ADDR` wiring so a reconcile marks any Vault-matched certs `managed_in_vault`.

- [ ] **Step 1: Add the vault service and app wiring**

Add to `services:` in `docker-compose.uat.yml`:

```yaml
  vault:
    image: hashicorp/vault:1.17
    profiles: ["vault"]
    cap_add: ["IPC_LOCK"]
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    command: server -dev
```

And add (commented in the base `app`, documented in README) the env the `vault` profile expects the operator to set when running that profile: `VAULT_ADDR=http://vault:8200`, `VAULT_TOKEN=root`.

- [ ] **Step 2: Document the limitation and run**

Because the UAT certs are self-signed (not Vault-issued), they remain **shadow** even with Vault up — the `vault` profile validates that a reachable-but-empty Vault yields `status: ok` with `vault_managed=0`, and (per the reconcile empty-mount fix) does **not** report failure. Run:

```bash
cd test/uat
VAULT_ADDR=http://vault:8200 VAULT_TOKEN=root \
  docker compose -f docker-compose.uat.yml --profile vault up -d --build
```
Expected: app starts with Vault configured; a `POST /api/v1/reconcile` returns `{"status":"ok",...,"vault_managed":0}` (verify: `curl -fsS -X POST localhost:8080/api/v1/reconcile | jq .status` → `ok`).

- [ ] **Step 3: Commit**

```bash
git add test/uat/docker-compose.uat.yml
git commit -m "test(uat): opt-in vault profile (managed-vs-shadow validation)"
```

---

### Task 7: `letsencrypt` profile — real external cert (staging, opt-in)

**Files:**
- Modify: `test/uat/docker-compose.uat.yml` (add a `lego` sidecar + an external endpoint under `profiles: [letsencrypt]`)

**Interfaces:**
- Consumes: `ACME_EMAIL` and `LE_DOMAIN` from `test/uat/.env`.
- Produces: an HTTPS endpoint serving a real LE **staging** cert, scannable as an external target.

- [ ] **Step 1: Add the lego sidecar + endpoint**

```yaml
  lego:
    image: goacme/lego:v4
    profiles: ["letsencrypt"]
    env_file: [.env]
    volumes:
      - ./le:/le
    # HTTP-01 needs :80 reachable from the internet on LE_DOMAIN.
    command: >
      --path /le --email ${ACME_EMAIL} --server https://acme-staging-v02.api.letsencrypt.org/directory
      --domains ${LE_DOMAIN} --http --http.port :80 --accept-tos run
    ports: ["80:80"]

  uat-letsencrypt:
    image: nginx:1.27-alpine
    profiles: ["letsencrypt"]
    env_file: [.env]
    volumes:
      - ./le:/le:ro
      - ./nginx/le.conf.tmpl:/etc/nginx/templates/default.conf.tmpl:ro
    depends_on:
      lego:
        condition: service_completed_successfully
```

Create `test/uat/nginx/le.conf.tmpl`:

```nginx
server {
    listen 443 ssl;
    server_name ${LE_DOMAIN};
    ssl_certificate     /le/certificates/${LE_DOMAIN}.crt;
    ssl_certificate_key /le/certificates/${LE_DOMAIN}.key;
    location / { return 200 "uat letsencrypt\n"; }
}
```

- [ ] **Step 2: Document + run (requires a public domain)**

Run (only meaningful with a real `LE_DOMAIN` pointing at this host and :80 reachable):

```bash
cd test/uat && cp .env.example .env   # then edit .env: real ACME_EMAIL + LE_DOMAIN
docker compose -f docker-compose.uat.yml --profile letsencrypt up -d --build
```
Then scan `${LE_DOMAIN}` and assert: `cert_scope == "external"`, no `sc081.expiry.*` finding (90-day cert), no `sc081.validity.*` finding today. This is a documented manual check (not automated in `driver.sh`) because it depends on external DNS.

- [ ] **Step 3: Commit**

```bash
git add test/uat/docker-compose.uat.yml test/uat/nginx/le.conf.tmpl
git commit -m "test(uat): opt-in letsencrypt (staging) external-cert profile"
```

---

### Task 8: Documentation (README + SDLC/testing tiers)

**Files:**
- Create: `test/uat/README.md`
- Modify: `CONTRIBUTING.md` (Verification commands)
- Modify: `docs/architecture.md` (add a "Testing tiers" note)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: operator docs.

- [ ] **Step 1: Write `test/uat/README.md`**

Include: purpose; how to run the Go test (`go test -tags uat ./internal/uat/...`); how to run the compose UAT (default, `--profile vault`, `--profile letsencrypt`); the env vars (`ACME_EMAIL`, `LE_DOMAIN`, gitignored `.env`); the full **expected-results matrix** (copy the table from the spec); and the four **intended behaviors** stated as expected (self-signed→`info`→not counted; fresh LE→no findings; `exp-14`/`exp-60` inclusive boundaries; validity vs expiry independence). State clearly: "a `FAIL` line is a real finding — triage bug vs intended against this table."

- [ ] **Step 2: Update `CONTRIBUTING.md` verification commands**

In the `## Verification commands` block, after `go test ./...`, add:

```bash
go test -tags uat ./internal/uat/...            # expiry/validity integration test
# Full manual UAT (real HTTPS endpoints):
#   cd test/uat && docker compose -f docker-compose.uat.yml up -d --build && sh driver.sh
```

- [ ] **Step 3: Add a "Testing tiers" note to `docs/architecture.md`**

Under a new `### Testing tiers` heading (near the existing testing/observability content), add: unit tests (`go test ./...`, default) → build-tagged integration (`go test -tags uat ./internal/uat/...`, real scanner+compliance, in CI) → docker-compose UAT (`test/uat/`, real HTTPS endpoints, manual/demo, opt-in vault + letsencrypt profiles). Link to `test/uat/README.md` and this plan's spec.

- [ ] **Step 4: Verify docs render and links resolve**

Run: `git diff --stat && grep -n "test/uat" CONTRIBUTING.md docs/architecture.md`
Expected: both files reference the UAT; README exists.

- [ ] **Step 5: Commit**

```bash
git add test/uat/README.md CONTRIBUTING.md docs/architecture.md
git commit -m "docs(uat): README, verification commands, and testing-tiers note"
```

---

## Self-Review

**Spec coverage:**
- G1 (real pipeline correctness) → Task 1 (Go) + Task 5 (driver). ✅
- G2 (boundaries) → Task 1 rows exp-14/15/60/61 + expired; +12h buffer constraint. ✅
- G3 (internal→info / prod→full) → Task 1 dual evaluation + Task 5 PATCH-to-prod. ✅
- G4 (shadow certs) → Task 5 blind-spot assertions. ✅
- G5 (CI regression + manual UAT) → Task 1/2 (CI) + Tasks 4–7 (compose). ✅
- G6 (Let's Encrypt) → Task 7. ✅
- SDLC/docs deliverables → Task 8. ✅
- Secrets handling → Task 3 (`.env.example`, `.gitignore`) + Task 7. ✅

**Placeholder scan:** No TBD/TODO; every code/step is concrete. The `valid-99` validity outcome is intentionally **not** asserted in the Go test (date-dependent as ceilings phase in) — documented as point-in-time in the README instead; `valid-400` (>every ceiling) is the robust validity assertion.

**Type consistency:** `scanner.Probe`→`ProbeResult.Certificate` (`cert.ParsedCertificate`); `governance.ClassifyScope(string(ChainStatus), IssuerDN, hostname, env)`; `compliance.EvaluateCerts([]store.Certificate)`→`ComplianceSummary{Findings, SC081ViolationCount}`; `Finding{RuleID, Pack, Severity, SubjectCN}`. Task 5 Step 2 explicitly verifies the `Finding` JSON key for `subject_cn` before relying on it.

**Known risk carried from spec:** LE lane needs a public domain + reachable :80; it is opt-in and excluded from `driver.sh` automation and CI.
