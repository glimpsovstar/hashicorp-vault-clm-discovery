# Design: CRL revocation for shadow certs (#40)

- **Issue:** #40 (extends v1.1b revocation beyond Vault-issued certs)
- **Status:** Implemented (slice 1: CRL). OCSP is a follow-up.
- **Builds on:** revocation columns (`status`, `revocation_status`) already exist.

## Goal

Detect revocation for **any** discovered certificate via its own CRL, not just
Vault-issued ones. On-demand, read-only external fetch.

## Design

### Core (`internal/revocation/crl.go`)

Pure-ish, injectable `*http.Client`:

```go
type Status string // good | revoked | unknown

type Result struct {
    Status    Status
    Source    string     // "crl"
    Verified  bool       // CRL signature verified against the issuer cert
    RevokedAt *time.Time
    CRLURL    string
}

func CheckCRL(ctx, client, serialHex string, crlURLs []string, issuerPEM string) (Result, error)
```

- No CRL DP → `unknown`. Fetch first reachable DP, `x509.ParseRevocationList`.
- Membership: parse `serialHex` (base-16, as stored) to `big.Int`, compare to
  `RevokedCertificateEntries[].SerialNumber`.
- **Signature verification:** when `issuerPEM` is provided, `crl.CheckSignatureFrom(issuer)`;
  set `Verified=true` on success. Verification failure does not error — it yields
  an **unverified** result.

### API (`POST /api/v1/certificates/{id}/revocation-check`)

Load the cert; best-effort find its issuer (a stored CA whose subject matches the
leaf's `issuer_dn`) to pass `issuerPEM`; run `CheckCRL`. **Persist
`status=revoked` + `revocation_status='revoked_via_crl'` only when the result is
`revoked` AND `Verified`** (an unauthenticated CRL is advisory only — never
mutates state). Return the `Result` either way.

### UI

Cert detail: "Check revocation" button → shows the result (status + verified +
source). Uses the existing catalog-import button pattern.

## Security

- Only a **signature-verified** CRL can flip a cert to revoked; MITM of an
  unauthenticated CRL fetch is advisory-only (no state change), bounding impact.
- Bounded HTTP timeout; the CRL URL comes from the cert's own CRLDistributionPoints.

## Testing (TDD)

- `crl_test.go`: generated CA+leaf; a CA-signed CRL revoking the leaf → `revoked`+`verified`;
  a non-revoked serial → `good`; no CRL DP → `unknown`; wrong issuer → `verified=false`.
- API handler: 400/404/500; success persists only when verified (fake store + stub CRL).

## Verification gate

`go build/vet/test ./...`, `cd web && npm run build`, PR + sub-agent review.
