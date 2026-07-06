# Design: OCSP revocation check (#42, follow-up to #40 CRL)

- **Issue:** #42 (builds on `internal/revocation` from #40)
- **Status:** Implemented.

## Goal

Add OCSP as the preferred revocation check. OCSP responses are **signed**, so a
verified "revoked" is authoritative; combine with CRL as a fallback.

## Design

- **`internal/revocation.CheckOCSP(ctx, client, leafPEM, issuerPEM, ocspServers)`**
  (`golang.org/x/crypto/ocsp`): build request from leaf+issuer, POST to the first
  responder (`application/ocsp-request`), parse with `ParseResponseForCert(resp,
  leaf, issuer)` which validates the response signature against the issuer.
  `Verified=true` on success. `unknown` when no responder / no issuer / all fail.
- **`Check(ctx, client, CheckInput{SerialHex, LeafPEM, IssuerPEM, OCSPServers,
  CRLURLs})`** — OCSP first; if inconclusive/unavailable, fall back to `CheckCRL`.
- **API:** the existing `POST /certificates/{id}/revocation-check` now builds a
  `CheckInput` (leaf PEM + issuer PEM + OCSP servers + CRL DPs) and calls the
  `revChecker` seam (default `revocation.Check`). The persist rule is unchanged:
  `status=revoked` only when the result is `revoked` AND `Verified`.

## Security

- Same SSRF hardening as CRL: scheme allowlist (`http`/`https`), redirects
  disabled on the fetch client, bounded body read, operator-triggered.
- OCSP verified via issuer (incl. delegated responder cert) → cannot be forged.

## Testing

- `ocsp_test.go`: mock responder (CA-signed) → good/revoked+verified; unknown when
  no responder/issuer; `Check` prefers OCSP then falls back to CRL.
- Handler tests reuse the `revChecker` seam (verified-persists vs advisory).
