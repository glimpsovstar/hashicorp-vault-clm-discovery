package revocation

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"

	"golang.org/x/crypto/ocsp"
)

// CheckInput carries everything the combined Check needs for one certificate.
type CheckInput struct {
	SerialHex   string
	LeafPEM     string
	IssuerPEM   string
	OCSPServers []string
	CRLURLs     []string
}

// Check prefers OCSP (a signed, authoritative per-cert answer verified against
// the issuer) and falls back to CRL when OCSP is unavailable or inconclusive.
func Check(ctx context.Context, client *http.Client, in CheckInput) (Result, error) {
	if r, err := CheckOCSP(ctx, client, in.LeafPEM, in.IssuerPEM, in.OCSPServers); err == nil && r.Status != StatusUnknown {
		return r, nil
	}
	return CheckCRL(ctx, client, in.SerialHex, in.CRLURLs, in.IssuerPEM)
}

// CheckOCSP queries the first working OCSP responder for the leaf's status and
// verifies the signed response against the issuer. Requires both leaf and issuer
// certs. Returns StatusUnknown when there is no responder, no issuer, or none
// could be reached/verified.
func CheckOCSP(ctx context.Context, client *http.Client, leafPEM, issuerPEM string, ocspServers []string) (Result, error) {
	res := Result{Status: StatusUnknown, Source: "ocsp"}
	if len(ocspServers) == 0 || issuerPEM == "" || leafPEM == "" {
		return res, nil
	}
	leaf := parseCert(leafPEM)
	issuer := parseCert(issuerPEM)
	if leaf == nil || issuer == nil {
		return res, nil
	}

	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return res, fmt.Errorf("create ocsp request: %w", err)
	}
	if client == nil {
		client = defaultClient()
	}

	for _, server := range ocspServers {
		u, err := neturl.Parse(server)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		respDER, err := postOCSP(ctx, client, server, reqDER)
		if err != nil {
			continue
		}
		// ParseResponseForCert validates the response signature against the issuer
		// (incl. a delegated responder cert) and that it is for this leaf.
		ocspResp, err := ocsp.ParseResponseForCert(respDER, leaf, issuer)
		if err != nil {
			continue
		}
		res.Verified = true
		switch ocspResp.Status {
		case ocsp.Good:
			res.Status = StatusGood
		case ocsp.Revoked:
			res.Status = StatusRevoked
			rt := ocspResp.RevokedAt
			res.RevokedAt = &rt
		default:
			res.Status = StatusUnknown
		}
		return res, nil
	}
	return res, nil
}

func postOCSP(ctx context.Context, client *http.Client, server string, reqDER []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp %s: status %d", server, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
