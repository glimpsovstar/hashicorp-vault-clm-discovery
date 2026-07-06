// Package revocation checks certificate revocation via CRL (and, later, OCSP)
// for certificates discovered on the wire — including shadow (non-Vault) certs.
package revocation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	neturl "net/url"
	"syscall"
	"time"
)

// Status is the revocation outcome for a certificate.
type Status string

const (
	StatusGood    Status = "good"
	StatusRevoked Status = "revoked"
	StatusUnknown Status = "unknown"
)

// Result is a single revocation check outcome.
type Result struct {
	Status    Status     `json:"status"`
	Source    string     `json:"source"`   // "crl" or "ocsp"
	Verified  bool       `json:"verified"` // response/CRL signature verified against the issuer
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CRLURL    string     `json:"crl_url,omitempty"`
}

// CheckCRL fetches the first reachable CRL distribution point, parses it, and
// reports whether serialHex (base-16, as stored) is revoked. When issuerPEM is
// provided, the CRL signature is verified against the issuer certificate and
// Result.Verified is set accordingly; verification failure is not an error (the
// result is simply unverified). Returns StatusUnknown when there is no CRL
// distribution point or none could be fetched/parsed.
func CheckCRL(ctx context.Context, client *http.Client, serialHex string, crlURLs []string, issuerPEM string) (Result, error) {
	res := Result{Status: StatusUnknown, Source: "crl"}
	if len(crlURLs) == 0 {
		return res, nil
	}

	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return res, fmt.Errorf("invalid serial %q", serialHex)
	}
	if client == nil {
		client = NewFetchClient()
	}

	var crl *x509.RevocationList
	for _, u := range crlURLs {
		der, err := fetchCRL(ctx, client, u)
		if err != nil {
			continue
		}
		parsed, err := x509.ParseRevocationList(der)
		if err != nil {
			continue
		}
		crl = parsed
		res.CRLURL = u
		break
	}
	if crl == nil {
		return res, nil // unknown: no CRL reachable/parseable
	}

	if issuerPEM != "" {
		if issuer := parseCert(issuerPEM); issuer != nil {
			res.Verified = crl.CheckSignatureFrom(issuer) == nil
		}
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			res.Status = StatusRevoked
			rt := entry.RevocationTime
			res.RevokedAt = &rt
			return res, nil
		}
	}
	res.Status = StatusGood
	return res, nil
}

func fetchCRL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	// The CRL URL comes from the scanned certificate (attacker-influenced), so
	// restrict the scheme to http/https to avoid file:// and other SSRF vectors.
	u, err := neturl.Parse(url)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("unsupported CRL URL scheme")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crl %s: status %d", url, resp.StatusCode)
	}
	// Cap the read to protect against oversized/hostile CRLs.
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// NewFetchClient returns the hardened HTTP client for revocation (CRL/OCSP)
// fetches: a bounded timeout, redirects disabled, and a dialer that refuses
// non-public addresses. The fetched URLs come from the scanned certificate
// (attacker-influenced), so this closes blind-SSRF into internal networks; the
// address check runs post-resolution, so DNS rebinding to an internal IP is also
// blocked.
func NewFetchClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to dial non-IP address %q", host)
			}
			if !isPublicIP(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
}

// isPublicIP reports whether ip is a routable public address (not loopback,
// unspecified, link-local, or private RFC-1918/ULA).
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

func parseCert(pemStr string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}
