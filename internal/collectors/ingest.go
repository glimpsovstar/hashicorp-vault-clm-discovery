package collectors

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

// Allowed collector scan sources. Cloud vendors use cloud_* (#99); ADCS is
// on-prem Windows CA collection via AAP (#86).
var allowedSources = map[string]struct{}{
	"adcs":      {},
	"cloud_akv": {},
	"cloud_acm": {},
	"cloud_gcp": {},
}

// ErrPrivateKeyRejected is returned when PEM material contains a private key.
var ErrPrivateKeyRejected = errors.New("private key material is not accepted")

// ErrInvalidSource is returned for unknown scan_source values.
var ErrInvalidSource = errors.New("invalid collector scan source")

// Item is one public certificate to ingest.
type Item struct {
	PEM  string `json:"pem"`
	Name string `json:"name,omitempty"`
}

// Upserter persists parsed certificates (satisfied by *store.Store).
type Upserter interface {
	UpsertCertificate(ctx context.Context, scanID uuid.UUID, parsed cert.ParsedCertificate, obs cert.Observation) (uuid.UUID, error)
}

// ValidateSource reports whether source is an allowed collector scan source.
func ValidateSource(source string) error {
	if _, ok := allowedSources[source]; !ok {
		return fmt.Errorf("%w: %q", ErrInvalidSource, source)
	}
	return nil
}

// IngestPublicPEMs parses CERTIFICATE PEM blocks only, upserts by
// fingerprint_sha256, and rejects private-key material. source becomes the
// observation IP sentinel (e.g. cloud_akv).
func IngestPublicPEMs(ctx context.Context, up Upserter, scanID uuid.UUID, source string, items []Item) (ingested, skipped int, err error) {
	if err := ValidateSource(source); err != nil {
		return 0, 0, err
	}
	if up == nil {
		return 0, 0, fmt.Errorf("upserter required")
	}
	now := time.Now().UTC()
	for _, it := range items {
		if containsPrivateKey(it.PEM) {
			return ingested, skipped, ErrPrivateKeyRejected
		}
		parsed, perr := parsePublicPEM(it.PEM)
		if perr != nil {
			skipped++
			continue
		}
		sni := it.Name
		if sni == "" && parsed.SubjectCN != "" {
			sni = parsed.SubjectCN
		}
		obs := cert.Observation{
			IP:         source,
			Port:       0,
			Hostname:   sni,
			SNI:        source + ":" + sni,
			ObservedAt: now,
		}
		if _, uerr := up.UpsertCertificate(ctx, scanID, parsed, obs); uerr != nil {
			return ingested, skipped, uerr
		}
		ingested++
	}
	return ingested, skipped, nil
}

func containsPrivateKey(pemText string) bool {
	upper := strings.ToUpper(pemText)
	return strings.Contains(upper, "PRIVATE KEY")
}

func parsePublicPEM(pemText string) (cert.ParsedCertificate, error) {
	rest := []byte(pemText)
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return cert.ParsedCertificate{}, err
		}
		if leaf == nil {
			leaf = c
		}
		chain = append(chain, c)
	}
	if leaf == nil {
		return cert.ParsedCertificate{}, fmt.Errorf("no CERTIFICATE PEM block")
	}
	hostname := leaf.Subject.CommonName
	return cert.ParseCertificate(leaf, chain, hostname, hostname), nil
}
