// Package cloud implements read-only cloud CA collectors (AKV / ACM / GCP CM)
// that feed the shared fingerprint inventory. No cloud root keys are stored in CLM.
package cloud

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
)

// PublicCertSource lists certificate names and fetches public PEM/CER only.
// Implementations must not expose GetKey / export private material.
type PublicCertSource interface {
	List(ctx context.Context) ([]string, error)
	GetPublicPEM(ctx context.Context, name string) (string, error)
}

// Collect lists public certs from src and ingests them under scanSource
// (cloud_akv | cloud_acm | cloud_gcp). Per-name fetch errors are skipped.
func Collect(ctx context.Context, up collectors.Upserter, scanID uuid.UUID, scanSource string, src PublicCertSource) (ingested, skipped int, err error) {
	if err := collectors.ValidateSource(scanSource); err != nil {
		return 0, 0, err
	}
	if src == nil {
		return 0, 0, fmt.Errorf("cloud source required")
	}
	names, err := src.List(ctx)
	if err != nil {
		return 0, 0, err
	}
	var items []collectors.Item
	for _, name := range names {
		pemText, gerr := src.GetPublicPEM(ctx, name)
		if gerr != nil || pemText == "" {
			skipped++
			continue
		}
		items = append(items, collectors.Item{PEM: pemText, Name: name})
	}
	n, skipParse, err := collectors.IngestPublicPEMs(ctx, up, scanID, scanSource, items)
	return n, skipped + skipParse, err
}
