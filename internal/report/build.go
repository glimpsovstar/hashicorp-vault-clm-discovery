package report

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// ErrScanNotCompleted is returned when a report is requested for a scan that
// has not finished. Callers match it with errors.Is rather than string compare.
var ErrScanNotCompleted = errors.New("scan not completed")

// ScanStore loads scan metadata and certificate counts for report generation.
type ScanStore interface {
	GetScan(ctx context.Context, id uuid.UUID) (store.Scan, error)
	CountByManagedStatus(ctx context.Context, scanID *uuid.UUID) (managed, discovered int, err error)
	compliance.CertStore
}

// BuildForScan assembles a report document for a completed scan.
func BuildForScan(ctx context.Context, st ScanStore, scanID uuid.UUID) (Document, error) {
	scan, err := st.GetScan(ctx, scanID)
	if err != nil {
		return Document{}, err
	}
	if scan.Status != "completed" {
		return Document{}, ErrScanNotCompleted
	}

	managed, discovered, err := st.CountByManagedStatus(ctx, &scanID)
	if err != nil {
		return Document{}, err
	}

	summary, err := compliance.EvaluateScan(ctx, st, &scanID)
	if err != nil {
		return Document{}, err
	}

	blindSpot := BuildBlindSpotSummary(managed, discovered, summary.SC081ViolationCount)
	return Generate(GenerateInput{
		Scan:       scan,
		BlindSpot:  blindSpot,
		Compliance: summary,
	}), nil
}
