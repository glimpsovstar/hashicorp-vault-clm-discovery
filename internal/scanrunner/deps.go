package scanrunner

import (
	"context"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type scanStore interface {
	UpdateScanRunning(ctx context.Context, id uuid.UUID, targetsTotal int) error
	UpdateScanProgress(ctx context.Context, id uuid.UUID, scanned, certsFound int) error
	CompleteScan(ctx context.Context, id uuid.UUID, summary store.ScanSummary) error
	FailScan(ctx context.Context, id uuid.UUID, errMsg string) error
	UpsertCertificate(ctx context.Context, scanID uuid.UUID, parsed cert.ParsedCertificate, obs cert.Observation) (uuid.UUID, error)
	UpsertIssuer(ctx context.Context, ca cert.ParsedCertificate, chainPEMs []string) error
}

type prober interface {
	Probe(ctx context.Context, target scanner.Target) scanner.ProbeResult
}
