package scanrunner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/logging"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type Job struct {
	ScanID      uuid.UUID
	CIDRs       []string
	Hostnames   []string
	Ports       []int
	Concurrency int
}

type Runner struct {
	store     *store.Store
	scanner   *scanner.Scanner
	log       *slog.Logger
	logLevel  string
	allowPriv bool
}

func New(st *store.Store, sc *scanner.Scanner, log *slog.Logger, logLevel string, allowPrivate bool) *Runner {
	return &Runner{
		store:     st,
		scanner:   sc,
		log:       log,
		logLevel:  logLevel,
		allowPriv: allowPrivate,
	}
}

func (r *Runner) Run(ctx context.Context, job Job) error {
	log := r.log.With("scan_id", job.ScanID)

	targets, warnings, err := scanner.ExpandScanTargets(job.CIDRs, job.Hostnames, job.Ports, r.allowPriv)
	if err != nil {
		r.failScan(ctx, job.ScanID, err.Error(), log)
		return err
	}

	if logging.IsDebugOrTrace(r.logLevel) {
		log.Debug("target expansion",
			"cidrs", job.CIDRs,
			"hostnames", job.Hostnames,
			"ports", job.Ports,
			"target_count", len(targets),
			"warning_count", len(warnings),
			"warnings", warnings,
		)
	}

	if err := r.store.UpdateScanRunning(ctx, job.ScanID, len(targets)); err != nil {
		msg := fmt.Sprintf("failed to mark scan running: %v", err)
		r.failScan(ctx, job.ScanID, msg, log)
		return err
	}

	concurrency := job.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	stats := &store.ScanStats{}

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t scanner.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			result := r.scanner.Probe(ctx, t)

			mu.Lock()
			stats.Scanned++
			curScanned := stats.Scanned
			mu.Unlock()

			if result.Error != nil {
				mu.Lock()
				stats.RecordProbeFailure(t, result.Error.Error())
				mu.Unlock()
				log.Error("probe failed", targetAttrs(t, result.Observation.SNI, nil)...)

				if logging.IsTrace(r.logLevel) {
					log.Log(context.Background(), logging.LevelTrace, "probe outcome",
						append(targetAttrs(t, result.Observation.SNI, nil), "outcome", "failed", "err", result.Error)...)
				}
			} else {
				if logging.IsTrace(r.logLevel) {
					log.Log(context.Background(), logging.LevelTrace, "probe outcome",
						append(targetAttrs(t, result.Observation.SNI, &result.Certificate), "outcome", "success")...)
				} else if logging.IsDebugOrTrace(r.logLevel) {
					log.Debug("probe succeeded", targetAttrs(t, result.Observation.SNI, &result.Certificate)...)
				}

				mu.Lock()
				stats.RecordProbeSuccess()
				mu.Unlock()

				if _, err := r.store.UpsertCertificate(ctx, job.ScanID, result.Certificate, result.Observation); err != nil {
					mu.Lock()
					stats.RecordUpsertFailure(t, err.Error())
					mu.Unlock()
					log.Error("upsert certificate",
						append(targetAttrs(t, result.Observation.SNI, &result.Certificate), "err", err)...)

					mu.Lock()
					curCerts := stats.CertsFound
					mu.Unlock()
					if curScanned%10 == 0 || curScanned == len(targets) {
						r.updateProgress(ctx, job.ScanID, curScanned, curCerts, log)
					}
					return
				}

				mu.Lock()
				stats.RecordCertFound()
				curCerts := stats.CertsFound
				mu.Unlock()

				for _, ca := range result.Chain {
					if ca.IsCA {
						chainPEMs := make([]string, len(result.Chain))
						for i, c := range result.Chain {
							chainPEMs[i] = c.PEM
						}
						if err := r.store.UpsertIssuer(ctx, ca, chainPEMs); err != nil {
							attrs := append(certAttrs(&ca), targetAttrs(t, result.Observation.SNI, &result.Certificate)...)
							log.Warn("upsert issuer", append(attrs, "err", err)...)
						}
					}
				}

				if curScanned%10 == 0 || curScanned == len(targets) {
					r.updateProgress(ctx, job.ScanID, curScanned, curCerts, log)
				}
			}

			if result.Error != nil && (curScanned%10 == 0 || curScanned == len(targets)) {
				mu.Lock()
				curCerts := stats.CertsFound
				mu.Unlock()
				r.updateProgress(ctx, job.ScanID, curScanned, curCerts, log)
			}
		}(target)
	}

	wg.Wait()

	summary := stats.Summary(len(targets), warnings)
	if err := r.store.CompleteScan(ctx, job.ScanID, summary); err != nil {
		log.Error("complete scan", "err", err)
	}

	log.Info("scan complete",
		"targets_total", summary.TargetsTotal,
		"targets_scanned", summary.TargetsScanned,
		"targets_succeeded", summary.TargetsSucceeded,
		"targets_failed", summary.TargetsFailed,
		"certs_found", summary.CertsFound,
		"upsert_failures", summary.UpsertFailures,
		"warning_count", len(summary.ExpansionWarnings),
	)

	return nil
}

func (r *Runner) failScan(ctx context.Context, scanID uuid.UUID, msg string, log *slog.Logger) {
	log.Error("scan failed", "err", msg)
	if err := r.store.FailScan(ctx, scanID, msg); err != nil {
		log.Error("persist scan failure", "err", err)
	}
}

func (r *Runner) updateProgress(ctx context.Context, scanID uuid.UUID, scanned, certsFound int, log *slog.Logger) {
	if err := r.store.UpdateScanProgress(ctx, scanID, scanned, certsFound); err != nil {
		log.Warn("update scan progress", "scan_id", scanID, "err", err)
	}
}

func targetAttrs(t scanner.Target, sni string, parsed *cert.ParsedCertificate) []any {
	attrs := []any{
		"target", fmt.Sprintf("%s:%d", t.IP, t.Port),
		"ip", t.IP,
		"port", t.Port,
	}
	if t.Hostname != "" {
		attrs = append(attrs, "hostname", t.Hostname)
	}
	if sni != "" {
		attrs = append(attrs, "sni", sni)
	}
	if parsed != nil {
		attrs = append(attrs,
			"fingerprint_sha256", parsed.FingerprintSHA256,
			"serial_number", parsed.SerialNumber,
		)
	}
	return attrs
}

func certAttrs(parsed *cert.ParsedCertificate) []any {
	return []any{
		"fingerprint_sha256", parsed.FingerprintSHA256,
		"serial_number", parsed.SerialNumber,
	}
}
