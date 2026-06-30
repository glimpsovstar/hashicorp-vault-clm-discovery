package compliance

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// CertStore loads certificates for compliance evaluation.
type CertStore interface {
	ListCertificates(ctx context.Context, f store.CertificateFilter) ([]store.Certificate, int, error)
}

var severityRank = map[string]int{
	"critical": 0,
	"warning":  1,
	"info":     2,
}

// EvaluateCert runs all compliance packs for a single certificate.
func EvaluateCert(cert store.Certificate) []Finding {
	input := CertInputFromStore(cert)
	var findings []Finding
	findings = append(findings, EvaluateSC081(input)...)
	findings = append(findings, EvaluatePCI(input)...)
	findings = append(findings, EvaluateCrypto(input)...)
	sortFindings(findings)
	return findings
}

// EvaluateCerts aggregates findings across certificate rows.
func EvaluateCerts(certs []store.Certificate) ComplianceSummary {
	summary := ComplianceSummary{
		GeneratedAt:        time.Now().UTC(),
		TotalCerts:         len(certs),
		FindingsBySeverity: map[string]int{},
		FindingsByPack:     map[string]int{},
		Findings:           []Finding{},
	}

	for _, cert := range certs {
		updateAlgorithmInventory(&summary.AlgorithmInventory, cert)
		findings := EvaluateCert(cert)
		for _, f := range findings {
			summary.Findings = append(summary.Findings, f)
			summary.FindingsBySeverity[f.Severity]++
			summary.FindingsByPack[f.Pack]++
			if f.Pack == "sc081" {
				summary.SC081ViolationCount++
			}
			if f.Pack == "pci" {
				summary.PCIFindingCount++
			}
		}
	}

	sortFindings(summary.Findings)
	return summary
}

// EvaluateScan loads certificates and returns a compliance summary.
// When scanID is nil, evaluates the full estate.
func EvaluateScan(ctx context.Context, st CertStore, scanID *uuid.UUID) (ComplianceSummary, error) {
	certs, err := loadAllCertificates(ctx, st, scanID)
	if err != nil {
		return ComplianceSummary{}, err
	}

	summary := EvaluateCerts(certs)
	if scanID != nil {
		summary.ScanID = *scanID
	}
	return summary, nil
}

// CountSC081Violations returns the number of SC-081 pack findings. It runs only
// the SC-081 pack — callers that need a single count should not pay for the PCI
// and crypto packs, algorithm inventory, and finding sort that EvaluateScan does.
func CountSC081Violations(ctx context.Context, st CertStore, scanID *uuid.UUID) (int, error) {
	certs, err := loadAllCertificates(ctx, st, scanID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, cert := range certs {
		count += len(EvaluateSC081(CertInputFromStore(cert)))
	}
	return count, nil
}

func loadAllCertificates(ctx context.Context, st CertStore, scanID *uuid.UUID) ([]store.Certificate, error) {
	filter := store.CertificateFilter{Limit: 500, Offset: 0}
	if scanID != nil {
		filter.ScanID = *scanID
	}

	var all []store.Certificate
	for {
		batch, total, err := st.ListCertificates(ctx, filter)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		filter.Offset += len(batch)
		if filter.Offset >= total || len(batch) == 0 {
			break
		}
	}
	return all, nil
}

func updateAlgorithmInventory(inv *AlgorithmInventory, cert store.Certificate) {
	switch {
	case strings.EqualFold(cert.KeyType, "RSA") && cert.KeyBits >= 2048:
		inv.RSA2048Plus++
	case strings.EqualFold(cert.KeyType, "RSA") && cert.KeyBits < 2048:
		inv.RSAUnder2048++
	case strings.EqualFold(cert.KeyType, "ECDSA"):
		inv.ECDSA++
	case strings.EqualFold(cert.KeyType, "Ed25519"), strings.EqualFold(cert.KeyType, "ED25519"):
		inv.Ed25519++
	}
	if containsSHA1(cert.SignatureAlgorithm) {
		inv.SHA1Signatures++
	}
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, okI := severityRank[findings[i].Severity]
		rj, okJ := severityRank[findings[j].Severity]
		if !okI {
			ri = 99
		}
		if !okJ {
			rj = 99
		}
		if ri != rj {
			return ri < rj
		}
		if findings[i].Pack != findings[j].Pack {
			return findings[i].Pack < findings[j].Pack
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}
