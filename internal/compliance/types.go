package compliance

import (
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// Finding is an in-memory compliance violation for a single certificate.
type Finding struct {
	RuleID      string    `json:"rule_id"`
	Pack        string    `json:"pack"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	CertID      uuid.UUID `json:"cert_id"`
	Fingerprint string    `json:"fingerprint"`
	SubjectCN   string    `json:"subject_cn"`
}

// AlgorithmInventory aggregates key and signature algorithm counts.
type AlgorithmInventory struct {
	RSA2048Plus     int `json:"rsa_2048_plus"`
	RSAUnder2048    int `json:"rsa_under_2048"`
	ECDSA           int `json:"ecdsa"`
	Ed25519         int `json:"ed25519"`
	SHA1Signatures  int `json:"sha1_signatures"`
}

// ComplianceSummary is the scan- or estate-level compliance report payload.
type ComplianceSummary struct {
	ScanID              uuid.UUID          `json:"scan_id,omitempty"`
	GeneratedAt         time.Time          `json:"generated_at"`
	TotalCerts          int                `json:"total_certs"`
	FindingsBySeverity  map[string]int     `json:"findings_by_severity"`
	FindingsByPack      map[string]int     `json:"findings_by_pack"`
	AlgorithmInventory  AlgorithmInventory `json:"algorithm_inventory"`
	SC081ViolationCount int                `json:"sc081_violation_count"`
	PCIFindingCount     int                `json:"pci_finding_count"`
	Findings            []Finding          `json:"findings"`
}

// CertInput is the normalized certificate view used by evaluators.
type CertInput struct {
	ID                 uuid.UUID
	Fingerprint        string
	SubjectCN          string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyType            string
	KeyBits            int
	SignatureAlgorithm string
	CertScope          string
	Environment        *string
	Owner              *string
	Tags               []string
	ManagedStatus      string
	DaysUntilExpiry    int
}

// CertInputFromStore maps a store row into evaluator input.
func CertInputFromStore(c store.Certificate) CertInput {
	subjectCN := ""
	if c.SubjectCN != nil {
		subjectCN = *c.SubjectCN
	}
	return CertInput{
		ID:                 c.ID,
		Fingerprint:        c.FingerprintSHA256,
		SubjectCN:          subjectCN,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		KeyType:            c.KeyType,
		KeyBits:            c.KeyBits,
		SignatureAlgorithm: c.SignatureAlgorithm,
		CertScope:          c.CertScope,
		Environment:        c.Environment,
		Owner:              c.Owner,
		Tags:               c.Tags,
		ManagedStatus:      c.ManagedStatus,
		DaysUntilExpiry:    c.DaysUntilExpiry,
	}
}
