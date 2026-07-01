package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/lifecycle"
)

// ErrScanNotFound, ErrCertificateNotFound, and ErrIssuerNotFound are returned
// when a row does not exist, letting callers distinguish a genuine not-found
// from an underlying database/IO failure (which must not be reported as 404).
var (
	ErrScanNotFound        = errors.New("scan not found")
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrIssuerNotFound      = errors.New("issuer not found")
)

type Store struct {
	pool             *pgxpool.Pool
	expiringSoonDays int
}

func New(pool *pgxpool.Pool, expiringSoonDays int) *Store {
	return &Store{pool: pool, expiringSoonDays: expiringSoonDays}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

type Scan struct {
	ID                uuid.UUID             `json:"id"`
	Source            string                `json:"source"`
	Status            string                `json:"status"`
	CIDRs             []string              `json:"cidrs"`
	Hostnames         []string              `json:"hostnames"`
	Ports             []int                 `json:"ports"`
	Concurrency       int                   `json:"concurrency"`
	StartedAt         *time.Time            `json:"started_at,omitempty"`
	FinishedAt        *time.Time            `json:"finished_at,omitempty"`
	TargetsTotal      int                   `json:"targets_total"`
	TargetsScanned    int                   `json:"targets_scanned"`
	TargetsSucceeded  int                   `json:"targets_succeeded"`
	TargetsFailed     int                   `json:"targets_failed"`
	CertsFound        int                   `json:"certs_found"`
	UpsertFailures    int                   `json:"upsert_failures"`
	ExpansionWarnings []string              `json:"expansion_warnings"`
	FailureSamples    []TargetFailureSample `json:"failure_samples"`
	Error             *string               `json:"error,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
}

type Certificate struct {
	ID                    uuid.UUID  `json:"id"`
	SerialNumber          string     `json:"serial_number"`
	FingerprintSHA256     string     `json:"fingerprint_sha256"`
	SubjectCN             *string    `json:"subject_cn"`
	SubjectAltNames       []string   `json:"subject_alt_names"`
	IssuerDN              string     `json:"issuer_dn"`
	AuthorityKeyID        *string    `json:"authority_key_id"`
	NotBefore             time.Time  `json:"not_before"`
	NotAfter              time.Time  `json:"not_after"`
	KeyType               string     `json:"key_type"`
	KeyBits               int        `json:"key_bits"`
	SignatureAlgorithm    string     `json:"signature_algorithm"`
	IsCA                  bool       `json:"is_ca"`
	KeyUsage              []string   `json:"key_usage"`
	ExtKeyUsage           []string   `json:"ext_key_usage"`
	PEM                   string     `json:"pem"`
	DaysUntilExpiry       int        `json:"days_until_expiry"`
	Status                string     `json:"status"`
	RevocationStatus      *string    `json:"revocation_status"`
	RevocationCheckedAt   *time.Time `json:"revocation_checked_at"`
	CRLDistributionPoints []string   `json:"crl_distribution_points"`
	OCSPServers           []string   `json:"ocsp_servers"`
	FirstDiscovered       time.Time  `json:"first_discovered"`
	LastSeen              time.Time  `json:"last_seen"`
	HostnameMatchesSAN    bool       `json:"hostname_matches_san"`
	ChainStatus           string     `json:"chain_status"`
	ManagedStatus         string     `json:"managed_status"`
	CertScope             string     `json:"cert_scope"`
	VaultIssuerRef        *string    `json:"vault_issuer_ref"`
	VaultPKIMount         *string    `json:"vault_pki_mount"`
	Owner                 *string    `json:"owner"`
	Team                  *string    `json:"team"`
	Environment           *string    `json:"environment"`
	Tags                  []string   `json:"tags"`
	RiskScore             int        `json:"risk_score"`
	RemediationState      string     `json:"remediation_state"`
	ObservationCount      int        `json:"observation_count,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

type Observation struct {
	ID            uuid.UUID `json:"id"`
	CertificateID uuid.UUID `json:"certificate_id"`
	ScanID        uuid.UUID `json:"scan_id"`
	IP            string    `json:"ip"`
	Port          int       `json:"port"`
	Hostname      *string   `json:"hostname"`
	SNI           *string   `json:"sni"`
	TLSVersion    *string   `json:"tls_version"`
	CipherSuite   *string   `json:"cipher_suite"`
	ObservedAt    time.Time `json:"observed_at"`
}

type Issuer struct {
	ID                uuid.UUID `json:"id"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	SerialNumber      string    `json:"serial_number"`
	SubjectCN         *string   `json:"subject_cn"`
	IssuerDN          string    `json:"issuer_dn"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	KeyType           string    `json:"key_type"`
	KeyBits           int       `json:"key_bits"`
	IsCA              bool      `json:"is_ca"`
	PEM               string    `json:"pem"`
	DaysUntilExpiry   int       `json:"days_until_expiry"`
	Status            string    `json:"status"`
	IssuerName        *string   `json:"issuer_name"`
	IssuerID          *string   `json:"issuer_id"`
	CAChain           []string  `json:"ca_chain"`
}

type CertificateFilter struct {
	Status      string
	ChainStatus string
	Search      string
	ScanID      uuid.UUID
	Limit       int
	Offset      int
}

type EnrichmentUpdate struct {
	Owner       *string
	Team        *string
	Environment *string
	Tags        []string
}

func (s *Store) CreateScan(ctx context.Context, cidrs, hostnames []string, ports []int, concurrency int) (Scan, error) {
	if cidrs == nil {
		cidrs = []string{}
	}
	if hostnames == nil {
		hostnames = []string{}
	}
	var scan Scan
	samplesScanner := failureSamplesArg(&scan.FailureSamples)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO scans (cidrs, hostnames, ports, concurrency, targets_total)
		VALUES ($1, $2, $3, $4, 0)
		RETURNING id, source, status::text, cidrs, hostnames, ports, concurrency,
			started_at, finished_at, targets_total, targets_scanned, targets_succeeded, targets_failed,
			certs_found, upsert_failures, expansion_warnings, failure_samples, error, created_at
	`, cidrs, hostnames, ports, concurrency).Scan(
		&scan.ID, &scan.Source, &scan.Status, &scan.CIDRs, &scan.Hostnames, &scan.Ports, &scan.Concurrency,
		&scan.StartedAt, &scan.FinishedAt, &scan.TargetsTotal, &scan.TargetsScanned,
		&scan.TargetsSucceeded, &scan.TargetsFailed, &scan.CertsFound, &scan.UpsertFailures,
		&scan.ExpansionWarnings, &samplesScanner, &scan.Error, &scan.CreatedAt,
	)
	return scan, err
}

func (s *Store) UpdateScanRunning(ctx context.Context, id uuid.UUID, targetsTotal int) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		UPDATE scans SET status = 'running', started_at = $2, targets_total = $3 WHERE id = $1
	`, id, now, targetsTotal)
	return err
}

func (s *Store) UpdateScanProgress(ctx context.Context, id uuid.UUID, scanned, certsFound int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scans SET targets_scanned = $2, certs_found = $3 WHERE id = $1
	`, id, scanned, certsFound)
	return err
}

func (s *Store) CompleteScan(ctx context.Context, id uuid.UUID, summary ScanSummary) error {
	now := time.Now().UTC()
	samplesJSON, err := failureSamplesJSON(summary.FailureSamples)
	if err != nil {
		return err
	}
	warnings := summary.ExpansionWarnings
	if warnings == nil {
		warnings = []string{}
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE scans SET
			status = 'completed',
			finished_at = $2,
			targets_scanned = $3,
			targets_succeeded = $4,
			targets_failed = $5,
			certs_found = $6,
			upsert_failures = $7,
			expansion_warnings = $8,
			failure_samples = $9,
			error = NULL
		WHERE id = $1
	`, id, now, summary.TargetsScanned, summary.TargetsSucceeded, summary.TargetsFailed,
		summary.CertsFound, summary.UpsertFailures, warnings, samplesJSON)
	return err
}

func (s *Store) FailScan(ctx context.Context, id uuid.UUID, errMsg string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		UPDATE scans SET status = 'failed', finished_at = $2, error = $3 WHERE id = $1
	`, id, now, errMsg)
	return err
}

func (s *Store) GetScan(ctx context.Context, id uuid.UUID) (Scan, error) {
	var scan Scan
	samplesScanner := failureSamplesArg(&scan.FailureSamples)
	err := s.pool.QueryRow(ctx, `
		SELECT id, source, status::text, cidrs, hostnames, ports, concurrency,
			started_at, finished_at, targets_total, targets_scanned, targets_succeeded, targets_failed,
			certs_found, upsert_failures, expansion_warnings, failure_samples, error, created_at
		FROM scans WHERE id = $1
	`, id).Scan(
		&scan.ID, &scan.Source, &scan.Status, &scan.CIDRs, &scan.Hostnames, &scan.Ports, &scan.Concurrency,
		&scan.StartedAt, &scan.FinishedAt, &scan.TargetsTotal, &scan.TargetsScanned,
		&scan.TargetsSucceeded, &scan.TargetsFailed, &scan.CertsFound, &scan.UpsertFailures,
		&scan.ExpansionWarnings, &samplesScanner, &scan.Error, &scan.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return scan, ErrScanNotFound
	}
	return scan, err
}

func (s *Store) ListScans(ctx context.Context, limit, offset int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, source, status::text, cidrs, hostnames, ports, concurrency,
			started_at, finished_at, targets_total, targets_scanned, targets_succeeded, targets_failed,
			certs_found, upsert_failures, expansion_warnings, failure_samples, error, created_at
		FROM scans ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var scan Scan
		samplesScanner := failureSamplesArg(&scan.FailureSamples)
		if err := rows.Scan(
			&scan.ID, &scan.Source, &scan.Status, &scan.CIDRs, &scan.Hostnames, &scan.Ports, &scan.Concurrency,
			&scan.StartedAt, &scan.FinishedAt, &scan.TargetsTotal, &scan.TargetsScanned,
			&scan.TargetsSucceeded, &scan.TargetsFailed, &scan.CertsFound, &scan.UpsertFailures,
			&scan.ExpansionWarnings, &samplesScanner, &scan.Error, &scan.CreatedAt,
		); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	if scans == nil {
		scans = []Scan{}
	}
	return scans, rows.Err()
}

func (s *Store) UpsertCertificate(ctx context.Context, scanID uuid.UUID, parsed cert.ParsedCertificate, obs cert.Observation) (uuid.UUID, error) {
	status, days := lifecycle.Compute(parsed.NotAfter, s.expiringSoonDays, false)
	sansJSON, err := json.Marshal(parsed.SubjectAltNames)
	if err != nil {
		return uuid.Nil, err
	}

	hostname := obs.Hostname
	if hostname == "" {
		hostname = obs.SNI
	}
	certScope := governance.ClassifyScope(string(parsed.ChainStatus), parsed.IssuerDN, hostname, "")

	var certID uuid.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO certificates (
			serial_number, fingerprint_sha256, subject_cn, subject_alt_names, issuer_dn,
			authority_key_id, not_before, not_after, key_type, key_bits, signature_algorithm,
			is_ca, key_usage, ext_key_usage, pem, days_until_expiry, status,
			crl_distribution_points, ocsp_servers, hostname_matches_san, chain_status,
			cert_scope, first_discovered, last_seen
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, $23
		)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			days_until_expiry = EXCLUDED.days_until_expiry,
			status = EXCLUDED.status,
			cert_scope = EXCLUDED.cert_scope,
			updated_at = NOW()
		RETURNING id
	`,
		parsed.SerialNumber, parsed.FingerprintSHA256, nullStr(parsed.SubjectCN), sansJSON,
		parsed.IssuerDN, nullStr(parsed.AuthorityKeyID), parsed.NotBefore, parsed.NotAfter,
		parsed.KeyType, parsed.KeyBits, parsed.SignatureAlgorithm, parsed.IsCA,
		stringSliceForPG(parsed.KeyUsage), stringSliceForPG(parsed.ExtKeyUsage), parsed.PEM, days, string(status),
		stringSliceForPG(parsed.CRLDistributionPoints), stringSliceForPG(parsed.OCSPServers), parsed.HostnameMatchesSAN,
		string(parsed.ChainStatus), certScope, obs.ObservedAt,
	).Scan(&certID)
	if err != nil {
		return uuid.Nil, err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO certificate_observations (certificate_id, scan_id, ip, port, hostname, sni, tls_version, cipher_suite, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (certificate_id, scan_id, ip, port, sni) DO UPDATE SET observed_at = EXCLUDED.observed_at
	`, certID, scanID, obs.IP, obs.Port, nullStr(obs.Hostname), nullStr(obs.SNI),
		nullStr(obs.TLSVersion), nullStr(obs.CipherSuite), obs.ObservedAt)

	return certID, err
}

func (s *Store) UpsertIssuer(ctx context.Context, parsed cert.ParsedCertificate, caChain []string) error {
	status, days := lifecycle.Compute(parsed.NotAfter, s.expiringSoonDays, false)
	sansJSON, _ := json.Marshal(parsed.SubjectAltNames)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO issuers (
			fingerprint_sha256, serial_number, subject_cn, subject_alt_names, issuer_dn,
			authority_key_id, not_before, not_after, key_type, key_bits, signature_algorithm,
			is_ca, key_usage, ext_key_usage, pem, days_until_expiry, status, ca_chain
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			days_until_expiry = EXCLUDED.days_until_expiry,
			status = EXCLUDED.status,
			ca_chain = EXCLUDED.ca_chain,
			updated_at = NOW()
	`, parsed.FingerprintSHA256, parsed.SerialNumber, nullStr(parsed.SubjectCN), sansJSON,
		parsed.IssuerDN, nullStr(parsed.AuthorityKeyID), parsed.NotBefore, parsed.NotAfter,
		parsed.KeyType, parsed.KeyBits, parsed.SignatureAlgorithm, parsed.IsCA,
		stringSliceForPG(parsed.KeyUsage), stringSliceForPG(parsed.ExtKeyUsage), parsed.PEM, days, string(status),
		stringSliceForPG(caChain))
	return err
}

func (s *Store) ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}

	where := "WHERE 1=1"
	args := []any{}
	argN := 1

	if f.Status != "" {
		where += fmt.Sprintf(" AND c.status = $%d", argN)
		args = append(args, f.Status)
		argN++
	}
	if f.ChainStatus != "" {
		where += fmt.Sprintf(" AND c.chain_status = $%d", argN)
		args = append(args, f.ChainStatus)
		argN++
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND (c.subject_cn ILIKE $%d OR c.fingerprint_sha256 ILIKE $%d OR c.subject_alt_names::text ILIKE $%d)", argN, argN, argN)
		args = append(args, "%"+f.Search+"%")
		argN++
	}
	if f.ScanID != uuid.Nil {
		where += fmt.Sprintf(" AND EXISTS (SELECT 1 FROM certificate_observations o WHERE o.certificate_id = c.id AND o.scan_id = $%d)", argN)
		args = append(args, f.ScanID)
		argN++
	}

	countQuery := "SELECT COUNT(*) FROM certificates c " + where
	var total int
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT c.id, c.serial_number, c.fingerprint_sha256, c.subject_cn, c.subject_alt_names,
			c.issuer_dn, c.authority_key_id, c.not_before, c.not_after, c.key_type, c.key_bits,
			c.signature_algorithm, c.is_ca, c.key_usage, c.ext_key_usage, c.pem,
			c.days_until_expiry, c.status::text, c.revocation_status, c.revocation_checked_at,
			c.crl_distribution_points, c.ocsp_servers, c.first_discovered, c.last_seen,
			c.hostname_matches_san, c.chain_status::text, c.managed_status::text, c.cert_scope::text,
			c.vault_issuer_ref, c.vault_pki_mount, c.owner, c.team, c.environment, c.tags,
			c.risk_score, c.remediation_state::text, c.created_at, c.updated_at,
			(SELECT COUNT(*) FROM certificate_observations o WHERE o.certificate_id = c.id) AS obs_count
		FROM certificates c %s ORDER BY c.last_seen DESC LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		certs = append(certs, c)
	}
	if certs == nil {
		certs = []Certificate{}
	}
	return certs, total, rows.Err()
}

func (s *Store) GetCertificate(ctx context.Context, id uuid.UUID) (Certificate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT c.id, c.serial_number, c.fingerprint_sha256, c.subject_cn, c.subject_alt_names,
			c.issuer_dn, c.authority_key_id, c.not_before, c.not_after, c.key_type, c.key_bits,
			c.signature_algorithm, c.is_ca, c.key_usage, c.ext_key_usage, c.pem,
			c.days_until_expiry, c.status::text, c.revocation_status, c.revocation_checked_at,
			c.crl_distribution_points, c.ocsp_servers, c.first_discovered, c.last_seen,
			c.hostname_matches_san, c.chain_status::text, c.managed_status::text, c.cert_scope::text,
			c.vault_issuer_ref, c.vault_pki_mount, c.owner, c.team, c.environment, c.tags,
			c.risk_score, c.remediation_state::text, c.created_at, c.updated_at,
			(SELECT COUNT(*) FROM certificate_observations o WHERE o.certificate_id = c.id)
		FROM certificates c WHERE c.id = $1
	`, id)
	cert, err := scanCertificate(row.Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrCertificateNotFound
	}
	return cert, err
}

func (s *Store) GetCertificateObservations(ctx context.Context, certID uuid.UUID) ([]Observation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, certificate_id, scan_id, ip, port, hostname, sni, tls_version, cipher_suite, observed_at
		FROM certificate_observations WHERE certificate_id = $1 ORDER BY observed_at DESC
	`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var obs []Observation
	for rows.Next() {
		var o Observation
		if err := rows.Scan(&o.ID, &o.CertificateID, &o.ScanID, &o.IP, &o.Port,
			&o.Hostname, &o.SNI, &o.TLSVersion, &o.CipherSuite, &o.ObservedAt); err != nil {
			return nil, err
		}
		obs = append(obs, o)
	}
	if obs == nil {
		obs = []Observation{}
	}
	return obs, rows.Err()
}

func (s *Store) UpdateCertificateEnrichment(ctx context.Context, id uuid.UUID, u EnrichmentUpdate) (Certificate, error) {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates SET
			owner = COALESCE($2, owner),
			team = COALESCE($3, team),
			environment = COALESCE($4, environment),
			tags = CASE WHEN $5::text[] IS NOT NULL THEN $5 ELSE tags END,
			updated_at = NOW()
		WHERE id = $1
	`, id, u.Owner, u.Team, u.Environment, u.Tags)
	if err != nil {
		return Certificate{}, err
	}
	return s.GetCertificate(ctx, id)
}

func (s *Store) ListIssuers(ctx context.Context, limit, offset int) ([]Issuer, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, fingerprint_sha256, serial_number, subject_cn, issuer_dn,
			not_before, not_after, key_type, key_bits, is_ca, pem, days_until_expiry,
			status::text, issuer_name, issuer_id, ca_chain
		FROM issuers ORDER BY not_after ASC LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var issuers []Issuer
	for rows.Next() {
		var i Issuer
		if err := rows.Scan(&i.ID, &i.FingerprintSHA256, &i.SerialNumber, &i.SubjectCN,
			&i.IssuerDN, &i.NotBefore, &i.NotAfter, &i.KeyType, &i.KeyBits, &i.IsCA,
			&i.PEM, &i.DaysUntilExpiry, &i.Status, &i.IssuerName, &i.IssuerID, &i.CAChain); err != nil {
			return nil, err
		}
		issuers = append(issuers, i)
	}
	if issuers == nil {
		issuers = []Issuer{}
	}
	return issuers, rows.Err()
}

func (s *Store) DeleteScan(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrScanNotFound
	}
	return nil
}

func (s *Store) DeleteCertificate(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCertificateNotFound
	}
	return nil
}

func (s *Store) DeleteIssuer(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM issuers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrIssuerNotFound
	}
	return nil
}

func stringSliceForPG(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCertificate(scan func(dest ...any) error) (Certificate, error) {
	var c Certificate
	var sansJSON []byte
	err := scan(
		&c.ID, &c.SerialNumber, &c.FingerprintSHA256, &c.SubjectCN, &sansJSON,
		&c.IssuerDN, &c.AuthorityKeyID, &c.NotBefore, &c.NotAfter, &c.KeyType, &c.KeyBits,
		&c.SignatureAlgorithm, &c.IsCA, &c.KeyUsage, &c.ExtKeyUsage, &c.PEM,
		&c.DaysUntilExpiry, &c.Status, &c.RevocationStatus, &c.RevocationCheckedAt,
		&c.CRLDistributionPoints, &c.OCSPServers, &c.FirstDiscovered, &c.LastSeen,
		&c.HostnameMatchesSAN, &c.ChainStatus, &c.ManagedStatus, &c.CertScope,
		&c.VaultIssuerRef, &c.VaultPKIMount, &c.Owner, &c.Team, &c.Environment, &c.Tags,
		&c.RiskScore, &c.RemediationState, &c.CreatedAt, &c.UpdatedAt, &c.ObservationCount,
	)
	if err != nil {
		return Certificate{}, err
	}
	_ = json.Unmarshal(sansJSON, &c.SubjectAltNames)
	return c, nil
}
