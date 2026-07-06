package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/lifecycle"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/renewal"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/revocation"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanrunner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

// resourceStore is the scan/certificate/issuer lookup and delete surface used
// by the generic resource handlers. Injectable so those handlers can be tested
// (including the not-found vs. DB-error paths) without a database.
type resourceStore interface {
	GetScan(ctx context.Context, id uuid.UUID) (store.Scan, error)
	GetCertificate(ctx context.Context, id uuid.UUID) (store.Certificate, error)
	ListCertificates(ctx context.Context, f store.CertificateFilter) ([]store.Certificate, int, error)
	SetManagedStatus(ctx context.Context, id uuid.UUID, status string) (store.Certificate, error)
	GetIssuer(ctx context.Context, id uuid.UUID) (store.Issuer, error)
	SetIssuerVaultRef(ctx context.Context, id uuid.UUID, issuerRef, mount string) (store.Issuer, error)
	GetIssuerPEMForCert(ctx context.Context, issuerDN string) (string, error)
	MarkRevoked(ctx context.Context, id uuid.UUID, source string) error
	DeleteScan(ctx context.Context, id uuid.UUID) error
	DeleteCertificate(ctx context.Context, id uuid.UUID) error
	DeleteIssuer(ctx context.Context, id uuid.UUID) error
}

// issuerImporter writes CA material into a Vault PKI mount (mode B). It is nil
// when Vault is not configured, which the handler maps to 503.
type issuerImporter interface {
	ImportIssuerBundle(ctx context.Context, mount, pemBundle string) (vault.IssuerImportResult, error)
}

// revChecker performs a revocation check (OCSP first, then CRL); injectable so
// the handler is testable without outbound HTTP.
type revChecker func(ctx context.Context, in revocation.CheckInput) (revocation.Result, error)

// RenewRef identifies the AAP job launched for a renewal.
type RenewRef struct {
	JobID    int  `json:"job_id"`
	Workflow bool `json:"workflow"`
}

// renewLauncher launches a Vault+AAP renewal (Mode C). It resolves the
// configured template by name and launches it with the given extra_vars. nil
// when AAP is not configured, which the handler maps to 503. Injectable so the
// handler is testable without a live Controller.
type renewLauncher interface {
	Renew(ctx context.Context, extraVars map[string]any) (RenewRef, error)
}

// aapRenewer is the production renewLauncher backed by an AAP Controller client.
type aapRenewer struct {
	client       *aap.Client
	templateName string
	workflow     bool
}

func (a *aapRenewer) Renew(ctx context.Context, extraVars map[string]any) (RenewRef, error) {
	var (
		id  int
		err error
	)
	if a.workflow {
		id, err = a.client.FindWorkflowJobTemplate(ctx, a.templateName)
	} else {
		id, err = a.client.FindJobTemplate(ctx, a.templateName)
	}
	if err != nil {
		return RenewRef{}, err
	}
	var res aap.LaunchResult
	if a.workflow {
		res, err = a.client.LaunchWorkflowJobTemplate(ctx, id, extraVars)
	} else {
		res, err = a.client.LaunchJobTemplate(ctx, id, extraVars)
	}
	if err != nil {
		return RenewRef{}, err
	}
	return RenewRef{JobID: res.JobID, Workflow: res.Workflow}, nil
}

type Server struct {
	cfg        config.Config
	store      *store.Store
	scanner    *scanner.Scanner
	log        *slog.Logger
	worker     *ScanWorker
	reconciler reconcileRunner
	blindSpot  blindSpotStore
	compliance complianceStore
	report     reportStore
	resources  resourceStore
	importer   issuerImporter
	revCheck   revChecker
	renewer    renewLauncher
}

func NewServer(cfg config.Config, st *store.Store, sc *scanner.Scanner, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: st, scanner: sc, log: log, blindSpot: st, compliance: st, report: st, resources: st}
	s.revCheck = func(ctx context.Context, in revocation.CheckInput) (revocation.Result, error) {
		return revocation.Check(ctx, revocation.NewFetchClient(), in)
	}
	if cfg.VaultAddr != "" {
		if vc, err := vault.NewClient(vault.Config{
			Address:    cfg.VaultAddr,
			Namespace:  cfg.VaultNamespace,
			Token:      cfg.VaultToken,
			AuthMethod: cfg.VaultAuthMethod,
		}); err == nil {
			s.reconciler = vault.NewReconciler(vc, st)
			s.importer = vc
		} else {
			log.Warn("vault client init failed", "err", err)
		}
	}
	if cfg.AAPURL != "" {
		if ac, err := aap.NewClient(aap.Config{
			BaseURL:       cfg.AAPURL,
			Token:         cfg.AAPToken,
			SkipTLSVerify: cfg.AAPSkipTLSVerify,
		}); err == nil {
			s.renewer = &aapRenewer{client: ac, templateName: cfg.AAPRenewTemplate, workflow: cfg.AAPRenewWorkflow}
		} else {
			log.Warn("aap client init failed", "err", err)
		}
	}
	s.worker = NewScanWorker(s)
	return s
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(RequestLogger(s.log))
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	r.Get("/api/v1/health", s.handleHealth)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans", s.handleCreateScan)
		r.Get("/scans", s.handleListScans)
		r.Get("/scans/{id}", s.handleGetScan)
		r.Get("/scans/{id}/blindspot", s.handleGetScanBlindSpot)
		r.Get("/scans/{id}/compliance", s.handleGetScanCompliance)
		r.Get("/scans/{id}/report", s.handleGetScanReport)
		r.Get("/scans/{id}/certificates", s.handleListScanCertificates)
		r.Delete("/scans/{id}", s.handleDeleteScan)

		r.Get("/certificates", s.handleListCertificates)
		r.Get("/certificates/{id}", s.handleGetCertificate)
		r.Get("/certificates/{id}/pem", s.handleGetCertificatePEM)
		r.Get("/certificates/{id}/choose", s.handleGetCertificateChoose)
		r.Get("/certificates/{id}/renewal-kit", s.handleRenewalKit)
		r.Post("/certificates/{id}/revocation-check", s.handleRevocationCheck)
		r.Post("/certificates/{id}/renew", s.handleRenewCertificate)
		r.Patch("/certificates/{id}", s.handlePatchCertificate)
		r.Post("/certificates/{id}/catalog-import", s.handleCatalogImport)
		r.Delete("/certificates/{id}", s.handleDeleteCertificate)

		r.Get("/issuers", s.handleListIssuers)
		r.Post("/issuers/{id}/import", s.handleImportIssuer)
		r.Delete("/issuers/{id}", s.handleDeleteIssuer)

		r.Post("/reconcile", s.handleReconcile)

		r.Get("/blindspot", s.handleGetBlindSpot)
		r.Get("/compliance/summary", s.handleGetComplianceSummary)
	})

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		requestLogger(r).Error("database unavailable", "err", err, "route", r.URL.Path)
		writeError(w, r, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createScanRequest struct {
	CIDRs       []string `json:"cidrs"`
	Hostnames   []string `json:"hostnames"`
	Ports       []int    `json:"ports"`
	Concurrency int      `json:"concurrency"`
	Consent     bool     `json:"consent"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "scan consent required; set consent=true to confirm authorized scanning")
		return
	}
	if len(req.CIDRs) == 0 && len(req.Hostnames) == 0 {
		writeError(w, r, http.StatusBadRequest, "cidrs or hostnames required")
		return
	}
	if len(req.Ports) == 0 {
		req.Ports = []int{443, 8443, 6443, 993, 465}
	}
	if req.Concurrency <= 0 {
		req.Concurrency = s.cfg.DefaultConcurrency
	}

	scan, err := s.store.CreateScan(r.Context(), req.CIDRs, req.Hostnames, req.Ports, req.Concurrency)
	if err != nil {
		s.writeServerError(w, r, err, "failed to create scan")
		return
	}

	s.worker.Enqueue(scan.ID, req.CIDRs, req.Hostnames, req.Ports, req.Concurrency)
	writeJSON(w, http.StatusAccepted, scan)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	scans, err := s.store.ListScans(r.Context(), limit, offset)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list scans")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": scans, "limit": limit, "offset": offset})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	scan, err := s.resources.GetScan(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, r, err, store.ErrScanNotFound, "scan not found", "failed to load scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (s *Server) handleListScanCertificates(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	if _, err := s.resources.GetScan(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrScanNotFound, "scan not found", "failed to load scan")
		return
	}
	limit, offset := pagination(r)
	certs, total, err := s.resources.ListCertificates(r.Context(), store.CertificateFilter{
		ScanID: id,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		s.writeServerError(w, r, err, "failed to list scan certificates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": certs, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}
	if err := s.resources.DeleteScan(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrScanNotFound, "scan not found", "failed to delete scan")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	if err := s.resources.DeleteCertificate(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrCertificateNotFound, "certificate not found", "failed to delete certificate")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteIssuer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid issuer id")
		return
	}
	if err := s.resources.DeleteIssuer(r.Context(), id); err != nil {
		s.writeLookupError(w, r, err, store.ErrIssuerNotFound, "issuer not found", "failed to delete issuer")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	filter := store.CertificateFilter{
		Status:      r.URL.Query().Get("status"),
		ChainStatus: r.URL.Query().Get("chain_status"),
		Search:      r.URL.Query().Get("search"),
		Limit:       limit,
		Offset:      offset,
	}
	if scanID := r.URL.Query().Get("scan_id"); scanID != "" {
		id, err := uuid.Parse(scanID)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid scan_id")
			return
		}
		filter.ScanID = id
	}
	certs, total, err := s.store.ListCertificates(r.Context(), filter)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list certificates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": certs, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, r, err, store.ErrCertificateNotFound, "certificate not found", "failed to load certificate")
		return
	}
	obs, err := s.store.GetCertificateObservations(r.Context(), id)
	if err != nil {
		s.writeServerError(w, r, err, "failed to get observations")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": cert, "observations": obs})
}

func (s *Server) handleGetCertificatePEM(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, r, err, store.ErrCertificateNotFound, "certificate not found", "failed to load certificate")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=certificate.pem")
	_, _ = w.Write([]byte(cert.PEM))
}

type patchCertificateRequest struct {
	Owner       *string  `json:"owner"`
	Team        *string  `json:"team"`
	Environment *string  `json:"environment"`
	Tags        []string `json:"tags"`
}

func (s *Server) handlePatchCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	var req patchCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	cert, err := s.store.UpdateCertificateEnrichment(r.Context(), id, store.EnrichmentUpdate{
		Owner: req.Owner, Team: req.Team, Environment: req.Environment, Tags: req.Tags,
	})
	if err != nil {
		s.writeServerError(w, r, err, "failed to update certificate")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

// handleGetCertificateChoose returns the recommended Choose-phase action for a
// certificate based on its discovered signals (read-only).
func (s *Server) handleGetCertificateChoose(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrCertificateNotFound) {
			writeError(w, r, http.StatusNotFound, "certificate not found")
			return
		}
		s.writeServerError(w, r, err, "failed to load certificate")
		return
	}
	rec := lifecycle.ChooseRecommendation(lifecycle.ChooseInput{
		CertScope:     cert.CertScope,
		ManagedStatus: cert.ManagedStatus,
		ChainStatus:   cert.ChainStatus,
		IsCA:          cert.IsCA,
	})
	writeJSON(w, http.StatusOK, rec)
}

// handleRenewalKit generates Mode C reissue+deploy artifacts (vault-agent HCL or
// an AAP playbook) for a certificate and a chosen Vault PKI role. Read-only:
// CLM generates the artifacts; the operator runs them, and CLM later verifies via
// rescan + reconcile.
func (s *Server) handleRenewalKit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrCertificateNotFound) {
			writeError(w, r, http.StatusNotFound, "certificate not found")
			return
		}
		s.writeServerError(w, r, err, "failed to load certificate")
		return
	}

	target := renewal.Target(strings.ToLower(r.URL.Query().Get("target")))
	if target == "" {
		target = renewal.TargetAgent
	}
	mount := strings.TrimSpace(r.URL.Query().Get("mount"))
	if mount == "" {
		mount = "pki"
	}
	cn := ""
	if cert.SubjectCN != nil {
		cn = *cert.SubjectCN
	}

	arts, err := renewal.Generate(target, renewal.KitInput{
		CommonName: cn,
		Mount:      mount,
		Role:       strings.TrimSpace(r.URL.Query().Get("role")),
		Service:    strings.TrimSpace(r.URL.Query().Get("service")),
	})
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "artifacts": arts})
}

// handleRenewCertificate launches a Vault+AAP renewal for a certificate (Mode C
// full automation). CLM resolves the configured AAP template by name and
// launches it with extra_vars derived from the cert (CN) and the requested Vault
// PKI coordinates; AAP issues from Vault and deploys. Consent-gated. Returns 503
// when AAP is not configured. CLM confirms the outcome via a later rescan +
// reconcile (closed loop, PR 3).
func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	if s.renewer == nil {
		writeError(w, r, http.StatusServiceUnavailable, "AAP not configured")
		return
	}

	var body struct {
		Consent     bool   `json:"consent"`
		Mount       string `json:"mount"`
		Role        string `json:"role"`
		Service     string `json:"service"`
		TargetHosts string `json:"target_hosts"`
		TTL         string `json:"ttl"`
		AltNames    string `json:"alt_names"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !body.Consent {
		writeError(w, r, http.StatusBadRequest, "consent required to launch a renewal")
		return
	}

	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrCertificateNotFound) {
			writeError(w, r, http.StatusNotFound, "certificate not found")
			return
		}
		s.writeServerError(w, r, err, "failed to load certificate")
		return
	}

	cn := ""
	if cert.SubjectCN != nil {
		cn = *cert.SubjectCN
	}
	mount := strings.TrimSpace(body.Mount)
	if mount == "" {
		mount = s.cfg.AAPDefaultMount
	}

	// Validate every value that flows to AAP with the same checks the renewal-kit
	// generator uses (the CN comes from the scanned cert and is attacker-shaped).
	kit := renewal.KitInput{CommonName: cn, Mount: mount, Role: strings.TrimSpace(body.Role), Service: strings.TrimSpace(body.Service)}
	if err := renewal.Validate(kit); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if !renewal.ValidService(strings.TrimSpace(body.Service)) {
		writeError(w, r, http.StatusBadRequest, "invalid service")
		return
	}
	if !renewal.ValidService(strings.TrimSpace(body.TargetHosts)) {
		writeError(w, r, http.StatusBadRequest, "invalid target_hosts")
		return
	}

	// extra_vars maps onto the vault-ansible-clm issue role's contract. Vault
	// AppRole creds are injected by an AAP credential, never passed by CLM.
	extraVars := map[string]any{
		"cert_common_name_override": cn,
		"vault_pki_mount":           mount,
		"vault_pki_role":            kit.Role,
	}
	if kit.Service != "" {
		extraVars["cert_service_type"] = kit.Service
	}
	if th := strings.TrimSpace(body.TargetHosts); th != "" {
		extraVars["target_hosts"] = th
	}
	if ttl := strings.TrimSpace(body.TTL); ttl != "" {
		extraVars["vault_cert_ttl"] = ttl
	}
	if an := strings.TrimSpace(body.AltNames); an != "" {
		extraVars["cert_alt_names_override"] = an
	}

	ref, err := s.renewer.Renew(r.Context(), extraVars)
	if err != nil {
		s.log.Warn("aap renewal launch failed", "action", "renew", "certificate_id", id.String(), "err", err)
		writeError(w, r, http.StatusBadGateway, "failed to launch AAP renewal")
		return
	}
	s.log.Info("aap renewal launched", "action", "renew", "certificate_id", id.String(), "job_id", ref.JobID, "workflow", ref.Workflow)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":      "launched",
		"job":         ref,
		"common_name": cn,
		"mount":       mount,
		"role":        kit.Role,
	})
}

// handleRevocationCheck runs a CRL revocation check for a discovered cert. It
// persists status=revoked ONLY when the CRL signature is verified against a
// known issuer; an unverified result is advisory and does not mutate state.
func (s *Server) handleRevocationCheck(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.resources.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrCertificateNotFound) {
			writeError(w, r, http.StatusNotFound, "certificate not found")
			return
		}
		s.writeServerError(w, r, err, "failed to load certificate")
		return
	}

	// Best-effort issuer lookup to enable CRL signature verification.
	issuerPEM, err := s.resources.GetIssuerPEMForCert(r.Context(), cert.IssuerDN)
	if err != nil {
		s.writeServerError(w, r, err, "failed to look up issuer")
		return
	}

	result, err := s.revCheck(r.Context(), revocation.CheckInput{
		SerialHex:   cert.SerialNumber,
		LeafPEM:     cert.PEM,
		IssuerPEM:   issuerPEM,
		OCSPServers: cert.OCSPServers,
		CRLURLs:     cert.CRLDistributionPoints,
	})
	if err != nil {
		s.log.Warn("revocation check failed", "action", "revocation_check", "certificate_id", id.String(), "err", err)
		writeError(w, r, http.StatusBadGateway, "revocation check failed")
		return
	}

	if result.Status == revocation.StatusRevoked && result.Verified {
		if err := s.resources.MarkRevoked(r.Context(), id, result.Source); err != nil {
			s.writeServerError(w, r, err, "failed to record revocation")
			return
		}
		s.log.Info("certificate revoked", "action", "revocation_check", "certificate_id", id.String(), "source", result.Source)
	}
	writeJSON(w, http.StatusOK, result)
}

type catalogImportRequest struct {
	Consent bool `json:"consent"`
}

// handleCatalogImport implements mode A (catalog): track a discovered cert in
// CLM as managed_status=imported. It never calls Vault and requires explicit
// consent, mirroring the scan consent policy.
func (s *Server) handleCatalogImport(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid certificate id")
		return
	}
	var req catalogImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "consent is required to catalog a certificate")
		return
	}
	cert, err := s.resources.SetManagedStatus(r.Context(), id, "imported")
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCertificateNotFound):
			writeError(w, r, http.StatusNotFound, "certificate not found")
		case errors.Is(err, store.ErrManagedByVault):
			writeError(w, r, http.StatusConflict, "certificate is managed in vault; catalog import does not apply")
		default:
			s.writeServerError(w, r, err, "failed to catalog certificate")
		}
		return
	}
	s.log.Info("catalog import", "action", "catalog_import", "certificate_id", id.String(), "managed_status", "imported")
	writeJSON(w, http.StatusOK, cert)
}

func (s *Server) handleListIssuers(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	issuers, err := s.store.ListIssuers(r.Context(), limit, offset)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list issuers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": issuers, "limit": limit, "offset": offset})
}

type importIssuerRequest struct {
	Consent bool   `json:"consent"`
	Mount   string `json:"mount"`
}

// handleImportIssuer implements mode B (CA import): write an issuer's CA bundle
// into a Vault PKI mount via pki/issuers/import/bundle. This is the only Vault
// WRITE path; it requires explicit consent, a CA issuer, and a configured Vault
// with a read-write PKI policy.
func (s *Server) handleImportIssuer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid issuer id")
		return
	}
	var req importIssuerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, r, http.StatusBadRequest, "consent is required to import a CA into Vault")
		return
	}
	mount := strings.TrimSpace(req.Mount)
	if mount == "" {
		writeError(w, r, http.StatusBadRequest, "mount is required")
		return
	}
	if !validMount(mount) {
		writeError(w, r, http.StatusBadRequest, "invalid mount: use a simple path segment (letters, digits, -, _, /)")
		return
	}
	if s.importer == nil {
		writeError(w, r, http.StatusServiceUnavailable, "vault is not configured")
		return
	}

	issuer, err := s.resources.GetIssuer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrIssuerNotFound) {
			writeError(w, r, http.StatusNotFound, "issuer not found")
			return
		}
		s.writeServerError(w, r, err, "failed to load issuer")
		return
	}
	if !issuer.IsCA {
		writeError(w, r, http.StatusConflict, "issuer is not a CA; only CA material can be imported into Vault PKI")
		return
	}

	result, err := s.importer.ImportIssuerBundle(r.Context(), mount, issuerBundle(issuer))
	if err != nil {
		// The write reached Vault but was rejected (e.g. 403 read-only token) or
		// Vault is unreachable; surface as a bad-gateway rather than a 500.
		s.log.Warn("vault issuer import failed", "action", "import_ca", "issuer_id", id.String(), "mount", mount, "err", err)
		writeError(w, r, http.StatusBadGateway, "vault import failed")
		return
	}

	updated, err := s.resources.SetIssuerVaultRef(r.Context(), id, firstIssuerRef(result), mount)
	if err != nil {
		s.writeServerError(w, r, err, "failed to record issuer import")
		return
	}
	s.log.Info("vault issuer import", "action", "import_ca", "issuer_id", id.String(), "mount", mount)
	writeJSON(w, http.StatusOK, updated)
}

// issuerBundle concatenates the issuer PEM with its chain for import/bundle.
func issuerBundle(i store.Issuer) string {
	parts := append([]string{i.PEM}, i.CAChain...)
	return strings.Join(parts, "\n")
}

// validMount guards the user-supplied Vault mount before it is interpolated into
// the request URL: reject leading slashes, dot-segments, and any character
// outside a simple mount path so a value like "../../sys" cannot alter the path.
func validMount(m string) bool {
	if m == "" || strings.HasPrefix(m, "/") || strings.Contains(m, "..") {
		return false
	}
	for _, c := range m {
		ok := c == '-' || c == '_' || c == '/' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// firstIssuerRef returns the Vault-side issuer reference to persist, preferring
// the first imported issuer id.
func firstIssuerRef(r vault.IssuerImportResult) string {
	if len(r.ImportedIssuers) > 0 {
		return r.ImportedIssuers[0]
	}
	return ""
}

func pagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

type scanJob struct {
	ID          uuid.UUID
	CIDRs       []string
	Hostnames   []string
	Ports       []int
	Concurrency int
}

type ScanWorker struct {
	srv  *Server
	jobs chan scanJob
	once sync.Once
}

func NewScanWorker(srv *Server) *ScanWorker {
	w := &ScanWorker{srv: srv, jobs: make(chan scanJob, 32)}
	w.once.Do(func() { go w.run() })
	return w
}

func (w *ScanWorker) Enqueue(id uuid.UUID, cidrs, hostnames []string, ports []int, concurrency int) {
	w.jobs <- scanJob{ID: id, CIDRs: cidrs, Hostnames: hostnames, Ports: ports, Concurrency: concurrency}
}

func (w *ScanWorker) run() {
	for job := range w.jobs {
		w.execute(job)
	}
}

func (w *ScanWorker) execute(job scanJob) {
	ctx := context.Background()
	runner := scanrunner.New(w.srv.store, w.srv.scanner, w.srv.log, w.srv.cfg.LogLevel, w.srv.cfg.AllowPrivateRanges)
	err := runner.Run(ctx, scanrunner.Job{
		ScanID:      job.ID,
		CIDRs:       job.CIDRs,
		Hostnames:   job.Hostnames,
		Ports:       job.Ports,
		Concurrency: job.Concurrency,
	})
	if err == nil {
		w.srv.maybeReconcileAfterScan(ctx, job.ID)
	}
}
