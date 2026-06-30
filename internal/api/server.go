package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanrunner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

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
}

func NewServer(cfg config.Config, st *store.Store, sc *scanner.Scanner, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: st, scanner: sc, log: log, blindSpot: st, compliance: st, report: st}
	if cfg.VaultAddr != "" {
		if vc, err := vault.NewClient(vault.Config{
			Address:    cfg.VaultAddr,
			Namespace:  cfg.VaultNamespace,
			Token:      cfg.VaultToken,
			AuthMethod: cfg.VaultAuthMethod,
		}); err == nil {
			s.reconciler = vault.NewReconciler(vc, st)
		} else {
			log.Warn("vault client init failed", "err", err)
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
		r.Patch("/certificates/{id}", s.handlePatchCertificate)
		r.Delete("/certificates/{id}", s.handleDeleteCertificate)

		r.Get("/issuers", s.handleListIssuers)
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
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
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
	if _, err := s.store.GetScan(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
		return
	}
	limit, offset := pagination(r)
	certs, total, err := s.store.ListCertificates(r.Context(), store.CertificateFilter{
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
	if err := s.store.DeleteScan(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "scan not found")
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
	if err := s.store.DeleteCertificate(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "certificate not found")
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
	if err := s.store.DeleteIssuer(r.Context(), id); err != nil {
		writeError(w, r, http.StatusNotFound, "issuer not found")
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
	cert, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "certificate not found")
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
	cert, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "certificate not found")
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

func (s *Server) handleListIssuers(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	issuers, err := s.store.ListIssuers(r.Context(), limit, offset)
	if err != nil {
		s.writeServerError(w, r, err, "failed to list issuers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": issuers, "limit": limit, "offset": offset})
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
