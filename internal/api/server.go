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
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type Server struct {
	cfg     config.Config
	store   *store.Store
	scanner *scanner.Scanner
	log     *slog.Logger
	worker  *ScanWorker
}

func NewServer(cfg config.Config, st *store.Store, sc *scanner.Scanner, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: st, scanner: sc, log: log}
	s.worker = NewScanWorker(s)
	return s
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	r.Get("/api/v1/health", s.handleHealth)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans", s.handleCreateScan)
		r.Get("/scans", s.handleListScans)
		r.Get("/scans/{id}", s.handleGetScan)

		r.Get("/certificates", s.handleListCertificates)
		r.Get("/certificates/{id}", s.handleGetCertificate)
		r.Get("/certificates/{id}/pem", s.handleGetCertificatePEM)
		r.Patch("/certificates/{id}", s.handlePatchCertificate)

		r.Get("/issuers", s.handleListIssuers)
	})

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Consent {
		writeError(w, http.StatusBadRequest, "scan consent required; set consent=true to confirm authorized scanning")
		return
	}
	if len(req.CIDRs) == 0 && len(req.Hostnames) == 0 {
		writeError(w, http.StatusBadRequest, "cidrs or hostnames required")
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
		s.log.Error("create scan", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	s.worker.Enqueue(scan.ID, req.CIDRs, req.Hostnames, req.Ports, req.Concurrency)
	writeJSON(w, http.StatusAccepted, scan)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	scans, err := s.store.ListScans(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list scans")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": scans, "limit": limit, "offset": offset})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, scan)
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
	certs, total, err := s.store.ListCertificates(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list certificates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": certs, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	obs, err := s.store.GetCertificateObservations(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get observations")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": cert, "observations": obs})
}

func (s *Server) handleGetCertificatePEM(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	cert, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "certificate not found")
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
		writeError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	var req patchCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cert, err := s.store.UpdateCertificateEnrichment(r.Context(), id, store.EnrichmentUpdate{
		Owner: req.Owner, Team: req.Team, Environment: req.Environment, Tags: req.Tags,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update certificate")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (s *Server) handleListIssuers(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	issuers, err := s.store.ListIssuers(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list issuers")
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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
	targets, err := scanner.ExpandScanTargets(job.CIDRs, job.Hostnames, job.Ports, w.srv.cfg.AllowPrivateRanges)
	if err != nil {
		_ = w.srv.store.FailScan(ctx, job.ID, err.Error())
		return
	}

	if err := w.srv.store.UpdateScanRunning(ctx, job.ID, len(targets)); err != nil {
		w.srv.log.Error("update scan running", "err", err)
		return
	}

	sem := make(chan struct{}, job.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	scanned := 0
	certsFound := 0

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t scanner.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			result := w.srv.scanner.Probe(ctx, t)
			mu.Lock()
			scanned++
			if result.Error == nil {
				certsFound++
			}
			curScanned, curCerts := scanned, certsFound
			mu.Unlock()

			if result.Error == nil {
				if _, err := w.srv.store.UpsertCertificate(ctx, job.ID, result.Certificate, result.Observation); err != nil {
					w.srv.log.Error("upsert certificate", "err", err)
				}
				for _, ca := range result.Chain {
					if ca.IsCA {
						chainPEMs := make([]string, len(result.Chain))
						for i, c := range result.Chain {
							chainPEMs[i] = c.PEM
						}
						_ = w.srv.store.UpsertIssuer(ctx, ca, chainPEMs)
					}
				}
			}

			if curScanned%10 == 0 || curScanned == len(targets) {
				_ = w.srv.store.UpdateScanProgress(ctx, job.ID, curScanned, curCerts)
			}
		}(target)
	}

	wg.Wait()
	_ = w.srv.store.CompleteScan(ctx, job.ID, scanned, certsFound)
}
