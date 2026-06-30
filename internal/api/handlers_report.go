package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/report"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type reportStore interface {
	report.ScanStore
}

func (s *Server) handleGetScanReport(w http.ResponseWriter, r *http.Request) {
	id, ok := parseScanID(w, r)
	if !ok {
		return
	}

	doc, err := report.BuildForScan(r.Context(), s.report, id)
	if err != nil {
		switch {
		case errors.Is(err, report.ErrScanNotCompleted):
			writeError(w, r, http.StatusNotFound, "scan not completed")
		case errors.Is(err, store.ErrScanNotFound):
			writeError(w, r, http.StatusNotFound, "scan not found")
		default:
			s.writeServerError(w, r, err, "failed to build report")
		}
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "markdown"
	}

	switch format {
	case "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.RenderMarkdown(doc)))
	case "json":
		raw, err := report.RenderJSON(doc)
		if err != nil {
			s.writeServerError(w, r, err, "failed to encode report")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	default:
		writeError(w, r, http.StatusBadRequest, "format must be markdown or json")
	}
}
