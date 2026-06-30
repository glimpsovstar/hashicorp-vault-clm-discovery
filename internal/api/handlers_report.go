package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/report"
)

type reportStore interface {
	report.ScanStore
}

func (s *Server) handleGetScanReport(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return
	}

	doc, err := report.BuildForScan(r.Context(), s.report, id)
	if err != nil {
		if err.Error() == "scan not completed" {
			writeError(w, r, http.StatusNotFound, "scan not completed")
			return
		}
		writeError(w, r, http.StatusNotFound, "scan not found")
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
