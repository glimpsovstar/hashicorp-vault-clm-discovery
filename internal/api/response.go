package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	body := map[string]string{"error": msg}
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		body["request_id"] = reqID
	}
	writeJSON(w, status, body)
}

func (s *Server) writeServerError(w http.ResponseWriter, r *http.Request, err error, msg string) {
	requestLogger(r).Error(msg,
		"err", err,
		"route", r.URL.Path,
		"method", r.Method,
	)
	writeError(w, r, http.StatusInternalServerError, msg)
}
