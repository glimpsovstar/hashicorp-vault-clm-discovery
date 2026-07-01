package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
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

// parseScanID parses the "id" URL parameter as a scan UUID. On failure it writes
// a 400 response and returns ok=false so the caller can simply return.
func parseScanID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid scan id")
		return uuid.Nil, false
	}
	return id, true
}

// writeLookupError maps a store lookup error to a response: the typed
// not-found sentinel becomes a 404 with notFoundMsg; any other error (e.g. a
// database/IO failure) becomes a logged 500, so outages are never masked as 404.
func (s *Server) writeLookupError(w http.ResponseWriter, r *http.Request, err error, notFound error, notFoundMsg, serverMsg string) {
	if errors.Is(err, notFound) {
		writeError(w, r, http.StatusNotFound, notFoundMsg)
		return
	}
	s.writeServerError(w, r, err, serverMsg)
}

func (s *Server) writeServerError(w http.ResponseWriter, r *http.Request, err error, msg string) {
	requestLogger(r).Error(msg,
		"err", err,
		"route", r.URL.Path,
		"method", r.Method,
	)
	writeError(w, r, http.StatusInternalServerError, msg)
}
