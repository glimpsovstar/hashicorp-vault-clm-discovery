package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type contextKey string

const loggerContextKey contextKey = "api_logger"

// RequestLogger attaches a request-scoped slog logger with request_id to the context.
func RequestLogger(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := middleware.GetReqID(r.Context())
			reqLog := base.With("request_id", reqID)
			ctx := context.WithValue(r.Context(), loggerContextKey, reqLog)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requestLogger(r *http.Request) *slog.Logger {
	if log, ok := r.Context().Value(loggerContextKey).(*slog.Logger); ok && log != nil {
		return log
	}
	return slog.Default()
}

func requestID(r *http.Request) string {
	return middleware.GetReqID(r.Context())
}
