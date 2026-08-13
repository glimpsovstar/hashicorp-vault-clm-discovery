package api

import (
	"net/http"
	"strings"
)

const bearerPrefix = "Bearer "

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InsecureNoAuth {
			if role, ok := r.Context().Value(settingsActorKey{}).(string); !ok || role == "" {
				r = r.WithContext(ContextWithActor(r.Context(), rolePlatformAdmin))
			}
			next.ServeHTTP(w, r)
			return
		}
		role, ok := s.cfg.LookupStaticRole(bearerToken(r.Header.Get("Authorization")))
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithActor(r.Context(), role)))
	})
}

func bearerToken(header string) string {
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}
