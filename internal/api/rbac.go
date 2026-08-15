package api

import (
	"net/http"
	"strings"
)

const (
	roleViewer           = "viewer"
	roleScannerOperator  = "scanner_operator"
	roleRemediator       = "remediator"
	roleVaultImportAdmin = "vault_import_admin"
	roleApprover         = "approver"
	rolePlatformAdmin    = "platform_admin"
	roleInventory        = "inventory"
)

func knownRBACRole(role string) bool {
	switch role {
	case roleViewer, roleScannerOperator, roleRemediator, roleVaultImportAdmin, roleApprover, rolePlatformAdmin, roleInventory:
		return true
	default:
		return false
	}
}

// roleAllows is the M1 permission matrix. Default-deny: unknown roles and
// unmatched routes are false. platform_admin is the only DELETE / Settings-write role.
func roleAllows(role, method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	switch role {
	case roleInventory:
		return isInventoryGET(method, path)
	case roleViewer:
		return isViewerRead(method, path)
	case roleApprover:
		return isViewerRead(method, path) || isWaiverWrite(method, path)
	case roleScannerOperator:
		return isViewerRead(method, path) || isCreateScan(method, path)
	case roleRemediator:
		return isViewerRead(method, path) || isCreateScan(method, path) || isRemediate(method, path) || isSettingsRead(method, path)
	case roleVaultImportAdmin:
		return isViewerRead(method, path) || isCreateScan(method, path) || isRemediate(method, path) || isVaultImport(method, path)
	case rolePlatformAdmin:
		return true
	default:
		return false
	}
}

func isInventoryGET(method, path string) bool {
	return method == http.MethodGet && path == "/api/v1/inventory"
}

func isViewerRead(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/settings/") {
		return false
	}
	for _, prefix := range []string{
		"/api/v1/inventory",
		"/api/v1/scans",
		"/api/v1/certificates",
		"/api/v1/issuers",
		"/api/v1/events",
		"/api/v1/lifecycle-jobs",
		"/api/v1/blindspot",
		"/api/v1/compliance",
		"/api/v1/waivers",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func isCreateScan(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return path == "/api/v1/scans" || path == "/api/v1/scans/collect"
}

func isRemediate(method, path string) bool {
	switch method {
	case http.MethodPost:
		if path == "/api/v1/renew-expiring" {
			return true
		}
		if strings.HasPrefix(path, "/api/v1/certificates/") {
			return strings.HasSuffix(path, "/catalog-import") ||
				strings.HasSuffix(path, "/renew") ||
				strings.HasSuffix(path, "/revoke") ||
				strings.HasSuffix(path, "/revocation-check") ||
				strings.HasSuffix(path, "/waivers")
		}
	case http.MethodPatch:
		rest := strings.TrimPrefix(path, "/api/v1/certificates/")
		return rest != path && rest != "" && !strings.Contains(rest, "/")
	case http.MethodDelete:
		return isWaiverWrite(method, path)
	}
	return false
}

func isWaiverWrite(method, path string) bool {
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/certificates/") && strings.HasSuffix(path, "/waivers") {
		return true
	}
	return method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/waivers/")
}

func isVaultImport(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	if path == "/api/v1/reconcile" {
		return true
	}
	return strings.HasPrefix(path, "/api/v1/issuers/") && strings.HasSuffix(path, "/import")
}

func isSettingsRead(method, path string) bool {
	return method == http.MethodGet && strings.HasPrefix(path, "/api/v1/settings/")
}

func (s *Server) requirePermission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := s.requestActor(r)
		if role == "" || !knownRBACRole(role) {
			s.auditDeny(r, role)
			writeError(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !roleAllows(role, r.Method, r.URL.Path) {
			s.auditDeny(r, role)
			writeError(w, r, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}
