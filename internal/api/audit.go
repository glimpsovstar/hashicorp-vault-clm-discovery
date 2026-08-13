package api

import (
	"context"
	"net/http"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// AuditEvent is the control-plane audit record persisted by the store adapter.
type AuditEvent struct {
	ActorID    string
	ActorType  string
	Role       string
	Action     string
	TargetType string
	TargetID   string
	Decision   string
	RequestID  string
	RemoteIP   string
	Payload    map[string]any
}

type auditor interface {
	AppendAudit(ctx context.Context, ev AuditEvent) error
}

// storeAuditor adapts store.AppendAudit to the API auditor interface so store
// does not import internal/api.
type storeAuditor struct {
	st *store.Store
}

func (a *storeAuditor) AppendAudit(ctx context.Context, ev AuditEvent) error {
	if a == nil || a.st == nil {
		return nil
	}
	return a.st.AppendAudit(ctx, store.AuditEvent{
		ActorID:    ev.ActorID,
		ActorType:  ev.ActorType,
		Role:       ev.Role,
		Action:     ev.Action,
		TargetType: ev.TargetType,
		TargetID:   ev.TargetID,
		Decision:   ev.Decision,
		RequestID:  ev.RequestID,
		RemoteIP:   ev.RemoteIP,
		Payload:    ev.Payload,
	})
}

func (s *Server) auditDeny(r *http.Request, role string) {
	s.appendAudit(r, role, "deny", r.Method+" "+r.URL.Path, "", "", nil)
}

func (s *Server) auditAllow(r *http.Request, action, targetType, targetID string, payload map[string]any) {
	s.appendAudit(r, s.requestActor(r), "allow", action, targetType, targetID, payload)
}

func (s *Server) appendAudit(r *http.Request, role, decision, action, targetType, targetID string, payload map[string]any) {
	if s.auditor == nil {
		return
	}
	ev := AuditEvent{
		Role:       role,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Decision:   decision,
		RequestID:  requestID(r),
		RemoteIP:   r.RemoteAddr,
		Payload:    payload,
	}
	if role != "" {
		ev.ActorID = "static:" + role
		ev.ActorType = "user"
	}
	_ = s.auditor.AppendAudit(r.Context(), ev)
}
