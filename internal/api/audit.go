package api

import "context"

// AuditEvent is the control-plane audit record Task 3 persists.
// Task 2 records deny decisions via auditor; the store is not implemented here.
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
