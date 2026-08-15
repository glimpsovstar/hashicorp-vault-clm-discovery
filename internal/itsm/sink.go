// Package itsm delivers catalogue outbox events to an optional ITSM HTTP
// webhook as ticket-shaped JSON templates. No ServiceNow SDK; no NATS.
package itsm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

const maxBody = 1 << 16

// Config holds ITSM webhook settings. HMACSecret is never logged.
type Config struct {
	WebhookURL string
	HMACSecret string
}

// Sink POSTs templated catalogue events to an ITSM webhook.
type Sink struct {
	cfg  Config
	http *http.Client
}

// New builds an ITSM sink. It is inert when WebhookURL is empty.
func New(cfg Config) *Sink {
	return &Sink{
		cfg: cfg,
		http: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Configured reports whether a webhook URL is set.
func (s *Sink) Configured() bool {
	return s != nil && s.cfg.WebhookURL != ""
}

// Deliver renders a catalogue template and POSTs it. Optional HMAC is sent as
// X-CLM-Signature: sha256=<hex>.
func (s *Sink) Deliver(ctx context.Context, e store.Event) error {
	if !s.Configured() {
		return fmt.Errorf("itsm webhook is not configured")
	}
	body, err := Render(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build itsm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.HMACSecret))
		mac.Write(body)
		req.Header.Set("X-CLM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("post itsm: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("itsm webhook status %d", resp.StatusCode)
	}
	return nil
}

// Render maps a catalogue event onto a ticket-shaped JSON payload. Summary
// text is deterministic from event_type; severity is never LLM-chosen.
func Render(e store.Event) ([]byte, error) {
	ticket := map[string]any{
		"source":     "clm",
		"event_id":   e.ID.String(),
		"event_type": e.EventType,
		"created_at": e.CreatedAt.UTC().Format(time.RFC3339),
		"summary":    summaryFor(e.EventType),
		"payload":    json.RawMessage(e.Payload),
	}
	return json.Marshal(ticket)
}

func summaryFor(eventType string) string {
	switch eventType {
	case "cert.discovered":
		return "CLM: new certificate discovered"
	case "cert.expiring":
		return "CLM: certificate expiring soon"
	case "cert.revoked":
		return "CLM: certificate revoked"
	case "blind_spot.detected":
		return "CLM: blind spot detected"
	case "renewal.requested", "renewal.launched", "renewal.verified", "renewal.failed", "renewal.timed_out":
		return "CLM: renewal lifecycle — " + eventType
	default:
		return "CLM catalogue event: " + eventType
	}
}
