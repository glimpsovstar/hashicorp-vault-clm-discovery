// Package eventbus delivers CLM outbox events to Ansible EDA via webhook
// (ADR 0001, event Phase 1). It is the reactive counterpart to the batch
// endpoints: a background dispatcher polls the outbox and POSTs each undelivered
// event to a configured EDA webhook, retrying with attempt tracking and
// dead-lettering after a cap. An optional ITSM sink receives the same events as
// ticket templates (M5). The whole thing is a no-op when neither webhook is
// configured. The transport is swappable — Phase 2 replaces the webhook sink
// with a message bus without touching the outbox or the domain logic.
//
// Delivery is at-least-once: an event may be re-sent if the process crashes or
// the delivered-mark write fails after a successful POST. Consumers (EDA
// rulebooks) MUST be idempotent and deduplicate on the stable event "id".
package eventbus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/itsm"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// eventStore is the outbox surface the dispatcher needs (satisfied by *store.Store).
type eventStore interface {
	ClaimUndeliveredEvents(ctx context.Context, owner string, leaseTTL time.Duration, limit, maxAttempts int) ([]store.Event, error)
	MarkEventDelivered(ctx context.Context, id uuid.UUID) error
	MarkEventFailed(ctx context.Context, id uuid.UUID, errMsg string) error
}

// Config holds dispatcher settings. Values come from the environment; the token
// and URL are never logged.
type Config struct {
	WebhookURL  string
	Token       string
	Interval    time.Duration
	BatchSize   int
	MaxAttempts int
	Owner       string
	LeaseTTL    time.Duration
	// Optional ITSM fan-out (templates over catalogue events).
	ITSMWebhookURL        string
	ITSMWebhookHMACSecret string
}

// Dispatcher polls the outbox and delivers events to the EDA webhook.
type Dispatcher struct {
	cfg   Config
	store eventStore
	http  *http.Client
	log   *slog.Logger
	itsm  *itsm.Sink
}

// New builds a dispatcher. It is inert until Run is called and does nothing when
// neither EDA nor ITSM is configured (Configured()==false).
func New(cfg Config, st eventStore, log *slog.Logger) *Dispatcher {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 10
	}
	if cfg.Owner == "" {
		cfg.Owner = "eda-dispatcher"
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 2 * time.Minute
	}
	d := &Dispatcher{
		cfg:   cfg,
		store: st,
		log:   log,
		http: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if cfg.ITSMWebhookURL != "" {
		d.itsm = itsm.New(itsm.Config{
			WebhookURL: cfg.ITSMWebhookURL,
			HMACSecret: cfg.ITSMWebhookHMACSecret,
		})
	}
	return d
}

// Configured reports whether EDA and/or ITSM delivery is enabled.
func (d *Dispatcher) Configured() bool {
	return d.cfg.WebhookURL != "" || (d.itsm != nil && d.itsm.Configured())
}

// Run polls and delivers on Interval until ctx is canceled. It is a no-op when
// the dispatcher is not configured.
func (d *Dispatcher) Run(ctx context.Context) {
	if !d.Configured() {
		return
	}
	ticker := time.NewTicker(d.cfg.Interval)
	defer ticker.Stop()
	for {
		if delivered, failed, err := d.RunOnce(ctx); err != nil {
			d.log.Warn("event dispatch cycle", "err", err)
		} else if delivered > 0 || failed > 0 {
			d.log.Info("event dispatch cycle", "delivered", delivered, "failed", failed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce delivers one batch of undelivered events. It returns the counts of
// delivered and failed events. A per-event delivery failure is recorded and does
// not stop the batch; only a store read error aborts the cycle.
func (d *Dispatcher) RunOnce(ctx context.Context) (delivered, failed int, err error) {
	events, err := d.store.ClaimUndeliveredEvents(ctx, d.cfg.Owner, d.cfg.LeaseTTL, d.cfg.BatchSize, d.cfg.MaxAttempts)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range events {
		if derr := d.deliver(ctx, e); derr != nil {
			if merr := d.store.MarkEventFailed(ctx, e.ID, derr.Error()); merr != nil {
				d.log.Warn("mark event failed", "event_id", e.ID.String(), "err", merr)
			}
			failed++
			continue
		}
		if merr := d.store.MarkEventDelivered(ctx, e.ID); merr != nil {
			// Posted but couldn't record it: count as a failed attempt so the
			// dead-letter cap still bounds redelivery (at-least-once — EDA dedups).
			d.log.Warn("mark event delivered", "event_id", e.ID.String(), "err", merr)
			if ferr := d.store.MarkEventFailed(ctx, e.ID, "delivered but not recorded: "+merr.Error()); ferr != nil {
				d.log.Warn("mark event failed", "event_id", e.ID.String(), "err", ferr)
			}
			failed++
			continue
		}
		delivered++
	}
	return delivered, failed, nil
}

// deliver POSTs a single event to the EDA webhook (when set) and optionally to
// the ITSM template sink. Both must succeed when configured.
func (d *Dispatcher) deliver(ctx context.Context, e store.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if d.cfg.WebhookURL != "" {
		if err := postWebhook(ctx, d.http, d.cfg.WebhookURL, d.cfg.Token, body); err != nil {
			return err
		}
	}
	if d.itsm != nil && d.itsm.Configured() {
		if err := d.itsm.Deliver(ctx, e); err != nil {
			return err
		}
	}
	if d.cfg.WebhookURL == "" && (d.itsm == nil || !d.itsm.Configured()) {
		return fmt.Errorf("no delivery sink configured")
	}
	return nil
}

// Ping POSTs a connection-test event to the webhook using the same auth as
// Dispatcher.deliver (Bearer when token is set). It does not read or write the
// events outbox.
func Ping(ctx context.Context, webhookURL, token string) error {
	if webhookURL == "" {
		return fmt.Errorf("eda webhook is not configured")
	}
	body, err := json.Marshal(map[string]string{
		"event_type": "clm.connection.test",
		"id":         uuid.New().String(),
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshal ping: %w", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return postWebhook(ctx, client, webhookURL, token, body)
}

func postWebhook(ctx context.Context, client *http.Client, webhookURL, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post event: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("eda webhook status %d", resp.StatusCode)
	}
	return nil
}
