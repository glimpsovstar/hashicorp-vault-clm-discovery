// Package eventbus delivers CLM outbox events to Ansible EDA via webhook
// (ADR 0001, event Phase 1). It is the reactive counterpart to the batch
// endpoints: a background dispatcher polls the outbox and POSTs each undelivered
// event to a configured EDA webhook, retrying with attempt tracking and
// dead-lettering after a cap. The whole thing is a no-op when no webhook URL is
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

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// eventStore is the outbox surface the dispatcher needs (satisfied by *store.Store).
type eventStore interface {
	ListUndeliveredEvents(ctx context.Context, limit, maxAttempts int) ([]store.Event, error)
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
}

// Dispatcher polls the outbox and delivers events to the EDA webhook.
type Dispatcher struct {
	cfg   Config
	store eventStore
	http  *http.Client
	log   *slog.Logger
}

// New builds a dispatcher. It is inert until Run is called and does nothing when
// the webhook URL is empty (Configured()==false).
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
	return &Dispatcher{
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
}

// Configured reports whether a webhook URL is set.
func (d *Dispatcher) Configured() bool { return d.cfg.WebhookURL != "" }

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
	events, err := d.store.ListUndeliveredEvents(ctx, d.cfg.BatchSize, d.cfg.MaxAttempts)
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

// deliver POSTs a single event to the EDA webhook as JSON.
func (d *Dispatcher) deliver(ctx context.Context, e store.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if d.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+d.cfg.Token)
	}
	resp, err := d.http.Do(req)
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
