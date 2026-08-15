package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClaimUndeliveredEvents_ConcurrentExclusive(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	certID := uuid.New()
	// Insert a bare outbox row without needing a real certificate FK when nullable.
	evID, err := insertTestEvent(ctx, st, "test.claim", nil, json.RawMessage(`{"n":1}`))
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), `DELETE FROM events WHERE id = $1`, evID)
	})
	_ = certID

	const workers = 8
	var mu sync.Mutex
	claimed := map[uuid.UUID]string{}
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		owner := fmt.Sprintf("eda-%d", i)
		go func(owner string) {
			defer wg.Done()
			<-start
			got, err := st.ClaimUndeliveredEvents(ctx, owner, 30*time.Second, 1, 10)
			if err != nil {
				t.Errorf("ClaimUndeliveredEvents(%s): %v", owner, err)
				return
			}
			for _, e := range got {
				mu.Lock()
				if prev, ok := claimed[e.ID]; ok {
					t.Errorf("event %s claimed by both %s and %s", e.ID, prev, owner)
				}
				claimed[e.ID] = owner
				mu.Unlock()
			}
		}(owner)
	}
	close(start)
	wg.Wait()

	if len(claimed) != 1 {
		t.Fatalf("expected exactly one claim, got %d: %v", len(claimed), claimed)
	}
	if _, ok := claimed[evID]; !ok {
		t.Fatalf("expected event %s claimed, got %v", evID, claimed)
	}
}

func insertTestEvent(ctx context.Context, st *Store, eventType string, certID *uuid.UUID, payload json.RawMessage) (uuid.UUID, error) {
	var id uuid.UUID
	err := st.pool.QueryRow(ctx, `
		INSERT INTO events (event_type, certificate_id, payload)
		VALUES ($1, $2, $3)
		RETURNING id
	`, eventType, certID, payload).Scan(&id)
	return id, err
}
