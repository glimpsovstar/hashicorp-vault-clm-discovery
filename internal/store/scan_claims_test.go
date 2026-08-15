package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClaimNextScans_ConcurrentExclusive(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	scan, err := st.CreateScan(ctx, []string{"203.0.113.10/32"}, nil, []int{443}, 10, 0)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteScan(context.Background(), scan.ID) })

	const workers = 8
	var mu sync.Mutex
	claimed := map[uuid.UUID]string{}
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		owner := fmt.Sprintf("worker-%d", i)
		go func(owner string) {
			defer wg.Done()
			<-start
			got, err := st.ClaimNextScans(ctx, owner, 30*time.Second, 1)
			if err != nil {
				t.Errorf("ClaimNextScans(%s): %v", owner, err)
				return
			}
			for _, s := range got {
				mu.Lock()
				if prev, ok := claimed[s.ID]; ok {
					t.Errorf("scan %s claimed by both %s and %s", s.ID, prev, owner)
				}
				claimed[s.ID] = owner
				mu.Unlock()
			}
		}(owner)
	}
	close(start)
	wg.Wait()

	if len(claimed) != 1 {
		t.Fatalf("expected exactly one claim of the pending scan, got %d: %v", len(claimed), claimed)
	}
	if _, ok := claimed[scan.ID]; !ok {
		t.Fatalf("expected scan %s to be claimed, got %v", scan.ID, claimed)
	}
}

func TestClaimNextScans_ReclaimsStaleRunning(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	scan, err := st.CreateScan(ctx, []string{"203.0.113.11/32"}, nil, []int{443}, 10, 0)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteScan(context.Background(), scan.ID) })

	first, err := st.ClaimNextScans(ctx, "owner-a", 50*time.Millisecond, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: got %d err=%v", len(first), err)
	}

	// Still within lease: second owner must not steal.
	second, err := st.ClaimNextScans(ctx, "owner-b", 50*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("expected no steal while lease fresh, got %+v", second)
	}

	time.Sleep(80 * time.Millisecond)

	stolen, err := st.ClaimNextScans(ctx, "owner-b", 50*time.Millisecond, 1)
	if err != nil || len(stolen) != 1 {
		t.Fatalf("stale reclaim: got %d err=%v", len(stolen), err)
	}
	if stolen[0].ID != scan.ID {
		t.Fatalf("reclaimed wrong scan: %s", stolen[0].ID)
	}
	if stolen[0].ClaimedBy == nil || *stolen[0].ClaimedBy != "owner-b" {
		t.Fatalf("expected claimed_by owner-b, got %v", stolen[0].ClaimedBy)
	}
}

func TestCreateScan_OverCapReturnsQueueFull(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	var ids []uuid.UUID
	t.Cleanup(func() {
		for _, id := range ids {
			_ = st.DeleteScan(context.Background(), id)
		}
	})

	for i := 0; i < 2; i++ {
		s, err := st.CreateScan(ctx, []string{"203.0.113.20/32"}, nil, []int{443}, 1, 2)
		if err != nil {
			t.Fatalf("CreateScan %d: %v", i, err)
		}
		ids = append(ids, s.ID)
	}
	_, err := st.CreateScan(ctx, []string{"203.0.113.21/32"}, nil, []int{443}, 1, 2)
	if err != ErrScanQueueFull {
		t.Fatalf("want ErrScanQueueFull, got %v", err)
	}
}

func TestHeartbeatScanClaim_ExtendsLease(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	scan, err := st.CreateScan(ctx, []string{"203.0.113.12/32"}, nil, []int{443}, 10, 0)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteScan(context.Background(), scan.ID) })

	got, err := st.ClaimNextScans(ctx, "hb-owner", 100*time.Millisecond, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v len=%d", err, len(got))
	}
	time.Sleep(60 * time.Millisecond)
	if err := st.HeartbeatScanClaim(ctx, scan.ID, "hb-owner"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	// Without heartbeat, lease would be ~120ms old; with heartbeat at 60ms it should still be held.
	steal, err := st.ClaimNextScans(ctx, "thief", 100*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("steal attempt: %v", err)
	}
	if len(steal) != 0 {
		t.Fatalf("heartbeat should prevent steal, got %+v", steal)
	}
}
