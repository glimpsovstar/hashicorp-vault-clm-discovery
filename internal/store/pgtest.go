package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// openTestStore connects to Postgres for claim/queue integration tests.
// Uses DATABASE_URL when set (CI), else the local Compose default.
// Skips when the database is unreachable so unit-only machines stay green.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://clm:clm@localhost:5432/clm?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres unreachable: %v", err)
	}
	t.Cleanup(pool.Close)
	return New(pool, 30)
}
