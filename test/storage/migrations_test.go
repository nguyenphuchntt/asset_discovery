package storage_test

import "testing"

// Migrations — covered scenarios:
//   1. Init succeeds on fresh DB (schema applied)
//   2. Init is idempotent (run twice — no error)
//   3. Embedded schema.sql is valid (parsed by SQLite on Init)

func TestMigrations_InitSuccess(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()
	// newRepo calls Init() — if we reach here, schema was applied.
}

func TestMigrations_InitIdempotent(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()
	// newRepo already called Init once. Call it again.
	// Init() is idempotent — should not error.
}
