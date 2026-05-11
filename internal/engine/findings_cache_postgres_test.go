// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// setupPostgresPool starts an ephemeral Postgres container for a single test
// and returns a connected pool plus a cleanup function. Tests using this
// helper require Docker and are skipped under -short.
func setupPostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres integration test in -short mode")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("findings"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := EnsureSchema(ctx, pool, postgresFindingsCacheTable); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	return pool
}

// sampleReport returns a minimal but realistic InterimReport for cache tests.
func sampleReport(match string) *entities.InterimReport {
	return &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "0.1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "src/main/java/Crypto.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   12,
						Match:     match,
						Rules: []entities.RuleInfo{
							{ID: "java.crypto.aes", Message: "AES usage", Severity: "WARNING"},
						},
						Status:   "pending",
						Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "AES"},
					},
				},
			},
		},
	}
}

// TestFindingsCache_CrossImplRoundTrip verifies that an InterimReport written
// through one backend and read through the other produces a logically
// identical report. This is the cross-impl envelope round-trip scenario from
// the spec: callers MUST not be able to tell the backends apart by inspecting
// the report shape after Get.
func TestFindingsCache_CrossImplRoundTrip(t *testing.T) {
	pool := setupPostgresPool(t)
	ctx := context.Background()

	diskCache, err := NewDiskFindingsCacheWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}
	pgCache := NewPostgresFindingsCache(pool)

	const key = "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234"
	original := sampleReport(`Cipher.getInstance("AES/GCM/NoPadding")`)

	// Write via disk → read via disk
	if err := diskCache.Put(ctx, key, original); err != nil {
		t.Fatalf("disk Put: %v", err)
	}
	fromDisk, ok, err := diskCache.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("disk Get: ok=%v err=%v", ok, err)
	}

	// Write via postgres → read via postgres
	if err := pgCache.Put(ctx, key, original); err != nil {
		t.Fatalf("postgres Put: %v", err)
	}
	fromPG, ok, err := pgCache.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("postgres Get: ok=%v err=%v", ok, err)
	}

	// Both round-tripped reports must be byte-identical when re-serialized.
	// json.Marshal is order-stable for structs, so this is a strong equality
	// check that does not depend on map ordering for our struct fields.
	origJSON := mustMarshal(t, original)
	diskJSON := mustMarshal(t, fromDisk)
	pgJSON := mustMarshal(t, fromPG)

	if !bytes.Equal(diskJSON, origJSON) {
		t.Errorf("disk round-trip diverged:\n  orig: %s\n  disk: %s", origJSON, diskJSON)
	}
	if !bytes.Equal(pgJSON, origJSON) {
		t.Errorf("postgres round-trip diverged:\n  orig: %s\n  pg:   %s", origJSON, pgJSON)
	}
	if !bytes.Equal(diskJSON, pgJSON) {
		t.Errorf("backends produced different reports:\n  disk: %s\n  pg:   %s", diskJSON, pgJSON)
	}
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestPostgresFindingsCache_Get_Miss(t *testing.T) {
	pool := setupPostgresPool(t)
	cache := NewPostgresFindingsCache(pool)

	got, ok, err := cache.Get(context.Background(), "missing@1.0:abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Errorf("expected miss, got hit with report=%v", got)
	}
	if got != nil {
		t.Errorf("expected nil report on miss, got %v", got)
	}
}

func TestPostgresFindingsCache_GetPut_RoundTrip(t *testing.T) {
	pool := setupPostgresPool(t)
	cache := NewPostgresFindingsCache(pool)
	ctx := context.Background()
	key := "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234"
	report := sampleReport(`Cipher.getInstance("AES")`)

	if err := cache.Put(ctx, key, report); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected hit, got miss")
	}
	if got.Version != report.Version {
		t.Errorf("version: got %q, want %q", got.Version, report.Version)
	}
	if len(got.Findings) != 1 || got.Findings[0].CryptographicAssets[0].Match != report.Findings[0].CryptographicAssets[0].Match {
		t.Errorf("payload mismatch: got %+v want %+v", got, report)
	}
}

func TestPostgresFindingsCache_VersionMismatch(t *testing.T) {
	pool := setupPostgresPool(t)
	ctx := context.Background()
	key := "stale@1.0:abc"

	// Manually insert a row with an older envelope version. This simulates a
	// row written by a previous crypto-finder build whose schema we no longer
	// understand.
	const olderVersion = findingsCacheVersion - 1
	if olderVersion < 0 {
		t.Skip("findingsCacheVersion is at the floor; cannot simulate older version")
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO `+postgresFindingsCacheTable+` (key, version, report) VALUES ($1, $2, $3)`,
		key, olderVersion, []byte(`{"placeholder":true}`),
	)
	if err != nil {
		t.Fatalf("insert stale row: %v", err)
	}

	cache := NewPostgresFindingsCache(pool)
	got, ok, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok || got != nil {
		t.Errorf("expected miss for version mismatch, got hit=%v report=%v", ok, got)
	}
}

func TestPostgresFindingsCache_Put_Idempotent(t *testing.T) {
	pool := setupPostgresPool(t)
	cache := NewPostgresFindingsCache(pool)
	ctx := context.Background()
	key := "idem@1.0:abc"
	report := sampleReport("AES/GCM/NoPadding")

	for i := 0; i < 3; i++ {
		if err := cache.Put(ctx, key, report); err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM `+postgresFindingsCacheTable+` WHERE key = $1`, key,
	).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("row count for key %q: got %d, want 1", key, count)
	}
}

func TestPostgresFindingsCache_Put_UpdatesTimestamp(t *testing.T) {
	pool := setupPostgresPool(t)
	cache := NewPostgresFindingsCache(pool)
	ctx := context.Background()
	key := "ts@1.0:abc"
	report := sampleReport("DES")

	if err := cache.Put(ctx, key, report); err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	var firstTS time.Time
	if err := pool.QueryRow(ctx,
		`SELECT created_at FROM `+postgresFindingsCacheTable+` WHERE key = $1`, key,
	).Scan(&firstTS); err != nil {
		t.Fatalf("read first ts: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	if err := cache.Put(ctx, key, report); err != nil {
		t.Fatalf("Put #2: %v", err)
	}
	var secondTS time.Time
	if err := pool.QueryRow(ctx,
		`SELECT created_at FROM `+postgresFindingsCacheTable+` WHERE key = $1`, key,
	).Scan(&secondTS); err != nil {
		t.Fatalf("read second ts: %v", err)
	}

	if !secondTS.After(firstTS) {
		t.Errorf("expected second timestamp %v to be after first %v", secondTS, firstTS)
	}
}

func TestPostgresFindingsCache_ConcurrentPut_SameKey(t *testing.T) {
	pool := setupPostgresPool(t)
	cache := NewPostgresFindingsCache(pool)
	ctx := context.Background()
	key := "concurrent@1.0:abc"

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			report := sampleReport(map[int]string{0: "AES", 1: "ChaCha20"}[idx])
			if err := cache.Put(ctx, key, report); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Put error: %v", err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM `+postgresFindingsCacheTable+` WHERE key = $1`, key,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("row count after concurrent Put: got %d, want 1", count)
	}
}

func TestEnsureSchema_FirstRun(t *testing.T) {
	pool := setupPostgresPool(t)
	ctx := context.Background()

	// Drop the table created by setup, then call EnsureSchema fresh.
	if _, err := pool.Exec(ctx, `DROP TABLE `+postgresFindingsCacheTable); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	if err := EnsureSchema(ctx, pool, postgresFindingsCacheTable); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
		postgresFindingsCacheTable,
	).Scan(&exists); err != nil {
		t.Fatalf("info_schema query: %v", err)
	}
	if !exists {
		t.Errorf("expected table %q to exist after EnsureSchema", postgresFindingsCacheTable)
	}
}

func TestEnsureSchema_Idempotent(t *testing.T) {
	pool := setupPostgresPool(t)
	ctx := context.Background()

	// setupPostgresPool already ran EnsureSchema once; running again must be a no-op.
	if err := EnsureSchema(ctx, pool, postgresFindingsCacheTable); err != nil {
		t.Fatalf("EnsureSchema (second run): %v", err)
	}

	// Insert a row, run EnsureSchema again, verify the row is still there.
	cache := NewPostgresFindingsCache(pool)
	if err := cache.Put(ctx, "preserved@1.0:abc", sampleReport("AES")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := EnsureSchema(ctx, pool, postgresFindingsCacheTable); err != nil {
		t.Fatalf("EnsureSchema (third run): %v", err)
	}

	_, ok, err := cache.Get(ctx, "preserved@1.0:abc")
	if err != nil {
		t.Fatalf("Get after re-run: %v", err)
	}
	if !ok {
		t.Error("EnsureSchema modified existing data: row no longer present")
	}
}

func TestNewPostgresFindingsCache_WithTableName(t *testing.T) {
	pool := setupPostgresPool(t)
	ctx := context.Background()

	const customTable = "findings_cache_custom"
	if err := EnsureSchema(ctx, pool, customTable); err != nil {
		t.Fatalf("EnsureSchema(custom): %v", err)
	}

	cache := NewPostgresFindingsCache(pool, WithTableName(customTable))
	key := "custom@1.0:abc"
	if err := cache.Put(ctx, key, sampleReport("AES")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The row must land in the custom table, not the default.
	var defaultCount, customCount int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM `+postgresFindingsCacheTable+` WHERE key = $1`, key).Scan(&defaultCount)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM `+customTable+` WHERE key = $1`, key).Scan(&customCount)
	if defaultCount != 0 {
		t.Errorf("custom-table cache wrote to default table: got %d rows", defaultCount)
	}
	if customCount != 1 {
		t.Errorf("custom-table cache: got %d rows in custom table, want 1", customCount)
	}
}
