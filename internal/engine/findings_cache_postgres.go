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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	// postgresFindingsCacheTable is the default table name used by
	// PostgresFindingsCache and EnsureSchema when no override is provided.
	postgresFindingsCacheTable = "findings_cache"
)

// postgresIdentifier matches valid SQL identifiers we accept for table names.
// Table names cannot be passed as bind parameters, so the caller-supplied
// value is validated against this pattern before interpolation.
var postgresIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// PostgresCacheOption configures a PostgresFindingsCache at construction time.
type PostgresCacheOption func(*PostgresFindingsCache)

// WithTableName overrides the default findings_cache table name. The provided
// name must match a SQL identifier pattern; invalid names cause the option to
// be ignored and the cache to fall back to the default table.
func WithTableName(name string) PostgresCacheOption {
	return func(c *PostgresFindingsCache) {
		if postgresIdentifier.MatchString(name) {
			c.table = name
		}
	}
}

// PostgresFindingsCache stores InterimReport entries in a Postgres table,
// providing a multi-process-safe FindingsCache implementation suitable for
// fleet-wide deployments where multiple workers share a single cache.
type PostgresFindingsCache struct {
	pool  *pgxpool.Pool
	table string
}

// NewPostgresFindingsCache returns a cache backed by the provided pool. The
// pool is borrowed, not owned: callers are responsible for closing it.
func NewPostgresFindingsCache(pool *pgxpool.Pool, opts ...PostgresCacheOption) *PostgresFindingsCache {
	c := &PostgresFindingsCache{
		pool:  pool,
		table: postgresFindingsCacheTable,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// EnsureSchema creates the findings_cache table on first run and is a no-op
// when the table already exists. It is safe to call repeatedly and from
// multiple processes.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool, table string) error {
	if !postgresIdentifier.MatchString(table) {
		return fmt.Errorf("invalid table name %q", table)
	}

	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    key         TEXT PRIMARY KEY,
    version     SMALLINT NOT NULL,
    report      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, table)

	if _, err := pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("ensure findings_cache schema: %w", err)
	}
	return nil
}

// Get retrieves a cached report by key. Returns (nil, false, nil) for unknown
// keys, version mismatches, or rows whose payload fails to unmarshal — the
// disk implementation has the same semantics, so callers cannot distinguish
// the backends.
func (c *PostgresFindingsCache) Get(ctx context.Context, key string) (*entities.InterimReport, bool, error) {
	stmt := fmt.Sprintf(`SELECT version, report FROM %s WHERE key = $1`, c.table)

	var (
		version int16
		payload []byte
	)
	if err := c.pool.QueryRow(ctx, stmt, key).Scan(&version, &payload); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("query findings_cache row: %w", err)
	}

	if int(version) != findingsCacheVersion {
		return nil, false, nil
	}

	var report entities.InterimReport
	if err := json.Unmarshal(payload, &report); err != nil {
		// Treat unreadable payload as a miss; this matches the disk impl
		// semantics (see findings_cache_disk.go: corrupted file → miss).
		// The error is intentionally swallowed because callers must not
		// distinguish "no row" from "unreadable row" when deciding whether
		// to rescan — the rescan path will overwrite the bad row.
		//nolint:nilerr // intentional: corrupted payload is treated as cache miss
		return nil, false, nil
	}
	return &report, true, nil
}

// Put stores or updates a report by key. Concurrent calls with the same key
// are safe: the upsert resolves any race to a single row whose contents
// reflect one of the racing payloads.
func (c *PostgresFindingsCache) Put(ctx context.Context, key string, report *entities.InterimReport) error {
	if report == nil {
		return errors.New("findings cache: refusing to store nil report")
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal findings cache payload: %w", err)
	}

	stmt := fmt.Sprintf(`INSERT INTO %s (key, version, report, created_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (key) DO UPDATE
SET version    = EXCLUDED.version,
    report     = EXCLUDED.report,
    created_at = NOW()`, c.table)

	if _, err := c.pool.Exec(ctx, stmt, key, findingsCacheVersion, payload); err != nil {
		return fmt.Errorf("upsert findings_cache row: %w", err)
	}
	return nil
}
