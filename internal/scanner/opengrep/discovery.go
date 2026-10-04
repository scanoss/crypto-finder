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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package opengrep

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog/log"
)

type discovery struct {
	ready chan struct{}
	value string
}
type discoveryCache struct {
	mu          sync.Mutex
	versionOnly bool
	entries     map[string]*discovery
	// kind names the probe in the on-disk store; store is nil when results
	// live only for this process.
	kind  string
	store *probeStore
}

// probe runs one discovery. persist reports whether a successful value may
// outlive the process: a fallback answer to a failed preferred probe may not.
type probe func() (value string, persist bool, err error)

// discoveryKeys fingerprints the executable once. binary covers the resolved
// path, size, modification time, mode and bytes, which is what the on-disk
// store trusts across processes. run also covers the invoked path, the working
// directory and the environment, which in-process reuse keeps exact.
// Config.Env and Config.WorkDir affect scans, not baseline version/help probes.
func discoveryKeys(path string) (run, binary string, err error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", err
	}
	if resolved, err = filepath.Abs(resolved); err != nil {
		return "", "", err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // Read-only close cannot change the fingerprint bytes.
	info, err := file.Stat()
	if err != nil {
		return "", "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	hash := sha256.New()
	//nolint:errcheck // SHA-256 writes always succeed.
	_, _ = fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%d\x00", resolved, info.Size(), info.ModTime().UnixNano(), info.Mode()) // #nosec G705 -- Writes SHA-256 digest bytes, not HTML.
	if _, err = io.Copy(hash, file); err != nil {
		return "", "", err
	}
	binary = fmt.Sprintf("%x", hash.Sum(nil))
	env := os.Environ()
	slices.Sort(env)
	runHash := sha256.New()
	//nolint:errcheck // SHA-256 writes always succeed.
	_, _ = fmt.Fprintf(runHash, "%s\x00%s\x00%s\x00%s\x00", binary, path, cwd, strings.Join(env, "\x00")) // #nosec G705 -- Writes SHA-256 digest bytes, not HTML.
	return fmt.Sprintf("%x", runHash.Sum(nil)), binary, nil
}

func (c *discoveryCache) get(ctx context.Context, path string, run probe) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c == nil {
		value, _, err := run()
		return value, err
	}
	key, binary, err := discoveryKeys(path)
	if err != nil {
		value, _, probeErr := run()
		return value, probeErr
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		c.mu.Lock()
		if entry := c.entries[key]; entry != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-entry.ready:
			}
			c.mu.Lock()
			cached := c.entries[key] == entry
			c.mu.Unlock()
			if cached {
				return entry.value, ctx.Err()
			}
			continue
		}
		entry := &discovery{ready: make(chan struct{})}
		c.entries[key] = entry
		c.mu.Unlock()
		return c.fill(ctx, path, key, binary, entry, run)
	}
}

// fill resolves a new entry from the on-disk store, or else by probing.
func (c *discoveryCache) fill(ctx context.Context, path, key, binary string, entry *discovery, run probe) (string, error) {
	if value, ok := c.load(binary); ok {
		c.mu.Lock()
		entry.value = value
		close(entry.ready)
		c.mu.Unlock()
		return value, nil
	}
	value, persist, err := run()
	if c.finish(ctx, path, key, entry, value, err) && persist {
		c.save(binary, value)
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return value, err
}

// finish publishes a probe result to waiters and reports whether it was kept.
func (c *discoveryCache) finish(ctx context.Context, path, key string, entry *discovery, value string, err error) bool {
	current, _, keyErr := discoveryKeys(path)
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.valid(value) && err == nil && ctx.Err() == nil && keyErr == nil && current == key
	if kept {
		entry.value = value
	} else {
		delete(c.entries, key)
	}
	close(entry.ready)
	return kept
}

// valid reports whether value is a usable result for this cache's probe.
func (c *discoveryCache) valid(value string) bool {
	if !c.versionOnly {
		return true
	}
	_, err := version.NewVersion(value)
	return err == nil
}

// load returns a stored result for the binary. Any unreadable, foreign or
// invalid entry is a miss, so the caller probes as before.
func (c *discoveryCache) load(binary string) (string, bool) {
	value, ok := c.store.load(c.kind, binary)
	if !ok || !c.valid(value) {
		return "", false
	}
	return value, true
}

func (c *discoveryCache) save(binary, value string) {
	if err := c.store.save(c.kind, binary, value); err != nil {
		log.Debug().Err(err).Str("probe", c.kind).Msg("failed to persist opengrep probe result; later runs will probe again")
	}
}
