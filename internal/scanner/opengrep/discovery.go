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
)

type discovery struct {
	ready chan struct{}
	value string
}
type discoveryCache struct {
	mu      sync.Mutex
	entries map[string]*discovery
}

// key fingerprints executable bytes and the ambient context actually used by probes.
// Config.Env and Config.WorkDir affect scans, not baseline version/help probes.
func discoveryKey(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // Read-only close cannot change the fingerprint bytes.
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	env := os.Environ()
	slices.Sort(env)
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00", path, resolved, cwd, info.Size(), info.ModTime().UnixNano(), info.Mode(), strings.Join(env, "\x00")) //nolint:errcheck // SHA-256 writes always succeed.
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (c *discoveryCache) get(ctx context.Context, path string, probe func() (string, error)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c == nil {
		return probe()
	}
	key, err := discoveryKey(path)
	if err != nil {
		return probe()
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
		value, err := probe()
		c.finish(ctx, path, key, entry, value, err)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return value, err
	}
}

func (c *discoveryCache) finish(ctx context.Context, path, key string, entry *discovery, value string, err error) {
	current, keyErr := discoveryKey(path)
	_, versionErr := version.NewVersion(value)
	c.mu.Lock()
	if versionErr != nil || err != nil || ctx.Err() != nil || keyErr != nil || current != key {
		delete(c.entries, key)
	} else {
		entry.value = value
	}
	close(entry.ready)
	c.mu.Unlock()
}
