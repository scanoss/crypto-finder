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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/perf"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// nonSemanticEnvironment names the variables left out of a dependency's
// findings-cache identity. None of them reaches what a scan finds: they are
// crypto-finder's own diagnostics and host tuning, which it reads and no
// scanner does, and the bookkeeping a shell or login session sets per
// invocation. Each one otherwise changes on every run (a timings file named
// per run, the previous directory, the login's ephemeral port) and turns
// every warm run into a full rescan. Every other variable still partitions
// the cache, because a scanner may read it.
var nonSemanticEnvironment = map[string]bool{
	// crypto-finder diagnostics: they write timing and profile files only.
	"SCANOSS_PHASE_TIMINGS": true,
	"SCANOSS_CPUPROFILE":    true,
	"SCANOSS_MEMPROFILE":    true,
	"SCANOSS_TRACE":         true,
	// Host tuning, already left out of the keyed scanner configuration
	// (Config.Jobs) for the same reason.
	"SCANOSS_SCANNER_JOBS": true,
	// Shell bookkeeping. The working directory is keyed on its own (CWD).
	"_":      true,
	"OLDPWD": true,
	"PWD":    true,
	"SHLVL":  true,
	// Per-login session identity.
	"SSH_AUTH_SOCK":   true,
	"SSH_CLIENT":      true,
	"SSH_CONNECTION":  true,
	"SSH_TTY":         true,
	"GPG_TTY":         true,
	"TERM_SESSION_ID": true,
	"WINDOWID":        true,
	"TMUX_PANE":       true,
	"XDG_SESSION_ID":  true,
}

// cacheIdentityEnvironment returns the sorted NAME=value entries of env that
// partition the findings cache.
func cacheIdentityEnvironment(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if nonSemanticEnvironment[name] {
			continue
		}
		kept = append(kept, entry)
	}
	sort.Strings(kept)
	return kept
}

// dependencyCacheIdentity is what a dependency's findings-cache key hashes.
// Its JSON encoding is the key material: field names and order are part of
// every stored key.
type dependencyCacheIdentity struct {
	Package       string
	RulesHash     string
	JavaRuntime   string
	Name          string
	Scanner       scanner.Info
	FinderVersion string
	Config        scanner.Config
	Languages     []string
	Environment   []string
	CWD           string
	// Omitted for a whole-module scan, so those keys stay as they were.
	Scope *scanner.DetectionScope `json:",omitempty"`
}

// key returns the findings-cache key of the identity.
func (id *dependencyCacheIdentity) key() (string, error) {
	identity, err := json.Marshal(id)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("dependency-findings-v2:%x", sha256.Sum256(identity)), nil
}

// logComponents logs, at debug level, a short digest of each identity
// component, so two runs' logs show which component split their keys.
func (id *dependencyCacheIdentity) logComponents(module, version, state string) {
	if !log.Debug().Enabled() {
		return
	}
	digest := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			return "unencodable"
		}
		return fmt.Sprintf("%x", sha256.Sum256(data))[:12]
	}
	log.Debug().
		Str("module", module).
		Str("version", version).
		Str("cache", state).
		Str("package", id.Package).
		Str("rulesHash", id.RulesHash).
		Str("javaRuntime", id.JavaRuntime).
		Str("scannerName", id.Name).
		Str("scanner", digest(id.Scanner)).
		Str("finderVersion", id.FinderVersion).
		Str("config", digest(id.Config)).
		Str("languages", digest(id.Languages)).
		Str("environment", digest(id.Environment)).
		Str("cwd", id.CWD).
		Str("scope", digest(id.Scope)).
		Msg("Dependency findings cache identity")
}

// Dependency findings-cache lookup outcomes.
const (
	depCacheHit            = "hit"
	depCacheAbsent         = "absent"
	depCacheDisabled       = "disabled"
	depCacheNoIdentity     = "no_identity"
	depCacheReadError      = "read_error"
	depCacheScannerFailed  = "scanner_init_failed"
	depCacheFindingsSource = "findings_source"
)

// Dependency findings-cache store outcomes.
const (
	depCacheStored     = "stored"
	depCacheIncomplete = "not_stored_incomplete"
	depCacheNoKey      = "not_stored_no_key"
	depCachePutError   = "not_stored_put_error"
	depCacheScanFailed = "not_stored_scan_failed"
)

// depCacheStats counts one scan's findings-cache lookups and stores by
// outcome. The nil value counts nothing.
type depCacheStats struct {
	mu      sync.Mutex
	lookups map[string]int
	stores  map[string]int
}

func newDepCacheStats() *depCacheStats {
	return &depCacheStats{lookups: map[string]int{}, stores: map[string]int{}}
}

func (s *depCacheStats) lookup(outcome string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lookups[outcome]++
	s.mu.Unlock()
}

func (s *depCacheStats) store(outcome string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stores[outcome]++
	s.mu.Unlock()
}

// report logs the counts and writes them as a phase note.
func (s *depCacheStats) report(event *zerolog.Event, msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	lookups, stores := formatCounts(s.lookups), formatCounts(s.stores)
	hits := s.lookups[depCacheHit]
	s.mu.Unlock()
	event.Int("cacheHits", hits).Str("cacheLookups", lookups).Str("cacheStores", stores).Msg(msg)
	perf.Note("dependency_findings_cache lookups=%s stores=%s", lookups, stores)
}

// formatCounts renders counts as sorted name:count pairs, "-" when empty.
func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "-"
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = fmt.Sprintf("%s:%d", name, counts[name])
	}
	return strings.Join(parts, ",")
}
