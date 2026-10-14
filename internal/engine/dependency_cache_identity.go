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

// opengrepEnvironment names the variables that partition an opengrep
// dependency scan's findings cache: the ones an audit of the scan path
// (crypto-finder, opengrep 1.30.2 and the opengrep-core it runs) found can
// change what a scan of fixed sources with fixed rules and settings finds. Every other variable
// is left out, so per-run, per-session and per-host values (HOSTNAME, PATH,
// HOME, CI run ids, SSH session variables, timings files) neither split the
// cache nor stop hosts sharing one. What the left-out variables do steer is
// keyed on its own, after it is resolved:
//   - the engine by its content (Engine), not by the PATH or HOME that find it;
//   - the dependency's root (Root), the absolute path the engine scans and
//     the cached findings name, not the HOME, GOMODCACHE or CARGO_HOME it
//     derives from;
//   - crypto-finder's SCANOSS_ settings by the scanner configuration, Java
//     runtime and engine fingerprint they resolve into (Config, JavaRuntime,
//     Engine).
//
// Variables the engines read that cannot reach a dependency scan's findings
// are left out too: dependency scans always pass --config and --timeout
// (SEMGREP_RULES, SEMGREP_TIMEOUT), never consult Git or .semgrepignore
// (GIT_*, Git configuration under HOME or XDG_CONFIG_HOME), and the opengrep
// CLI verifies what it unpacks under XDG_CACHE_HOME on every launch.
// Upgrading opengrep changes the engine fingerprint; audit the new version's
// environment reads before relying on this list for it.
var opengrepEnvironment = map[string]bool{
	// Locale: the opengrep CLI decodes rule files and the matched "lines"
	// with the locale's encoding; without a UTF-8 locale a non-ASCII rule
	// fails the scan and UTF-8 snippets come out mangled.
	"LANG":     true,
	"LC_ALL":   true,
	"LC_CTYPE": true,
	"LOCPATH":  true,
	// opengrep-core: SEMGREP_CORE_EXTRA appends arbitrary core flags, the
	// OCaml runtime parameters set its stack and GC limits.
	"SEMGREP_CORE_EXTRA": true,
	"OCAMLRUNPARAM":      true,
	"CAMLRUNPARAM":       true,
	// opengrep CLI scan settings crypto-finder never passes as flags: a
	// baseline keeps only new findings, an explicit ignore file drops
	// targets, the recursion limit decides whether deep input is analyzed.
	"SEMGREP_BASELINE_COMMIT":                     true,
	"SEMGREP_BASELINE_REF":                        true,
	"SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE": true,
	"SEMGREP_PYTHON_RECURSION_LIMIT_INCREASE":     true,
	// The dynamic loader: these change the code the dynamically linked
	// opengrep CLI runs.
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
}

// nonSemanticEnvironment names the variables left out of the findings-cache
// identity of a scanner whose environment reads were not audited (see
// opengrepEnvironment). None of them reaches what a scan finds: they are
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

// auditedEnvironment maps a scanner name to the variables an audit found can
// change that scanner's findings.
var auditedEnvironment = map[string]map[string]bool{
	"opengrep": opengrepEnvironment,
}

// cacheIdentityEnvironment returns the sorted NAME=value entries of env that
// partition the findings cache of the named scanner: the audited ones, or,
// for a scanner without an audit, every variable but the non-semantic ones.
func cacheIdentityEnvironment(scannerName string, env []string) []string {
	audited, ok := auditedEnvironment[scannerName]
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if (ok && audited[name]) || (!ok && !nonSemanticEnvironment[name]) {
			kept = append(kept, entry)
		}
	}
	sort.Strings(kept)
	return kept
}

// engineFingerprint returns the content fingerprint of the engine s runs,
// or "" for a scanner that cannot give one.
func engineFingerprint(ctx context.Context, s scanner.Scanner) (string, error) {
	fingerprinter, ok := s.(scanner.EngineFingerprinter)
	if !ok {
		return "", nil
	}
	return fingerprinter.EngineFingerprint(ctx)
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
	// CWD is crypto-finder's working directory when the scan's results can
	// depend on it (cacheCWD), else empty.
	CWD string
	// Omitted for a whole-module scan.
	Scope *scanner.DetectionScope `json:",omitempty"`
	// Engine is the engine's content fingerprint; empty for a scanner that
	// cannot give one.
	Engine string `json:",omitempty"`
	// Root is where the dependency's source lies (cacheRoot): its place in
	// a store of published package versions when the scanner scans it
	// through paths relative to it, else its directory. Cached reports name
	// files relative to the dependency's directory, so an entry keyed by a
	// place serves every directory holding that place.
	Root string
	// Source is the digest of the dependency's source content
	// (sourceDigest) when Root is a place in a store that does not verify
	// what it holds (storeVerifiesContent): node_modules, site-packages and
	// crypto-finder's source cache hold whatever was installed there under
	// a version's name. Empty when the place names the content, or the
	// directory is keyed.
	Source string `json:",omitempty"`
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
		Str("engine", id.Engine).
		Str("root", id.Root).
		Str("source", id.Source).
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
	depCacheUnportable = "not_stored_unportable"
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
