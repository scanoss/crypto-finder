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

package opengrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// CoreBinaryEnv names an opengrep-core binary to run in core mode instead of
// the one the opengrep CLI unpacked into its cache.
const CoreBinaryEnv = "SCANOSS_OPENGREP_CORE"

// coreVerifiedVersions are the OpenGrep releases whose CLI behavior core
// mode reproduces: target selection, rule id prefixes, the core command
// line and the output conversion were checked against them. Any other
// version runs the CLI.
var coreVerifiedVersions = []string{"1.30.2"}

// Defaults of the CLI's core command line (opengrep 1.30.2).
const (
	coreDefaultTimeoutSeconds   = 5
	coreTimeoutThreshold        = "3"
	coreMaxMemory               = "0"
	coreDynamicTimeoutUnitKB    = "30"
	coreDynamicTimeoutMaxFactor = "20"
	coreMaxMatchPerFile         = "10000"
)

// coreBinaries remembers, per CLI path and version, the opengrep-core binary
// found for it, or "" when none was.
var coreBinaries sync.Map

// coreCommandOutput runs opengrep-core -version; tests replace it.
var coreCommandOutput = func(ctx context.Context, path string) ([]byte, error) {
	return scanner.CommandContext(ctx, path, "-version").Output()
}

// errCoreUnavailable marks a scan core mode cannot run; the CLI runs instead.
var errCoreUnavailable = errors.New("opengrep: core mode unavailable")

// coreBinary finds the opengrep-core binary matching the CLI's version: the
// one CoreBinaryEnv names, else the one the CLI unpacks into
// <cache>/opengrep/v<version>/semgrep/bin, else one beside the CLI. It
// accepts a binary only when `-version` reports the CLI's version.
func (s *Scanner) coreBinary(ctx context.Context) (string, error) {
	if !slices.Contains(coreVerifiedVersions, s.version) {
		return "", fmt.Errorf("%w: opengrep %s is not a version core mode was verified against (%s)", errCoreUnavailable, s.version, strings.Join(coreVerifiedVersions, ", "))
	}
	key := s.executablePath + "\x00" + s.version + "\x00" + os.Getenv(CoreBinaryEnv)
	if found, ok := coreBinaries.Load(key); ok {
		if path := found.(string); path != "" { //nolint:errcheck,forcetypeassert // Only strings are stored.
			return path, nil
		}
		return "", fmt.Errorf("%w: no opengrep-core %s found", errCoreUnavailable, s.version)
	}
	for _, candidate := range coreCandidates(s.executablePath, s.version) {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		output, err := coreCommandOutput(ctx, candidate)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			continue
		}
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(output)), "opengrep-core version:")) == s.version {
			coreBinaries.Store(key, candidate)
			return candidate, nil
		}
		log.Debug().Str("path", candidate).Str("reported", strings.TrimSpace(string(output))).Str("version", s.version).Msg("opengrep-core version differs from the opengrep CLI; not using it")
	}
	coreBinaries.Store(key, "")
	return "", fmt.Errorf("%w: no opengrep-core %s found", errCoreUnavailable, s.version)
}

func coreCandidates(cliPath, version string) []string {
	var candidates []string
	if explicit := os.Getenv(CoreBinaryEnv); explicit != "" {
		return []string{explicit}
	}
	versionDir := filepath.Join("opengrep", "v"+version, "semgrep", "bin", "opengrep-core")
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, versionDir))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".cache", versionDir))
	}
	if dir, err := os.UserCacheDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, versionDir))
	}
	if resolved, err := filepath.EvalSymlinks(cliPath); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(resolved), "opengrep-core"))
	}
	return slices.Compact(candidates)
}

// coreSupported reports why the scan cannot run in core mode, or "" when it
// can: arguments the adapter does not translate, rules or targets the CLI
// would treat in ways core mode does not reproduce.
func (s *Scanner) coreSupported(rules *coreRuleset) string {
	if len(s.extraArgs) > 0 {
		return "extra scanner arguments are set"
	}
	if rules.coreReason != "" {
		return rules.coreReason
	}
	return ""
}

// coreArgs is the command line the CLI builds for opengrep-core.
func (s *Scanner) coreArgs(rulesFile, targetsFile string) []string {
	jobs := int(s.jobs)
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	timeout := int(s.ruleTimeout)
	if timeout == 0 {
		timeout = coreDefaultTimeoutSeconds
	}
	return []string{
		"-json",
		"-rules", rulesFile,
		"-j", strconv.Itoa(jobs),
		"-targets", targetsFile,
		"-timeout", strconv.Itoa(timeout),
		"-timeout_threshold", coreTimeoutThreshold,
		"-max_memory", coreMaxMemory,
		"-dynamic_timeout_unit_kb", coreDynamicTimeoutUnitKB,
		"-dynamic_timeout_max_multiplier", coreDynamicTimeoutMaxFactor,
		"-max_match_per_file", coreMaxMatchPerFile,
		"-taint_intrafile",
		"-fast",
	}
}

// targetsDocument encodes targets as the targets file opengrep-core reads.
func targetsDocument(targets []coreTarget) ([]byte, error) {
	type codeTarget struct {
		Path     string   `json:"path"`
		Analyzer string   `json:"analyzer"`
		Products []string `json:"products"`
	}
	entries := make([][2]any, 0, len(targets))
	for _, target := range targets {
		entries = append(entries, [2]any{"CodeTarget", codeTarget{Path: target.path, Analyzer: target.analyzer, Products: []string{"sast"}}})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("opengrep: encode core targets: %w", err)
	}
	return data, nil
}

// runCore runs opengrep-core over plan with rules and converts its output to
// what the CLI prints. useBase names the rules by the ids their files spell
// (coreRuleIDs) rather than by the CLI's prefixed ids; cacheable lets such a
// rules file persist in the core rules cache.
func (s *Scanner) runCore(ctx context.Context, binary string, rules []*coreRule, plan *targetPlan, useBase, cacheable bool) (*entities.SemgrepOutput, error) {
	if len(rules) == 0 || len(plan.targets) == 0 {
		return &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}, nil
	}
	doc, err := rulesDocument(rules, useBase)
	if err != nil {
		return nil, err
	}
	cacheDir := ""
	if cacheable && useBase {
		cacheDir = s.coreRulesCacheDir
	}
	rulesFile, cleanupRules, err := cachedRulesFile(cacheDir, s.version, doc)
	if err != nil {
		return nil, err
	}
	defer cleanupRules()

	targetsFile, cleanupTargets, err := writeTargetsFile(plan.targets)
	if err != nil {
		return nil, err
	}
	defer cleanupTargets()

	args := s.coreArgs(rulesFile, targetsFile)
	cmd := scanner.CommandContext(ctx, binary, args...)
	if s.workDir != "" {
		cmd.Dir = s.workDir
	}
	if len(s.env) > 0 {
		cmd.Env = append(cmd.Environ(), mapToEnvSlice(s.env)...)
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	started := time.Now()
	stdout, runErr := cmd.Output()
	duration := time.Since(started)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if runErr != nil {
		return nil, fmt.Errorf("opengrep: opengrep-core failed after %.2fs: %w: %s", duration.Seconds(), runErr, lastLines(stderr.String(), 5))
	}
	parsed, err := parseCoreOutput(stdout)
	if err != nil {
		return nil, err
	}
	converted, err := convertCoreOutput(parsed, rules, useBase)
	if err != nil {
		return nil, err
	}
	log.Info().
		Dur("duration", duration).
		Int("rules", len(rules)).
		Int("targets", len(plan.targets)).
		Msgf("opengrep-core completed in %.2fs", duration.Seconds())
	return converted, nil
}

// writeTargetsFile writes the targets file for one opengrep-core run.
func writeTargetsFile(targets []coreTarget) (string, func(), error) {
	data, err := targetsDocument(targets)
	if err != nil {
		return "", nil, err
	}
	file, err := os.CreateTemp("", "crypto-finder-core-targets-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("opengrep: create core targets file: %w", err)
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) } //nolint:errcheck // Best-effort removal of the temp file CreateTemp made.
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("opengrep: write core targets file: %w", err)
	}
	return name, cleanup, nil
}

func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
