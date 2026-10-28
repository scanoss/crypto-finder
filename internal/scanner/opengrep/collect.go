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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// prefilteredIDMarker starts the id of every rule in a prefiltered rules
// file the CLI runs. The CLI puts the file's own directory before it, and
// everything up to and including the marker is cut from the check_ids it
// reports, leaving the id the CLI gives the rule in its original file.
const prefilteredIDMarker = "crypto-finder-prefiltered."

// collect runs OpenGrep over roots, which share base, in the base
// directory (site), and returns the output the CLI prints for them, with
// paths named as the caller names the base. With a rule prefilter or core
// mode it first reads the rules and enumerates the targets as the CLI
// would; whenever that or opengrep-core fails it runs the CLI with every
// rule, so a failure costs time, never findings. Rules that hit OpenGrep's
// time limit on a file run once more with a longer limit (retryTimeouts).
func (s *Scanner) collect(ctx context.Context, base string, roots []scanner.Root, rulePaths []string) (*entities.SemgrepOutput, error) {
	st := s.siteFor(base, roots, rulePaths)
	if st.dir != "" {
		local := *s
		local.skipPatterns = st.excludes
		s = &local
	}
	scoped := false
	for _, root := range roots {
		scoped = scoped || root.Scope != nil
	}
	if s.mode == scanner.OpengrepModeCore || s.prefilter == scanner.RulePrefilterImports {
		output, ran, handled, err := s.collectPlanned(ctx, &st, rulePaths, scoped)
		if handled {
			if err != nil {
				return nil, err
			}
			return s.retryTimeouts(ctx, &st, output, ran, rulePaths)
		}
	}
	output, err := s.collectCLI(ctx, &st, st.configs, scoped, st.rewriteID)
	if err != nil {
		return nil, err
	}
	return s.retryTimeouts(ctx, &st, output, nil, rulePaths)
}

// collectPlanned is collect for the modes that plan the scan themselves.
// handled is false when the plain CLI scan must run instead; ran is the
// rules the scan ran.
func (s *Scanner) collectPlanned(ctx context.Context, st *site, rulePaths []string, scoped bool) (output *entities.SemgrepOutput, ran []*coreRule, handled bool, err error) {
	started := time.Now()
	cwd, err := physicalDir(s.workDir)
	if err != nil {
		s.fallback("working directory unavailable", err)
		return nil, nil, false, nil
	}
	ruleset, err := loadCoreRuleset(rulePaths, cwd)
	if err != nil {
		s.fallback("rules unreadable for core mode or the prefilter", err)
		return nil, nil, false, nil
	}
	plan, err := enumerateTargets(ctx, targetOptions{
		targets:           targetStrings(st.targets()),
		dir:               st.dir,
		skipPatterns:      s.skipPatterns,
		includeGitIgnored: s.includeGitIgnored,
		forceExclude:      scoped,
		maxTargetBytes:    defaultMaxTargetBytes,
		env:               s.processEnv(),
	}, languagesOf(ruleset.rules))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, true, s.contextFailure(ctx, time.Since(started))
		}
		s.fallback("targets need the opengrep CLI", err)
		return nil, nil, false, nil
	}

	// A scoped scan (--detect-paths-from) reads only the listed files, whose
	// imports may sit in files outside the scope, so the prefilter would
	// drop rules the unit can match: every rule runs.
	withPrefilter := s.prefilter == scanner.RulePrefilterImports && !scoped
	inspection := inspectTargets(plan, withPrefilter)
	rules := ruleset.rules
	if withPrefilter {
		rules = s.prefilterRules(ruleset.rules, inspection.evidence, st.roots)
	} else if s.prefilter == scanner.RulePrefilterImports {
		log.Debug().Msg("Rule prefilter skipped: the scan is limited to listed files")
	}

	if s.mode == scanner.OpengrepModeCore {
		output, err := s.collectCore(ctx, ruleset, rules, plan, inspection.nosem)
		if err == nil {
			st.nameOutput(output)
			return output, rules, true, nil
		}
		if ctx.Err() != nil {
			return nil, nil, true, s.contextFailure(ctx, time.Since(started))
		}
		s.fallback("opengrep-core did not run", err)
	}

	if len(rules) == len(ruleset.rules) {
		output, err := s.collectCLI(ctx, st, st.configs, scoped, st.rewriteID)
		return output, rules, true, err
	}
	if len(rules) == 0 {
		return &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}, rules, true, nil
	}
	filtered, cleanup, err := writePrefilteredRules(rules)
	if err != nil {
		s.fallback("prefiltered rules could not be written", err)
		return nil, nil, false, nil
	}
	defer cleanup()
	output, err = s.collectCLI(ctx, st, []string{filtered}, scoped, restorePrefilteredID)
	return output, rules, true, err
}

// collectCore runs opengrep-core when core mode supports the scan. nosem
// says some target may hold a nosemgrep comment.
func (s *Scanner) collectCore(ctx context.Context, ruleset *coreRuleset, rules []*coreRule, plan *targetPlan, nosem bool) (*entities.SemgrepOutput, error) {
	if reason := s.coreSupported(ruleset); reason != "" {
		return nil, fmt.Errorf("%w: %s", errCoreUnavailable, reason)
	}
	binary, err := s.coreBinary(ctx)
	if err != nil {
		return nil, err
	}
	// Only the whole rule set is worth keeping on disk: a prefiltered subset
	// differs per scanned unit.
	// opengrep-core silences a match when a nosemgrep comment names a suffix
	// of the rule id it knows, so ids without the CLI's prefix are only safe
	// when no target has such a comment.
	useBase := coreRuleIDs(rules) && !nosem
	return s.runCore(ctx, binary, rules, plan.forLanguages(languagesOf(rules)), useBase, len(rules) == len(ruleset.rules))
}

// forLanguages keeps the targets of the given languages: the CLI plans
// targets only for the languages of the rules it runs.
func (p *targetPlan) forLanguages(langs []*language) *targetPlan {
	wanted := make(map[string]bool, len(langs))
	for _, lang := range langs {
		wanted[lang.id] = true
	}
	kept := &targetPlan{analyzers: p.analyzers, dir: p.dir}
	for _, target := range p.targets {
		if wanted[target.analyzer] {
			kept.targets = append(kept.targets, target)
		}
	}
	return kept
}

// collectCLI runs the opengrep CLI over the site's roots, one process per
// share of the command-line budget. rewriteID, when set, maps each reported
// rule id.
func (s *Scanner) collectCLI(ctx context.Context, st *site, rulePaths []string, scoped bool, rewriteID func(string) string) (*entities.SemgrepOutput, error) {
	parsed := &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}
	for _, targets := range scanner.RootTargetBatches(st.targets()) {
		batch, _, _, err := s.run(ctx, st.workDir(s), s.buildCommand(ctx, targets, rulePaths, scoped), rulePaths, nil)
		if err != nil {
			return nil, err
		}
		parsed.Results = append(parsed.Results, batch.Results...)
		parsed.Errors = append(parsed.Errors, batch.Errors...)
	}
	if rewriteID != nil {
		restoreIDs(parsed, rewriteID)
	}
	st.nameOutput(parsed)
	return parsed, nil
}

// targetInspection is what the adapter reads from the targets before the
// engine runs.
type targetInspection struct {
	// evidence is the prefilter's view of the targets, when asked for.
	evidence *prefilter.Evidence
	// nosem says some target mentions nosem, as nosemgrep comments do.
	nosem bool
}

// inspectTargets reads every target once.
func inspectTargets(plan *targetPlan, withEvidence bool) targetInspection {
	var inspection targetInspection
	if withEvidence {
		inspection.evidence = prefilter.NewEvidence()
	}
	nosem := []byte("nosem")
	for path, analyzers := range plan.analyzers {
		data, err := os.ReadFile(plan.file(path)) // #nosec G304 -- a scan target enumerated below the scan roots.
		if err != nil {
			// An unreadable target is one the engine cannot read either, but
			// its comments are unknown.
			inspection.nosem = true
			continue
		}
		if !inspection.nosem && bytes.Contains(data, nosem) {
			inspection.nosem = true
		}
		if withEvidence {
			inspection.evidence.AddFile(analyzers, data)
		}
	}
	return inspection
}

// prefilterRules keeps the rules the unit's sources may let match and logs
// the decision.
func (s *Scanner) prefilterRules(rules []*coreRule, evidence *prefilter.Evidence, roots []scanner.Root) []*coreRule {
	inputs := make([]prefilter.Rule, len(rules))
	for i, rule := range rules {
		inputs[i] = prefilter.Rule{Analyzers: rule.analyzers(), Requirement: rule.requirement()}
	}
	keep, stats := prefilter.Decide(inputs, evidence)
	kept := make([]*coreRule, 0, stats.Kept)
	for i, rule := range rules {
		if keep[i] {
			kept = append(kept, rule)
		}
	}
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		dirs = append(dirs, root.Dir)
	}
	log.Debug().
		Strs("unit", dirs).
		Int("files", evidence.Files()).
		Int("rules", stats.Total).
		Int("kept", stats.Kept).
		Int("keptUnknown", stats.Unknown).
		Int("droppedLanguage", stats.DroppedLanguage).
		Int("droppedImports", stats.DroppedImports).
		Msg("Rule prefilter (imports)")
	return kept
}

// requirement derives the rule's prefilter requirement, once.
func (r *coreRule) requirement() prefilter.Expr {
	r.requirementOnce.Do(func() {
		body := r.body()
		if body == nil || r.langs == nil {
			r.req = prefilter.True
			return
		}
		r.req = prefilter.Requirement(body, r.analyzers())
	})
	return r.req
}

// writePrefilteredRules writes rules to one rules file for the CLI, each id
// behind prefilteredIDMarker.
func writePrefilteredRules(rules []*coreRule) (string, func(), error) {
	dir, err := os.MkdirTemp("", "crypto-finder-prefilter-*")
	if err != nil {
		return "", nil, fmt.Errorf("opengrep: create prefiltered rules dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) } //nolint:errcheck // Best-effort temp cleanup.
	var doc bytes.Buffer
	doc.WriteString("{\"rules\":[\n")
	for i, rule := range rules {
		raw, err := rule.prefixedRaw(prefilteredIDMarker)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if i > 0 {
			doc.WriteString(",\n")
		}
		doc.Write(raw)
	}
	doc.WriteString("\n]}\n")
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("opengrep: write prefiltered rules: %w", err)
	}
	return path, cleanup, nil
}

// restorePrefilteredID cuts the prefiltered file's prefix and the marker
// from a check_id.
func restorePrefilteredID(checkID string) string {
	if i := strings.Index(checkID, prefilteredIDMarker); i >= 0 {
		return checkID[i+len(prefilteredIDMarker):]
	}
	return checkID
}

// processEnv is the environment OpenGrep runs with.
func (s *Scanner) processEnv() []string {
	return append(os.Environ(), mapToEnvSlice(s.env)...)
}

// fallbackWarned limits the core mode unavailability warning to once per
// reason and process: dependency scans would repeat it for every batch.
var fallbackWarned sync.Map

// fallback logs why the planned scan gives way to the CLI. In core mode a
// failed opengrep-core run warns every time, since the scan then runs
// twice; core mode being unavailable warns once; prefilter-only fallbacks
// are debug details.
func (s *Scanner) fallback(reason string, err error) {
	event := log.Debug()
	if s.mode == scanner.OpengrepModeCore {
		key := reason
		if errors.Is(err, errCoreUnavailable) {
			key += ": " + err.Error()
		}
		if _, seen := fallbackWarned.LoadOrStore(key, true); !seen || !errors.Is(err, errCoreUnavailable) {
			event = log.Warn()
		}
	}
	event.Err(err).Str("mode", s.mode.String()).Str("prefilter", s.prefilter.String()).Msg("OpenGrep " + reason + "; running the opengrep CLI instead")
}
