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
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	// cliDefaultRuleTimeoutSeconds is OpenGrep's own limit per rule and file.
	cliDefaultRuleTimeoutSeconds = 5
	// cliTimeoutThreshold is the number of timed-out rules after which
	// OpenGrep skips the remaining rules of a file.
	cliTimeoutThreshold = 3
	// minRetryRuleTimeoutSeconds and retryTimeoutFactor size the limit of
	// the retry: four times the scan's own, and at least 30 s.
	minRetryRuleTimeoutSeconds = 30
	retryTimeoutFactor         = 4
	// maxRetryFiles bounds the retry: a scan whose limits cut short more
	// files than this retries the first ones in path order.
	maxRetryFiles    = 64
	timeoutErrorType = "Timeout"
	// parseInterrupted is in the message of the syntax error OpenGrep reports,
	// naming no rule, when a time limit stopped the parse of a file: no rule
	// ran on it. Parsing counts against the first rule's limit, and a large C
	// or C++ file takes seconds to parse on a busy host.
	parseInterrupted = "Memprof_limits.Limit_reached"
)

// timedOut is the files a rule timed out on, with the rules per file. A file
// whose parse a time limit interrupted has no rules: all of them must run.
type timedOut map[string]map[string]bool

// timeouts collects the Timeout errors of output by file and rule, and the
// files whose parse a time limit interrupted.
func timeouts(errs []entities.SemgrepError) timedOut {
	out := timedOut{}
	interrupted := map[string]bool{}
	for i := range errs {
		e := &errs[i]
		if interruptedParse(e) {
			interrupted[e.Path] = true
			out[e.Path] = map[string]bool{}
			continue
		}
		if e.Path == "" || e.RuleID == "" || errorTypeName(e.Type) != timeoutErrorType || interrupted[e.Path] {
			continue
		}
		if out[e.Path] == nil {
			out[e.Path] = map[string]bool{}
		}
		out[e.Path][e.RuleID] = true
	}
	return out
}

// interruptedParse reports whether e is the error of a parse a time limit
// stopped.
func interruptedParse(e *entities.SemgrepError) bool {
	return e.Path != "" && e.RuleID == "" && strings.Contains(e.Message, parseInterrupted)
}

// retriedError reports whether e is a limit error of a pair or file plan
// reruns, which the retry's own errors replace.
func retriedError(e *entities.SemgrepError, plan *retryPlan) bool {
	if errorTypeName(e.Type) == timeoutErrorType {
		return plan.covers(e.Path, e.RuleID)
	}
	return plan.whole[e.Path] && interruptedParse(e)
}

// errorTypeName is the name of an error type, which the CLI writes as a
// string or as [name, locations].
func errorTypeName(errorType any) string {
	switch t := errorType.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			name, _ := t[0].(string) //nolint:errcheck // A non-string name is no Timeout.
			return name
		}
	}
	return ""
}

// retryRuleTimeout is the per-rule limit of the retry.
func (s *Scanner) retryRuleTimeout() int {
	base := int(s.ruleTimeout)
	if base == 0 {
		base = cliDefaultRuleTimeoutSeconds
	}
	return min(max(base*retryTimeoutFactor, minRetryRuleTimeoutSeconds), 255)
}

// retryTimeouts runs again, once, the rules that hit OpenGrep's time limit
// on a file, with a longer limit, and adds the matches they find. A rule
// timing out depends on the host's load rather than on the code: the same
// rule on the same file finishes in milliseconds on an idle host and
// overruns 5 s when the host is busy, so without a retry a busy scan
// silently reports fewer findings. A file where OpenGrep gave up after
// cliTimeoutThreshold timeouts, or whose parse the limit interrupted, runs
// every rule of the scan again, since the rules it skipped report nothing.
// ran is the rules the scan ran; nil loads them from rulePaths. Any failure
// keeps the output as it was.
func (s *Scanner) retryTimeouts(ctx context.Context, output *entities.SemgrepOutput, ran []*coreRule, rulePaths []string) *entities.SemgrepOutput {
	pending := timeouts(output.Errors)
	if len(pending) == 0 {
		return output
	}
	if ran == nil {
		cwd, err := physicalDir(s.workDir)
		if err == nil {
			var ruleset *coreRuleset
			ruleset, err = loadCoreRuleset(rulePaths, cwd)
			if err == nil {
				ran = ruleset.rules
			}
		}
		if err != nil {
			log.Debug().Err(err).Msg("OpenGrep rule timeouts cannot be retried: rules unreadable")
			return output
		}
	}
	plan := planRetry(pending, ran)
	if len(plan.files) == 0 {
		return output
	}
	started := time.Now()
	retried, err := s.runRetry(ctx, plan)
	if err != nil {
		log.Warn().Err(err).Int("files", len(plan.files)).Msg("Retrying OpenGrep rule timeouts failed; keeping the findings of the first run")
		return output
	}
	merged, recovered, still := mergeRetry(output, retried, plan)
	log.Info().
		Int("files", len(plan.files)).
		Int("rules", len(plan.rules)).
		Int("timeoutSeconds", s.retryRuleTimeout()).
		Int("recoveredFindings", recovered).
		Int("stillTimedOut", still).
		Dur("duration", time.Since(started)).
		Msg("Retried OpenGrep rule timeouts")
	return merged
}

// retryPlan is what a retry runs: rules over files, and the pairs whose
// results and errors it replaces.
type retryPlan struct {
	files []string
	rules []*coreRule
	// whole marks the files that rerun every rule; the others rerun the
	// rules of pairs.
	whole map[string]bool
	pairs timedOut
}

func (p *retryPlan) covers(path, ruleID string) bool {
	return p.whole[path] || p.pairs[path][ruleID]
}

func planRetry(pending timedOut, ran []*coreRule) *retryPlan {
	byID := make(map[string]*coreRule, len(ran))
	for _, rule := range ran {
		byID[rule.id] = rule
	}
	files := make([]string, 0, len(pending))
	for path := range pending {
		files = append(files, path)
	}
	slices.Sort(files)
	if len(files) > maxRetryFiles {
		log.Warn().Int("files", len(files)).Int("retried", maxRetryFiles).Msg("OpenGrep rules timed out on many files; retrying the first ones only")
		files = files[:maxRetryFiles]
	}
	plan := &retryPlan{whole: map[string]bool{}, pairs: timedOut{}}
	wanted := map[string]bool{}
	for _, path := range files {
		plan.add(path, pending[path], byID, ran, wanted)
	}
	for _, rule := range ran {
		if wanted[rule.id] {
			plan.rules = append(plan.rules, rule)
			wanted[rule.id] = false
		}
	}
	return plan
}

// add plans the retry of path, where the rules ids timed out, and marks the
// rules it needs in wanted. Rules the scan did not run are skipped. No ids
// means the parse was interrupted, so every rule runs again.
func (p *retryPlan) add(path string, ids map[string]bool, byID map[string]*coreRule, ran []*coreRule, wanted map[string]bool) {
	if len(ids) == 0 || len(ids) >= cliTimeoutThreshold {
		p.whole[path] = true
		p.files = append(p.files, path)
		for _, rule := range ran {
			wanted[rule.id] = true
		}
		return
	}
	for id := range ids {
		if byID[id] == nil {
			continue
		}
		wanted[id] = true
		if p.pairs[path] == nil {
			p.pairs[path] = map[string]bool{}
		}
		p.pairs[path][id] = true
	}
	if p.pairs[path] != nil {
		p.files = append(p.files, path)
	}
}

// runRetry runs the CLI over the plan with the retry's limit. The rules go
// through a prefiltered rules file, so results keep the ids of the first run.
func (s *Scanner) runRetry(ctx context.Context, plan *retryPlan) (*entities.SemgrepOutput, error) {
	path, cleanup, err := writePrefilteredRules(plan.rules)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	retry := *s
	retry.ruleTimeout = uint8(s.retryRuleTimeout()) //nolint:gosec // retryRuleTimeout caps at 255.
	if int(retry.jobs) > len(plan.files) {
		retry.jobs = int16(len(plan.files)) //nolint:gosec // Bounded by jobs.
	}
	// The files were scan targets already, so named-file excludes keep them.
	out, _, _, err := retry.run(ctx, retry.buildCommand(ctx, plan.files, []string{path}, true), []string{path}, nil)
	if err != nil {
		return nil, err
	}
	restoreIDs(out, restorePrefilteredID)
	return out, nil
}

// mergeRetry adds the retry's new matches of the planned pairs to output
// and replaces the Timeout errors of those pairs by the retry's. It returns
// the merged output, the matches it added and the pairs still timed out.
func mergeRetry(output, retried *entities.SemgrepOutput, plan *retryPlan) (merged *entities.SemgrepOutput, recovered, still int) {
	type matchKey struct {
		checkID, path string
		start, end    int
	}
	keyOf := func(r *entities.SemgrepResult) matchKey {
		return matchKey{r.CheckID, r.Path, r.Start.Offset, r.End.Offset}
	}
	seen := make(map[matchKey]bool, len(output.Results))
	for i := range output.Results {
		seen[keyOf(&output.Results[i])] = true
	}
	merged = &entities.SemgrepOutput{Results: slices.Clone(output.Results)}
	for i := range retried.Results {
		r := &retried.Results[i]
		if !plan.covers(r.Path, r.CheckID) || seen[keyOf(r)] {
			continue
		}
		seen[keyOf(r)] = true
		merged.Results = append(merged.Results, *r)
		recovered++
	}
	if recovered > 0 {
		sortLikeCLI(merged.Results)
	}
	merged.Errors = make([]entities.SemgrepError, 0, len(output.Errors))
	for i := range output.Errors {
		e := &output.Errors[i]
		if retriedError(e, plan) {
			continue
		}
		merged.Errors = append(merged.Errors, *e)
	}
	for i := range retried.Errors {
		e := &retried.Errors[i]
		if retriedError(e, plan) {
			merged.Errors = append(merged.Errors, *e)
			still++
		}
	}
	return merged, recovered, still
}

// restoreIDs maps the rule ids of output's results and errors.
func restoreIDs(output *entities.SemgrepOutput, rewriteID func(string) string) {
	for i := range output.Results {
		output.Results[i].CheckID = rewriteID(output.Results[i].CheckID)
	}
	for i := range output.Errors {
		if output.Errors[i].RuleID != "" {
			output.Errors[i].RuleID = rewriteID(output.Errors[i].RuleID)
		}
	}
}
