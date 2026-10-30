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
	// minRetryBudget and retryBudgetFactor bound the time all retry rounds
	// of a scan take together: twice the first pass, and at least 2 min. A
	// file where OpenGrep gave up reruns every rule of the scan, which on a
	// few large generated files takes far longer than the first pass did.
	minRetryBudget    = 2 * time.Minute
	retryBudgetFactor = 2
	// minRetryReserve and retryReserveDivisor keep part of the time the
	// scan's own deadline leaves free of the retry: a tenth of it, and at
	// least 1 min, for the work after the scan (the CBOM, the callgraph and
	// the graph fragment), which a retry running to the deadline would fail.
	minRetryReserve     = time.Minute
	retryReserveDivisor = 10
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

// retryRuleTimeouts are the per-rule limits of the retry rounds: the retry's
// limit, then four times it for the files the first round still could not
// finish. A large C++ file can take over a minute to parse on a very busy
// host.
func (s *Scanner) retryRuleTimeouts() []int {
	first := s.retryRuleTimeout()
	if second := min(first*retryTimeoutFactor, 255); second > first {
		return []int{first, second}
	}
	return []int{first}
}

// retryTimeouts runs again the rules that hit OpenGrep's time limit on a
// file, with a longer limit, and adds the matches they find; what still hits
// it runs once more with a longer limit again (retryRuleTimeouts). A rule
// timing out depends on the host's load rather than on the code: the same
// rule on the same file finishes in milliseconds on an idle host and
// overruns 5 s when the host is busy, so without a retry a busy scan
// silently reports fewer findings. A file where OpenGrep gave up after
// cliTimeoutThreshold timeouts, or whose parse the limit interrupted, runs
// every rule of the scan again, since the rules it skipped report nothing.
// ran is the rules the scan ran; nil loads them from rulePaths. firstPass
// is how long the scan took, which sizes the retry's budget (retryBudget).
// A retry the scan's context stopped (a timeout or a cancellation) fails the
// scan, as the first run would have: the caller must not take the output of
// a scan that was cut short for the whole. A retry its budget stopped, or
// any other failure, keeps the output of the earlier runs: the timeouts of
// the pairs it did not finish stand, so their files stay incomplete.
func (s *Scanner) retryTimeouts(ctx context.Context, st *site, output *entities.SemgrepOutput, ran []*coreRule, rulePaths []string, firstPass time.Duration) (*entities.SemgrepOutput, error) {
	pending := timeouts(output.Errors)
	if len(pending) == 0 {
		return output, nil
	}
	floor := s.minRetryBudget
	if floor == 0 {
		floor = minRetryBudget
	}
	deadline, _ := ctx.Deadline() // Without one, the zero time.
	budget, ok := retryBudget(firstPass, floor, deadline, time.Now())
	if !ok {
		log.Warn().Int("files", len(pending)).Msg("OpenGrep rule timeouts are not retried: the scan's deadline leaves no time")
		return output, nil
	}
	retryCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if ran == nil {
		var err error
		if ran, err = s.loadRan(rulePaths); err != nil {
			log.Debug().Err(err).Msg("OpenGrep rule timeouts cannot be retried: rules unreadable")
			return output, nil
		}
	}
	for round, limit := range s.retryRuleTimeouts() {
		plan := planRetry(pending, ran)
		if len(plan.files) == 0 {
			break
		}
		started := time.Now()
		retried, err := s.runRetry(retryCtx, st, plan, limit)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if retryCtx.Err() != nil {
				log.Warn().Dur("budget", budget).Strs("files", plan.files).Msg("Retrying OpenGrep rule timeouts ran out of time; keeping the findings of the earlier runs")
				break
			}
			log.Warn().Err(err).Int("files", len(plan.files)).Msg("Retrying OpenGrep rule timeouts failed; keeping the findings of the earlier runs")
			break
		}
		merged, recovered, still := mergeRetry(output, retried, plan)
		log.Info().
			Int("round", round+1).
			Int("files", len(plan.files)).
			Int("rules", len(plan.rules)).
			Int("timeoutSeconds", limit).
			Int("recoveredFindings", recovered).
			Int("stillTimedOut", still).
			Dur("duration", time.Since(started)).
			Msg("Retried OpenGrep rule timeouts")
		output = merged
		if still == 0 {
			break
		}
		pending = within(timeouts(output.Errors), plan.files)
	}
	return output, nil
}

// loadRan reads the rules of rulePaths as the scan ran them.
func (s *Scanner) loadRan(rulePaths []string) ([]*coreRule, error) {
	cwd, err := physicalDir(s.workDir)
	if err != nil {
		return nil, err
	}
	ruleset, err := loadCoreRuleset(rulePaths, cwd)
	if err != nil {
		return nil, err
	}
	return ruleset.rules, nil
}

// retryBudget is the time the retry rounds of a scan whose first pass took
// firstPass may take: retryBudgetFactor times it, and at least floor. A
// non-zero deadline caps it to keep the reserve free (minRetryReserve); ok
// is false when the time left is the reserve or less: there is no retry.
func retryBudget(firstPass, floor time.Duration, deadline, now time.Time) (budget time.Duration, ok bool) {
	budget = max(floor, retryBudgetFactor*firstPass)
	if deadline.IsZero() {
		return budget, true
	}
	left := deadline.Sub(now)
	reserve := max(left/retryReserveDivisor, minRetryReserve)
	if left <= reserve {
		return 0, false
	}
	return min(budget, left-reserve), true
}

// within keeps the files of pending that files lists.
func within(pending timedOut, files []string) timedOut {
	kept := make(timedOut, len(files))
	for _, path := range files {
		if ids, ok := pending[path]; ok {
			kept[path] = ids
		}
	}
	return kept
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

// runRetry runs the CLI over the plan with the per-rule limit timeout, where
// the first run ran. The rules go through a prefiltered rules file, so
// results keep the ids of the first run.
func (s *Scanner) runRetry(ctx context.Context, st *site, plan *retryPlan, timeout int) (*entities.SemgrepOutput, error) {
	path, cleanup, err := writePrefilteredRules(plan.rules)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	retry := *s
	retry.ruleTimeout = uint8(timeout) //nolint:gosec // retryRuleTimeouts caps at 255.
	if int(retry.jobs) > len(plan.files) {
		retry.jobs = int16(len(plan.files)) //nolint:gosec // Bounded by jobs.
	}
	files := make([]string, len(plan.files))
	for i, file := range plan.files {
		files[i] = st.relative(file)
	}
	// The files were scan targets already, so named-file excludes keep them.
	out, _, _, err := retry.run(ctx, st.workDir(s), retry.buildCommand(ctx, files, []string{path}, true), []string{path}, nil)
	if err != nil {
		return nil, err
	}
	restoreIDs(out, restorePrefilteredID)
	st.nameOutput(out)
	return out, nil
}

// mergeRetry adds the retry's new matches of the planned pairs to output
// and replaces the Timeout errors of those pairs by the retry's. A planned
// file the retry's output names nowhere, neither among its scanned paths
// nor in a result or an error, keeps its errors: the CLI did not scan it (a
// file it skipped or could not read), so its limit errors still stand and
// the file stays incomplete. It returns the merged output, the matches it
// added and the pairs still timed out.
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
	named := make(map[string]bool, len(plan.files))
	if retried.Paths != nil {
		for _, path := range retried.Paths.Scanned {
			named[path] = true
		}
	}
	for i := range retried.Errors {
		named[retried.Errors[i].Path] = true
	}
	merged = &entities.SemgrepOutput{Results: slices.Clone(output.Results)}
	for i := range retried.Results {
		r := &retried.Results[i]
		named[r.Path] = true
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
			if named[e.Path] {
				continue
			}
			still++
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
