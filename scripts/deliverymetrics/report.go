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

package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// inputs is everything the weekly rows are computed from.
type inputs struct {
	prs      []pull
	costs    map[int]map[string]float64 // CI seconds per phase of the costed PRs
	qa       map[int]qaPR
	reverted map[int]time.Time
	red      []issue
	audits   []comment
}

// week is one row of the report. A nil pointer is a metric with no input.
type week struct {
	Week                string             `json:"week"`
	Merged              int                `json:"merged"`
	Costed              int                `json:"costed"`
	CIMinutesPerPR      *float64           `json:"ci_minutes_per_pr"`
	CIMinutesByWorkflow map[string]float64 `json:"ci_minutes_by_workflow"`
	QAPRs               int                `json:"qa_prs"`
	QANoData            int                `json:"qa_no_data"`
	QATurnsPerPR        *float64           `json:"qa_turns_per_pr"`
	QATokensPerPR       *float64           `json:"qa_tokens_per_pr"`
	QAEstimatedUSDPerPR *float64           `json:"qa_estimated_usd_per_pr"`
	QAUnpriced          int                `json:"qa_unpriced"`
	Reverted            []int              `json:"reverted"`
	RevertRate          *float64           `json:"revert_rate"`
	MedianHoursToRevert *float64           `json:"median_hours_to_revert"`
	RedMainIssues       int                `json:"red_main_issues"`
	MedianHoursRed      *float64           `json:"median_hours_red"`
	MergedBeforeGreen   int                `json:"merged_before_green"`
}

// weekly computes n rows, one per week from start (a Monday, UTC).
func weekly(in inputs, start time.Time, n int) []week {
	rows := make([]week, 0, n)
	for i := range n {
		lo := start.AddDate(0, 0, 7*i)
		hi := lo.AddDate(0, 0, 7)
		inside := func(t time.Time) bool { return !t.Before(lo) && t.Before(hi) }
		var merged []*pull
		for j := range in.prs {
			if p := &in.prs[j]; p.MergedAt != nil && inside(*p.MergedAt) {
				merged = append(merged, p)
			}
		}
		w := week{Week: lo.Format(time.DateOnly), Merged: len(merged), Reverted: []int{}}
		w.ci(merged, in.costs)
		w.qaUsage(merged, in.qa)
		w.revertRate(merged, in.reverted)
		w.redMain(in, inside)
		rows = append(rows, w)
	}
	return rows
}

func (w *week) redMain(in inputs, inside func(time.Time) bool) {
	var hoursRed []float64
	for _, r := range in.red {
		if inside(r.CreatedAt) {
			w.RedMainIssues++
			if r.ClosedAt != nil {
				hoursRed = append(hoursRed, r.ClosedAt.Sub(r.CreatedAt).Hours())
			}
		}
	}
	w.MedianHoursRed = median(hoursRed)
	for i := range in.audits {
		if inside(in.audits[i].CreatedAt) {
			w.MergedBeforeGreen++
		}
	}
}

func (w *week) ci(merged []*pull, costs map[int]map[string]float64) {
	w.CIMinutesByWorkflow = map[string]float64{}
	var costed []map[string]float64
	for _, p := range merged {
		if c, ok := costs[p.Number]; ok {
			costed = append(costed, c)
		}
	}
	w.Costed = len(costed)
	if len(costed) == 0 {
		return
	}
	// Seconds are summed before dividing, so the result is the same in any
	// map order.
	total := 0.0
	for _, c := range costed {
		for name, seconds := range c {
			w.CIMinutesByWorkflow[name] += seconds
			total += seconds
		}
	}
	perPR := func(seconds float64) float64 { return round(seconds/60/float64(len(costed)), 1) }
	for name, s := range w.CIMinutesByWorkflow {
		w.CIMinutesByWorkflow[name] = perPR(s)
	}
	w.CIMinutesPerPR = ptr(perPR(total))
}

// qaUsage averages turns and tokens over the PRs whose QA left usage, and the
// estimate over the PRs whose every QA run was priced.
func (w *week) qaUsage(merged []*pull, qa map[int]qaPR) {
	var withData, priced int
	var turns, tokens, usd float64
	for _, p := range merged {
		q, ok := qa[p.Number]
		if !ok || q.Comments == 0 {
			continue
		}
		w.QAPRs++
		if q.Runs == 0 {
			w.QANoData++
			continue
		}
		withData++
		turns += float64(q.Turns)
		tokens += float64(q.Tokens)
		if q.Unpriced > 0 {
			w.QAUnpriced++
			continue
		}
		priced++
		usd += q.USD
	}
	if withData > 0 {
		w.QATurnsPerPR = ptr(round(turns/float64(withData), 1))
		w.QATokensPerPR = ptr(math.Round(tokens / float64(withData)))
	}
	if priced > 0 {
		w.QAEstimatedUSDPerPR = ptr(round(usd/float64(priced), 4))
	}
}

func (w *week) revertRate(merged []*pull, reverted map[int]time.Time) {
	var hours []float64
	for _, p := range merged {
		if at, ok := reverted[p.Number]; ok {
			w.Reverted = append(w.Reverted, p.Number)
			hours = append(hours, at.Sub(*p.MergedAt).Hours())
		}
	}
	sort.Ints(w.Reverted)
	if len(merged) > 0 {
		w.RevertRate = ptr(round(float64(len(w.Reverted))/float64(len(merged)), 3))
	}
	w.MedianHoursToRevert = median(hours)
}

func median(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return ptr(round(m, 1))
}

func round(x float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(x*p) / p
}

func ptr[T any](v T) *T { return &v }

// report is the whole output: the rows and how they were measured.
type report struct {
	Repo      string    `json:"repo"`
	Start     string    `json:"start"`
	Weeks     int       `json:"weeks"` // per window; the rows are 2*Weeks
	Sample    int       `json:"sample"`
	Reserve   int       `json:"reserve"`
	NotCosted []skipped `json:"not_costed"`
	Rows      []week    `json:"rows"`
}

// skipped is a sampled PR left out of the CI cost, and why.
type skipped struct {
	PR     int    `json:"pr"`
	Reason string `json:"reason"`
}

// markdown renders the report as the issue body's tables.
func markdown(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The last %d weeks (from %s) against the %d before them; the current week is partial. "+
		"CI cost is sampled: up to %d merged PRs a week, evenly spaced by number, and \"costed\" counts the PRs measured. "+
		"Costing stops while fewer than %d API requests are left.\n\n", r.Weeks, r.Rows[r.Weeks].Week, r.Weeks, r.Sample, r.Reserve)
	b.WriteString("| Week (Mon) | Merged PRs | CI min/PR (costed) | QA PRs (no data) | QA turns/PR | QA tokens/PR | QA est. $/PR | Reverted | Revert rate | Median h to revert | Red-main issues | Median h red | Merged before green |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for i := range r.Rows {
		w := &r.Rows[i]
		if i == r.Weeks {
			b.WriteString("| **window starts** | | | | | | | | | | | | |\n")
		}
		fmt.Fprintf(&b, "| %s | %d | %s (%d) | %d (%d) | %s | %s | %s | %s | %s | %s | %d | %s | %d |\n",
			w.Week, w.Merged, cell(w.CIMinutesPerPR, "%.1f"), w.Costed, w.QAPRs, w.QANoData,
			qaCell(w.QATurnsPerPR), qaTokens(w), qaUSD(w), prList(w.Reverted),
			percent(w.RevertRate), cell(w.MedianHoursToRevert, "%.1f"), w.RedMainIssues,
			cell(w.MedianHoursRed, "%.1f"), w.MergedBeforeGreen)
	}
	b.WriteString("\nQA est. $ is Claude Code's own `cost_usd` estimate: the QA runs on the Claude seat, which bills nothing per run, so it is a comparable signal, not an invoice. " +
		"\"no data\" is a QA comment without usage, and \"unpriced\" a run without an estimate; neither is $0.\n")
	if len(r.NotCosted) > 0 {
		parts := make([]string, 0, len(r.NotCosted))
		for _, s := range r.NotCosted {
			parts = append(parts, fmt.Sprintf("#%d (%s)", s.PR, s.Reason))
		}
		b.WriteString("\nSampled but not costed: " + strings.Join(parts, ", ") + ".\n")
	}
	workflowTable(&b, r.Rows)
	return b.String()
}

func workflowTable(b *strings.Builder, rows []week) {
	names := map[string]bool{}
	for i := range rows {
		w := &rows[i]
		for n := range w.CIMinutesByWorkflow {
			names[n] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	b.WriteString("\nCI minutes per costed PR, by workflow and phase (runner time of merged PRs only; " +
		"a renamed workflow starts a new row, so compare totals across a rename):\n\n| Workflow |")
	for i := range rows {
		w := &rows[i]
		b.WriteString(" " + w.Week + " |")
	}
	b.WriteString("\n|---|" + strings.Repeat("---|", len(rows)) + "\n")
	for _, n := range sorted {
		b.WriteString("| " + n + " |")
		for i := range rows {
			w := &rows[i]
			if m, ok := w.CIMinutesByWorkflow[n]; ok {
				fmt.Fprintf(b, " %.1f |", m)
			} else {
				b.WriteString(" n/a |")
			}
		}
		b.WriteString("\n")
	}
}

// noData is a QA metric without input, never shown as 0 or $0.
const noData = "no data"

// cell formats v, or "n/a" when there was nothing to compute it from.
func cell(v *float64, format string) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf(format, *v)
}

func percent(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", *v*100)
}

func qaCell(v *float64) string {
	if v == nil {
		return noData
	}
	return fmt.Sprintf("%.1f", *v)
}

func qaTokens(w *week) string {
	if w.QATokensPerPR == nil {
		return noData
	}
	t := *w.QATokensPerPR
	switch {
	case t >= 1e6:
		return fmt.Sprintf("%.1fM", t/1e6)
	case t >= 1e3:
		return fmt.Sprintf("%.0fk", t/1e3)
	default:
		return fmt.Sprintf("%.0f", t)
	}
}

func qaUSD(w *week) string {
	var s string
	switch {
	case w.QAEstimatedUSDPerPR != nil:
		s = fmt.Sprintf("~$%.3f", *w.QAEstimatedUSDPerPR)
	case w.QAUnpriced > 0:
		s = "unpriced"
	default:
		return noData
	}
	if w.QAUnpriced > 0 && w.QAEstimatedUSDPerPR != nil {
		s += fmt.Sprintf(" (%d unpriced)", w.QAUnpriced)
	}
	return s
}

func prList(ns []int) string {
	if len(ns) == 0 {
		return "0"
	}
	parts := make([]string, 0, len(ns))
	for _, n := range ns {
		parts = append(parts, fmt.Sprintf("#%d", n))
	}
	return strings.Join(parts, ", ")
}
