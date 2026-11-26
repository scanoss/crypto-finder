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

package cardmatch

import (
	"fmt"
	"sort"
)

// Explanation says, for one rule and one source line, what the index pass
// (matchIndex) does with each of the rule's entries at each call site of
// the line: the stage that rejected the site, or that it reports a finding.
// A triage aid for fidelity work (go-port audit F7).
type Explanation struct {
	Rule string `json:"rule"`
	File string `json:"file"`
	Line int    `json:"line"`
	// HandCard: the rule has a hand card, which replaces its entries in a
	// scan; the steps still show what the entries would do.
	HandCard bool          `json:"hand_card"`
	Entries  int           `json:"entries"`
	Steps    []ExplainStep `json:"steps"`
	// Sites are the call sites of the file near the line, when none is on
	// it (`line: method`).
	Nearby []string `json:"nearby,omitempty"`
}

// ExplainStep is one entry at one site: the stage that decided, whether
// the site passed it, and what the stage saw.
type ExplainStep struct {
	Entry   int    `json:"entry"`
	Pattern string `json:"pattern"`
	Site    string `json:"site"`
	Stage   string `json:"stage"`
	Finding bool   `json:"finding"`
	Detail  string `json:"detail,omitempty"`
}

// Stages of the index pass, in the order matchIndex runs them.
const (
	stageCall        = "call"
	stageConstraints = "constraints"
	stageInsides     = "insides"
	stageNotInside   = "not_inside"
	stageNotCalls    = "not_calls"
	stageTaint       = "taint"
	stageReported    = "reported"
	stageConstant    = "constant"
)

// Explain runs the index pass of Match for one rule on the call sites the
// fragment holds at file:line, stage by stage.
func (a *Assets) Explain(frag *FragmentJSON, rule, file string, line int) (*Explanation, error) {
	matching.Lock()
	defer matching.Unlock()
	fr, err := a.indexPassFrag(frag)
	if err != nil {
		return nil, err
	}
	out := &Explanation{Rule: rule, File: file, Line: line, HandCard: a.cards.RuleIDs[rule]}
	entries := a.indexPassEntries(rule)
	out.Entries = len(entries)
	if len(entries) == 0 && !out.HandCard {
		return nil, fmt.Errorf("cardmatch: rule %s has no compiled entry and no hand card", rule)
	}
	var sites []*Site
	for _, s := range fr.Sites {
		if s.File == file && s.Line == line {
			sites = append(sites, s)
		}
	}
	if len(sites) == 0 {
		out.Nearby = fr.nearbySites(file, line)
	}
	for i, e := range entries {
		if e.Receiver == strConstant {
			// Matched against constant references (matchConstantEntries),
			// not call sites: not explained here.
			out.Steps = append(out.Steps, ExplainStep{Entry: i, Pattern: e.Pattern, Stage: stageConstant, Detail: "a constant entry, matched against constant references; not explained"})
			continue
		}
		for _, s := range sites {
			out.Steps = append(out.Steps, explainSite(i, e, s, fr))
		}
	}
	return out, nil
}

// indexPassEntries are the rule's entries Match gives the index pass (a
// hand card aside: Explanation flags it).
func (a *Assets) indexPassEntries(rule string) []*Entry {
	var out []*Entry
	for _, e := range a.index.Entries {
		if e.RuleID == rule && e.Callee == nil && e.Rust == nil && e.C == nil {
			out = append(out, e)
		}
	}
	return out
}

// indexPassFrag reads the fragment as Match reads one it gives the index
// pass; an error for a fragment another matcher decides.
func (a *Assets) indexPassFrag(frag *FragmentJSON) (*Frag, error) {
	if frag.c() || frag.rust() {
		return nil, fmt.Errorf("cardmatch: explain runs the index pass; a %s fragment is matched by its own matcher", frag.ScanMetadata.Ecosystem)
	}
	fr := newFrag(frag)
	if fr.Node {
		return nil, fmt.Errorf("cardmatch: explain runs the index pass; a node fragment is matched by its own matcher")
	}
	fr.ResolveParams = true
	a.opts.applyPolicies(fr)
	return fr, nil
}

// explainSite runs the stages of matchIndex for one entry at one site.
func explainSite(i int, e *Entry, s *Site, fr *Frag) ExplainStep {
	step := ExplainStep{Entry: i, Pattern: e.Pattern, Site: fmt.Sprintf("%d:%d %s (class %q, receiver %q)", s.Line, s.Col, s.Raw, s.receiverClass(), fr.receiverText(s))}
	groups := callMatches(e, s, fr)
	switch {
	case groups == nil:
		step.Stage, step.Detail = stageCall, fmt.Sprintf("method %q / receiver %s %v does not match the site", s.Method, e.Receiver, explainType(e))
		return step
	case !constraintsHold(e, s, groups, fr):
		step.Stage, step.Detail = stageConstraints, fmt.Sprintf("%d argument constraints, one fails", len(e.Constraints))
		return step
	case !insidesHold(e, s, fr):
		step.Stage, step.Detail = stageInsides, fmt.Sprintf("an origin group of %d does not hold (pattern-inside or object source)", len(e.Insides))
		return step
	case notInsideHit(e.NotInside, s, fr):
		step.Stage, step.Detail = stageNotInside, "the site is inside a pattern-not-inside call"
		return step
	}
	for _, n := range e.NotCalls {
		if callMatches(n, s, fr) != nil {
			step.Stage, step.Detail = stageNotCalls, "a pattern-not matches the site: "+n.Pattern
			return step
		}
	}
	if e.Taint && e.Flow != flowObject {
		hits := taintMatches(e, s, fr.Incoming, fr.ResolveParams)
		if len(hits) == 0 {
			step.Stage, step.Detail = stageTaint, "no taint source reaches an argument"
			return step
		}
		step.Detail = fmt.Sprintf("taint: %s %s", hits[0].How, hits[0].Value)
	}
	step.Stage, step.Finding = stageReported, true
	return step
}

// explainType is an entry's callee type as compiled, for the detail text.
func explainType(e *Entry) string {
	if e.Type == nil {
		return "(any type)"
	}
	return *e.Type
}

// nearbySites lists the call sites of the file within three lines of line.
func (fr *Frag) nearbySites(file string, line int) []string {
	var out []string
	for _, s := range fr.Sites {
		if s.File == file && s.Line >= line-3 && s.Line <= line+3 {
			out = append(out, fmt.Sprintf("%d: %s", s.Line, s.Raw))
		}
	}
	sort.Strings(out)
	return out
}
