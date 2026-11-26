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

// The node (JavaScript/TypeScript) pass: matchIndex for a node fragment.
// A site is a call of an entry's callee (calleeHolds), its arguments unify
// with the entry's argument pattern (jspat), the constraints hold over the
// bindings, no not_calls pattern unifies and the file imports none of
// not_imports. Findings are built as matchIndex builds them (newFinding).

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/cardmatch/internal/jspat"
)

// maxProducerDepth bounds how many producers an object callee follows.
const maxProducerDepth = 4

// nodeIndex is the node entries arranged for the one question a site asks:
// which entries can name me.
type nodeIndex struct {
	pos map[*Entry]int // an entry's place in the index: candidates keep index order
	// byKey: the full callee key of every import and global entry with a
	// fixed path, one per module.
	byKey map[string][]*Entry
	// written: callee text ("new " prefixed for a `new`) -> written entries.
	written map[string][]*Entry
	// byMethod: method name -> path-regex entries whose method is fixed,
	// and object entries.
	byMethod map[string][]*Entry
	// anyMethod: path-regex entries whose method is a metavariable.
	anyMethod []*Entry
	// text: text entries, a candidate of every site.
	text []*Entry
	// literal: literal entries, the candidates of every object literal site
	// (and of no call).
	literal []*Entry
	// instance: method name -> import entries keyed on an instance with a
	// property chain after the class (`m.(C).utils.f`), candidates of
	// unbound sites (instanceHolds).
	instance map[string][]*Entry
}

// buildNodeIndex indexes the node entries of entries (those with a callee).
func buildNodeIndex(entries []*Entry) *nodeIndex {
	ix := &nodeIndex{
		pos: map[*Entry]int{}, byKey: map[string][]*Entry{}, written: map[string][]*Entry{}, byMethod: map[string][]*Entry{},
		instance: map[string][]*Entry{},
	}
	for i, e := range entries {
		if e.Callee == nil {
			continue
		}
		ix.pos[e] = i
		e.prepareNode()
		c := e.Callee
		switch {
		case c.Bind == BindWritten:
			k := c.writtenKey()
			ix.written[k] = append(ix.written[k], e)
		case c.Bind == BindText:
			ix.text = append(ix.text, e)
		case c.Bind == BindLiteral:
			ix.literal = append(ix.literal, e)
		case c.Bind == BindObject:
			ix.byMethod[c.Path] = append(ix.byMethod[c.Path], e)
		case c.Path != "":
			for k := range c.keySet {
				ix.byKey[k] = append(ix.byKey[k], e)
			}
			if _, rest, ok := strings.Cut(c.Path, ")."); ok && c.Bind == BindImport && !c.New {
				m := rest[strings.LastIndexByte(rest, '.')+1:]
				ix.instance[m] = append(ix.instance[m], e)
			}
			for _, k := range c.moduleNameKeys() {
				ix.written[k] = append(ix.written[k], e)
			}
		case e.Method != nil:
			ix.byMethod[*e.Method] = append(ix.byMethod[*e.Method], e)
		default:
			ix.anyMethod = append(ix.anyMethod, e)
		}
	}
	return ix
}

// prepareNode parses the argument patterns of a node entry, its not_calls
// and its producers, and sets its callee's key set. The index was validated
// when it loaded, so the patterns parse.
func (e *Entry) prepareNode() {
	if e.ArgPattern != nil && e.jsArgs == nil {
		if args, err := jspat.ParseArgs(*e.ArgPattern); err == nil {
			e.jsArgs = args
		}
	}
	e.prepareNodeNested()
	e.Callee.prepareCallee()
}

// prepareNodeNested prepares the entries nested in a node entry: its
// not_calls, consumers, producers, not_producers, not_entries and within.
func (e *Entry) prepareNodeNested() {
	for _, n := range e.NotCalls {
		n.prepareNode()
	}
	for _, k := range e.Consumers {
		k.asEntry()
		for _, p := range k.Producers {
			p.prepareNode()
		}
	}
	for _, p := range e.Producers {
		p.prepareNode()
	}
	for _, p := range e.NotProducers {
		p.prepareNode()
	}
	for _, n := range e.NotEntries {
		n.prepareNode()
	}
	for _, w := range e.Within {
		w.prepareNode()
	}
}

// prepareCallee sets the callee's key set, parses its written spelling and
// prepares its from producers. A nil callee has none.
func (c *NodeCallee) prepareCallee() {
	if c == nil {
		return
	}
	if c.keySet == nil {
		c.keySet = map[string]bool{}
		for _, k := range c.keys() {
			c.keySet[k] = true
		}
	}
	if c.Written != "" && c.written == nil {
		if n, err := jspat.ParseExpr(c.Written, true); err == nil {
			c.written = n
		}
	}
	for _, f := range c.From {
		f.prepareNode()
	}
}

// writtenKey is the callee text a written callee is called with.
func (c *NodeCallee) writtenKey() string {
	if c.New {
		return "new " + c.Path
	}
	return c.Path
}

// writtenKey is the site's callee text, whitespace removed, "new " kept.
func writtenKey(raw string) string {
	if rest, ok := strings.CutPrefix(raw, "new "); ok {
		return "new " + norm(rest)
	}
	return norm(raw)
}

// candidates are the entries whose callee can be the site's, in index order.
func (ix *nodeIndex) candidates(s *Site) []*Entry {
	var out []*Entry
	out = append(out, ix.byKey[s.node.key]...)
	// OpenGrep reads a written spelling (`crypto.pbkdf2(...)` with no import
	// guard) on the text, whatever reach bound the call to.
	out = append(out, ix.written[writtenKey(s.Raw)]...)
	if s.node.unbound {
		out = append(out, ix.instance[s.Method]...)
		for _, k := range candidateKeys(s) {
			out = append(out, ix.byKey[k]...)
		}
	}
	out = append(out, ix.byMethod[s.Method]...)
	out = append(out, ix.anyMethod...)
	out = append(out, ix.text...)
	sort.SliceStable(out, func(i, j int) bool { return ix.pos[out[i]] < ix.pos[out[j]] })
	return out
}

// howSymbol is the taint hit's How for a finding matched by its symbol.
const howSymbol = "symbol"

// nodeCandidate is a site with the entries that may match it.
type nodeCandidate struct {
	s  *Site
	es []*Entry
}

// matchNodeIndex is matchIndex for a node fragment.
func matchNodeIndex(ix *nodeIndex, fr *Frag) []*Finding {
	var findings []*Finding
	seen := map[string]bool{}
	byCaller := map[string][]*Site{}
	for _, s := range fr.Sites {
		byCaller[s.Caller] = append(byCaller[s.Caller], s)
	}
	for _, c := range nodeCandidates(ix, fr) {
		for _, e := range c.es {
			findings = append(findings, entryFindings(e, c.s, fr, byCaller[c.s.Caller], seen)...)
		}
	}
	return dropSubmatches(findings)
}

// nodeCandidates are the fragment's sites, then its object literals, each
// with the entries that may match it.
func nodeCandidates(ix *nodeIndex, fr *Frag) []nodeCandidate {
	all := make([]nodeCandidate, 0, len(fr.Sites)+len(fr.NodeData.objects))
	for _, s := range fr.Sites {
		all = append(all, nodeCandidate{s, ix.candidates(s)})
	}
	for _, o := range fr.NodeData.objects {
		all = append(all, nodeCandidate{o, ix.literal})
	}
	return all
}

// entryFindings are the findings of one entry on one site (sameCaller: the
// sites of the site's caller).
func entryFindings(e *Entry, s *Site, fr *Frag, sameCaller []*Site, seen map[string]bool) []*Finding {
	var findings []*Finding
	for _, m := range nodeCalls(e, s, fr) {
		groups, env := m.groups, m.env
		if !nodeHolds(e, s, fr, env, sameCaller) {
			continue
		}
		for k, v := range producerGroups(e.Producers, s, fr, env) {
			if _, set := groups[k]; !set {
				groups[k] = v
			}
		}
		for _, h := range nodeHits(e, s, fr) {
			f := newFinding(e, reportSite(e, s, env, fr), copyGroups(groups), h, "cf", seen)
			if f == nil {
				continue
			}
			nodeFocus(f, e, s, env, fr)
			findings = append(findings, f)
		}
	}
	return findings
}

// nodeHits are the ways the site satisfies the entry once its call matched: a
// taint entry needs one of the arguments to hold a value a source regex
// matches (here or passed by a caller in the same file), any other the symbol
// or the text of its constraints.
func nodeHits(e *Entry, s *Site, fr *Frag) []taintHit {
	if e.Taint {
		return taintMatches(e, s, fr.Incoming, true)
	}
	how := howSymbol
	if len(e.Constraints) > 0 {
		how = strText
	}
	return []taintHit{{How: how}}
}

// copyGroups is a copy of g, so each hit fills its own.
func copyGroups(g Groups) Groups {
	out := make(Groups, len(g))
	for k, v := range g {
		out[k] = v
	}
	return out
}

// focusSite is s, or for a focus on a value inside an object literal or a
// call argument a copy of s at that value, so two values of one object or
// array are two findings.
func focusSite(e *Entry, s *Site, env jspat.Env, fr *Frag) *Site {
	if e.FocusMetavar == "" {
		return s
	}
	v, ok := env[e.FocusMetavar]
	if !ok || v.Node == nil {
		return s
	}
	var pos *textPos
	word := 0
	switch {
	case s.Kind == siteObjectLiteral && s.node.lit != nil:
		pos, word = s.node.lit, s.node.litWord
	case s.Kind != siteObjectLiteral && s.argIndex(v) < 0:
		// A value inside a call's argument (an array element): found in the
		// call's own source, so each element is its own finding.
		pos = fr.callSource(s)
	}
	if pos == nil {
		return s
	}
	sp, ok := pos.valueAt(word, v.Node.Text)
	if !ok {
		return s
	}
	cp := *s
	cp.Line, cp.Col = sp.line, sp.col
	return &cp
}

// nodeMatch is one way a site matches an entry's call pattern.
type nodeMatch struct {
	groups Groups
	env    jspat.Env
}

// nodeCalls are the ways the site matches the entry's call pattern. With a
// focus metavariable that can stand for an array element
// (`[..., $ALG, ...]`), OpenGrep reports each element that satisfies the
// rule: the focus is bound to each element of the arguments' arrays in turn.
// Otherwise, or when no element does, the first match.
func nodeCalls(e *Entry, s *Site, fr *Frag) []nodeMatch {
	if e.FocusMetavar != "" {
		var out []nodeMatch
		for _, el := range arrayElements(s) {
			if g, env, ok := nodeCallFrom(e, s, fr, 0, true, jspat.Env{e.FocusMetavar: {Node: el}}); ok {
				out = append(out, nodeMatch{g, env})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if g, env, ok := nodeCall(e, s, fr, 0); ok {
		return []nodeMatch{{g, env}}
	}
	return nil
}

// arrayElements are the elements of every array literal in the site's
// arguments, in source order.
func arrayElements(s *Site) []*jspat.Node {
	if s.node == nil {
		return nil
	}
	args, known := s.nodeArgs()
	if !known {
		return nil
	}
	var out []*jspat.Node
	var walk func(n *jspat.Node)
	walk = func(n *jspat.Node) {
		if n == nil {
			return
		}
		if n.Kind == jspat.Array {
			out = append(out, n.Kids...)
		}
		for _, k := range n.Kids {
			walk(k)
		}
		for _, p := range n.Props {
			walk(p.Value)
		}
	}
	for _, a := range args {
		walk(a.Node)
	}
	return out
}

// dropSubmatches removes a finding whose range lies strictly inside another
// finding of the same rule in the same file, as OpenGrep keeps only the
// outer match (an object literal a rule also matches as the call it is an
// argument of). A finding with no end column is kept.
func dropSubmatches(findings []*Finding) []*Finding {
	type key struct{ rule, file string }
	byRule := map[key][]*Finding{}
	for _, f := range findings {
		if f.EndCol > 0 && f.LineOK && f.ColOK {
			k := key{f.RuleID, f.File}
			byRule[k] = append(byRule[k], f)
		}
	}
	out := findings[:0]
	for _, f := range findings {
		inside := false
		for _, g := range byRule[key{f.RuleID, f.File}] {
			if g != f && f.EndCol > 0 && f.LineOK && f.ColOK && spanWithin(f, g) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, f)
		}
	}
	return out
}

// spanWithin: f's range is inside g's and not equal to it.
func spanWithin(f, g *Finding) bool {
	fs, fe := [2]int{f.Line, f.Col}, [2]int{max(f.EndLine, f.Line), f.EndCol}
	gs, ge := [2]int{g.Line, g.Col}, [2]int{max(g.EndLine, g.Line), g.EndCol}
	less := func(a, b [2]int) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }
	if less(fs, gs) || less(ge, fe) {
		return false
	}
	return fs != gs || fe != ge
}

// nodeHolds: what the entry asks of a site its call pattern names besides
// the call itself (negations, consumers, producers), with env the argument
// bindings.
func nodeHolds(e *Entry, s *Site, fr *Frag, env jspat.Env, callers []*Site) bool {
	return !nodeNegated(e, s) && !fr.notImportsHit(s, e.NotImports) && nodeConsumed(e, s, fr, callers) &&
		!nodeNotRegexHit(e, s) && nodeProduced(e, s, fr, env) && !nodeNotEntryHit(e, s, fr, callers) &&
		!fr.enclosed(s, e.NotEnclosed, callers) && withinHolds(e, s, fr, callers) && !notProduced(e, s, fr, env)
}

// nodeNotEntryHit: one of the entry's not_entries matches the site. A
// negation reads the call as written (no resolved constant), as not_calls do.
func nodeNotEntryHit(e *Entry, s *Site, fr *Frag, callers []*Site) bool {
	for _, n := range e.NotEntries {
		if _, env, ok := nodeCallAs(n, s, fr, 0, false); ok && nodeHolds(n, s, fr, env, callers) {
			return true
		}
	}
	return false
}

// nodeCall: the site is a call the entry's call pattern names (callee,
// arguments, constraints). It returns the fill groups (metavariable values,
// overridden by regex groups) and the argument bindings.
func nodeCall(e *Entry, s *Site, fr *Frag, depth int) (Groups, jspat.Env, bool) {
	return nodeCallAs(e, s, fr, depth, true)
}

// nodeCallAs is nodeCall reading the arguments as written only (resolved
// false) or also as the constants reach resolved.
func nodeCallAs(e *Entry, s *Site, fr *Frag, depth int, resolved bool) (Groups, jspat.Env, bool) {
	return nodeCallFrom(e, s, fr, depth, resolved, nil)
}

// nodeCallFrom is nodeCallAs with metavariables bound beforehand.
func nodeCallFrom(e *Entry, s *Site, fr *Frag, depth int, resolved bool, env0 jspat.Env) (Groups, jspat.Env, bool) {
	if (s.Kind == siteRead) != e.Read {
		return nil, nil, false
	}
	calleeGroups, ok := calleeHolds(e, s, fr, depth)
	if !ok {
		return nil, nil, false
	}
	env, ok := nodeArgsUnifyFrom(e, s, resolved, env0)
	if !ok {
		return nil, nil, false
	}
	groups := Groups{}
	for name, v := range env {
		if val := fillValue(s, v); val != "" {
			groups[name[1:]] = val
		}
	}
	for k, v := range calleeGroups {
		groups[k] = v
	}
	if !nodeConstraintsHold(e, s, env, calleeGroups, groups, resolved) {
		return nil, nil, false
	}
	return groups, env, true
}

// nodeArgsUnify unifies the site's arguments with the entry's pattern. An
// Unknown verdict (a spread, a computed key, an argument the fragment does
// not list) is no match. resolved=false leaves out the values reach resolved
// the arguments to, so only the source as written is read.
func nodeArgsUnify(e *Entry, s *Site, resolved bool) (jspat.Env, bool) {
	return nodeArgsUnifyFrom(e, s, resolved, nil)
}

// nodeArgsUnifyFrom is nodeArgsUnify with metavariables bound beforehand.
func nodeArgsUnifyFrom(e *Entry, s *Site, resolved bool, env0 jspat.Env) (jspat.Env, bool) {
	if e.ArgPattern == nil {
		return jspat.Env{}, true
	}
	args, known := s.nodeArgs()
	if !known || len(args) < e.MinArity || e.MaxArity != nil && len(args) > *e.MaxArity {
		return nil, false
	}
	if !resolved {
		written := make([]jspat.Concrete, len(args))
		for i, a := range args {
			written[i] = jspat.Concrete{Node: a.Node}
		}
		args = written
	}
	env, v := jspat.UnifyArgs(e.jsArgs, args, env0)
	if v != jspat.Yes {
		return nil, false
	}
	return env, true
}

// nodeNegated: a not_calls argument pattern unifies with the site's
// arguments, its constraints hold and none of its own exceptions matches.
// Unknown is no hit. A negation reads the arguments as written, never the
// values reach resolved them to: OpenGrep reads no constant there, and a
// negation it does not apply must not take away a call it reports.
func nodeNegated(e *Entry, s *Site) bool {
	for _, n := range e.NotCalls {
		if env, ok := nodeArgsUnify(n, s, false); ok && nodeConstraintsHold(n, s, env, nil, Groups{}, false) && !nodeNegated(n, s) {
			return true
		}
	}
	return false
}

// nodeNotRegexHit: one of the entry's pattern-not-regex regexes is found
// in the site's call text. The text is rebuilt from the callee and the
// arguments as written; a site whose arguments the fragment does not list
// is read as its callee alone.
func nodeNotRegexHit(e *Entry, s *Site) bool {
	if len(e.NotRegexes) == 0 {
		return false
	}
	args := make([]string, 0, s.Arity)
	for i := 0; i < s.Arity; i++ {
		if p := s.Params[i]; p != nil {
			args = append(args, p.ArgumentExpression)
		}
	}
	text := s.Raw + "(" + strings.Join(args, ", ") + ")"
	for _, rx := range e.NotRegexes {
		if reSearch(rx, text) != nil {
			return true
		}
	}
	return false
}

// nodeConsumed: the entry has no consumers, or a call of the site's own
// function (callers) is one of them and takes the site's call.
func nodeConsumed(e *Entry, s *Site, fr *Frag, callers []*Site) bool {
	if len(e.Consumers) == 0 {
		return true
	}
	for _, c := range e.Consumers {
		for _, t := range callers {
			if t.Kind == siteRead {
				continue
			}
			if t != s && c.takes(t, s, fr) {
				return true
			}
		}
	}
	return false
}

// takes: t is a call of the consumer's callee whose arguments match and
// that takes s on, as NodeConsumer describes.
func (c *NodeConsumer) takes(t, s *Site, fr *Frag) bool {
	if !c.calleeMatches(t) {
		return false
	}
	e := c.asEntry()
	env, ok := nodeArgsUnify(e, t, true)
	if !ok || !nodeConstraintsHold(e, t, env, nil, Groups{}, true) || !producersHold(c.Producers, t, fr, env) {
		return false
	}
	if c.Via == ConsumeReceiver {
		return fr.producer(t, viaVar) == s || fr.innerLink(s, t)
	}
	v, ok := env[c.Use]
	if !ok || v.Node == nil {
		return false
	}
	used := norm(v.Node.Text)
	if c.Via == ConsumeVar {
		return s.AssignedVar != "" && used == s.AssignedVar && !startBefore(t, s)
	}
	end := t.EndLine
	if end == 0 {
		end = t.Line
	}
	return strings.HasPrefix(used, norm(s.Raw)+"(") && t.Line <= s.Line && s.Line <= end
}

// calleeMatches: t's callee text and method match the consumer's regexes.
func (c *NodeConsumer) calleeMatches(t *Site) bool {
	if c.CalleeRegex != "" && reMatch(c.CalleeRegex, strings.TrimPrefix(t.Raw, "new ")) == nil {
		return false
	}
	return c.MethodRegex == "" || reMatch(c.MethodRegex, t.Method) != nil
}

// calleeHolds: the site is a call of the entry's callee. It returns the
// groups the callee binds (path and local regexes, a producer's bindings).
//
//	import/global: the site's key is one of the callee's keys, or its path
//	               under one of the modules matches the path regex; then
//	               the local name the call is written with matches local_regex.
//	written:       the site is unbound and its callee text is the path.
//	text:          the site's callee text matches the path regex.
//	literal:       the site is an object literal, its file importing one
//	               of the modules (when set) at or before it.
//	object:        the site is unbound, its method is the path, and its
//	               receiver's producer matches one of From.
func calleeHolds(e *Entry, s *Site, fr *Frag, depth int) (Groups, bool) {
	c := e.Callee
	switch c.Bind {
	case BindImport, BindGlobal:
		return c.importCalleeHolds(s, fr)
	case BindWritten:
		return Groups{}, writtenKey(s.Raw) == c.writtenKey() && (len(c.Modules) == 0 || fr.notImportsHit(s, c.Modules))
	case BindLiteral:
		return Groups{}, s.Kind == siteObjectLiteral && (!c.Assigned || s.AssignedVar != "") &&
			(len(c.Modules) == 0 || fr.notImportsHit(s, c.Modules))
	case BindText:
		return c.textHolds(s, fr)
	case BindObject:
		return c.objectHolds(s, fr, depth)
	}
	return nil, false
}

// importCalleeHolds is calleeHolds for an import or global callee: the
// import match, then the candidate match, then the instance match.
func (c *NodeCallee) importCalleeHolds(s *Site, fr *Frag) (Groups, bool) {
	if g, ok := c.importHolds(s, fr); ok {
		return g, true
	}
	if g, ok := c.candidateHolds(s, fr); ok {
		return g, true
	}
	if g, ok := c.instanceHolds(s, fr); ok {
		return g, true
	}
	return c.moduleNameHolds(s, fr)
}

// moduleNameKeys are the callee texts that spell a namespace member
// callee (Member, `$C.getRandomValues(..)` under `$C = require('crypto')`)
// on a module's own name: `crypto.getRandomValues`.
func (c *NodeCallee) moduleNameKeys() []string {
	if c.Bind != BindImport || !c.Member || c.New || c.Path == "" || strings.Contains(c.Path, ")") {
		return nil
	}
	var out []string
	for _, m := range c.Modules {
		if jsIdentRe.MatchString(m) {
			out = append(out, m+"."+c.Path)
		}
	}
	return out
}

// moduleNameHolds reads a namespace member callee on a site reach bound to
// no import (unbound, or keyed on a WebCrypto interface) written on the
// module's own name, in a file whose module scope binds a name to
// `require(<one of the modules>)` at or before it: OpenGrep matches `$C.f(..)`
// under `$C = require('crypto')` on a `crypto.f(..)` whatever `crypto`
// holds (the global, `nodeCrypto.webcrypto`). An import declaration, or a
// require inside a function, does not.
func (c *NodeCallee) moduleNameHolds(s *Site, fr *Frag) (Groups, bool) {
	if !s.node.unbound && !strings.HasPrefix(s.node.key, "(") {
		return nil, false
	}
	if !slices.Contains(c.moduleNameKeys(), writtenKey(s.Raw)) {
		return nil, false
	}
	for _, im := range fr.NodeData.imports[s.File] {
		if im.Kind == "require" && !im.Local && im.Name == "" && im.Alias != "" && inList(im.Module, c.Modules) &&
			(im.Line == 0 || !s.LineOK || im.Line <= s.Line) {
			return Groups{}, true
		}
	}
	return nil, false
}

// textHolds is calleeHolds for a text callee.
func (c *NodeCallee) textHolds(s *Site, fr *Frag) (Groups, bool) {
	// `new X(p).m` is a call of m, not a construction: the site's method
	// says which it is.
	isNew := s.Method == jsInit
	rest := s.Raw
	if isNew {
		rest = strings.TrimPrefix(rest, "new ")
	}
	if isNew != c.New || len(c.Modules) > 0 && !fr.notImportsHit(s, c.Modules) {
		return nil, false
	}
	g := reMatch(c.PathRegex, norm(rest))
	return g, g != nil
}

// instanceHolds reads an import callee keyed on an instance
// (`m.(C).utils.keccak256`, `m.(C).encrypt`, as a path or a path regex) on a
// site reach left unbound: the site's callee text is `<variable>.<rest>` and
// the variable holds the instance its producer constructs (`m.(C).<init>`),
// so the site's instance key is `m.(C).<rest>`. reach keys a method on an
// instance it tracks, not every one (a property chain, a module-level
// instance used later).
func (c *NodeCallee) instanceHolds(s *Site, fr *Frag) (Groups, bool) {
	if c.Bind != BindImport || !s.node.unbound || c.New {
		return nil, false
	}
	key, ok := fr.instanceKey(s)
	if !ok {
		return nil, false
	}
	if c.PathRegex != "" {
		g := c.pathMatch(key)
		return g, g != nil
	}
	return Groups{}, c.keySet[key]
}

// instanceKey is the key of an unbound site called on a variable that holds
// a constructed instance: the constructor's key with `<init>` replaced by
// the rest of the callee text.
func (fr *Frag) instanceKey(s *Site) (string, bool) {
	// `new m.C(p).f()`: the chain's previous link constructs the instance.
	if p := fr.producer(s, viaChain); p != nil {
		if ctor, ok := strings.CutSuffix(p.node.key, ").<init>"); ok {
			return ctor + ")." + s.Method, true
		}
	}
	// A read on `new m.C(p)` (no chain): the construction starts where the
	// read does.
	if strings.HasPrefix(s.Raw, "new ") {
		for _, t := range fr.ByCaller[s.Caller] {
			if t != s && t.Method == "<init>" && t.Line == s.Line && t.Col == s.Col {
				if ctor, ok := strings.CutSuffix(t.node.key, ").<init>"); ok {
					return ctor + ")." + s.Method, true
				}
			}
		}
	}
	head, rest, ok := strings.Cut(norm(s.Raw), ".")
	if !ok || !jsIdentRe.MatchString(head) {
		return "", false
	}
	p := fr.varProducer(s, head)
	if p == nil {
		return "", false
	}
	ctor, ok := strings.CutSuffix(p.node.key, ").<init>")
	if !ok {
		return "", false
	}
	return ctor + ")." + rest, true
}

// importHolds is calleeHolds for an import or global callee.
func (c *NodeCallee) importHolds(s *Site, fr *Frag) (Groups, bool) {
	if s.node.unbound {
		return nil, false
	}
	groups := Groups{}
	if c.PathRegex != "" {
		g := c.pathMatch(s.node.key)
		if g == nil {
			return nil, false
		}
		groups = g
	} else if !c.keySet[s.node.key] {
		return nil, false
	}
	if c.LocalRegex != "" {
		g := reMatch(c.LocalRegex, jspat.Head(strings.TrimPrefix(s.Raw, "new ")))
		if g == nil {
			return nil, false
		}
		for k, v := range g {
			groups[k] = v
		}
	}
	if !c.writtenHolds(s, fr) {
		return nil, false
	}
	return groups, true
}

// writtenHolds checks how the call is written against what reach's key
// cannot tell: the local name a destructuring gave (LocalFirst), a
// namespace member (Member), a wrapper's variable (Wrapped), a global's
// spelling (Written).
func (c *NodeCallee) writtenHolds(s *Site, fr *Frag) bool {
	head := jspat.Head(strings.TrimPrefix(s.Raw, "new "))
	switch {
	case c.LocalFirst && head != c.firstSegment(s.node.key),
		c.Member && !c.writtenAsMember(s),
		c.Wrapped && fr.bindsModule(s.File, head, c.Modules),
		c.Inline && !writtenInline(s.Raw):
		return false
	}
	if c.written == nil {
		return true
	}
	site, err := jspat.ParseExpr(strings.TrimPrefix(s.Raw, "new "), false)
	if err != nil {
		return false
	}
	_, v := jspat.Unify(c.written, site, nil)
	return v == jspat.Yes
}

// objectHolds is calleeHolds for an object callee: the groups are the
// producer's.
func (c *NodeCallee) objectHolds(s *Site, fr *Frag, depth int) (Groups, bool) {
	// reach leaves the call unbound, or keys it on the instance a contract
	// typed (`m.(T).method`): either way its receiver's producer decides.
	instance := strings.Contains(s.node.key, ")."+s.Method)
	if !s.node.unbound && !instance || s.Method != c.Path || depth >= maxProducerDepth {
		return nil, false
	}
	if c.Props != "" {
		return c.propsHold(s, fr, depth)
	}
	for _, via := range c.Via {
		p := fr.producer(s, via)
		if p == nil {
			continue
		}
		for _, f := range c.From {
			if g, _, ok := nodeCall(f, p, fr, depth+1); ok {
				return g, true
			}
		}
	}
	return nil, false
}

// propsHold is objectHolds for a callee reached through a property chain:
// the site's callee text is `<variable>.<Props>.<method>` and the
// variable's producer matches one of From.
func (c *NodeCallee) propsHold(s *Site, fr *Frag, depth int) (Groups, bool) {
	head, rest, ok := strings.Cut(norm(s.Raw), ".")
	if !ok || rest != c.Props+"."+c.Path || !jsIdentRe.MatchString(head) {
		return nil, false
	}
	p := fr.varProducer(s, head)
	if p == nil {
		return nil, false
	}
	for _, f := range c.From {
		if g, _, ok := nodeCall(f, p, fr, depth+1); ok {
			return g, true
		}
	}
	return nil, false
}

// firstSegment is the first segment of key's path under one of the
// callee's modules, "" when key is under none.
func (c *NodeCallee) firstSegment(key string) string {
	// The longest module the key starts with: `m` and `m.js` both prefix
	// `m.js.f`.
	best := ""
	for _, m := range c.Modules {
		if strings.HasPrefix(key, m+".") && len(m) > len(best) {
			best = m
		}
	}
	if best == "" {
		return ""
	}
	first, _, _ := strings.Cut(key[len(best)+1:], ".")
	// A constructed class is written `(C)` in a key, `C` in source.
	return strings.TrimSuffix(strings.TrimPrefix(first, "("), ")")
}

// pathMatch matches the path regex against the key: an import callee's path
// is the key under one of its modules, a global's the key itself.
func (c *NodeCallee) pathMatch(key string) Groups {
	if c.Bind == BindGlobal {
		return reMatch(c.PathRegex, key)
	}
	for _, m := range c.Modules {
		if rest, ok := strings.CutPrefix(key, m+"."); ok {
			if g := reMatch(c.PathRegex, rest); g != nil {
				return g
			}
		}
	}
	return nil
}

// nodeConstraintsHold applies each constraint's regex to its metavariable's
// binding: the bound text, then (resolved=true) the literal reach resolved
// it to. A metavariable the callee's path binds is read from its group.
// Named groups are added to groups.
func nodeConstraintsHold(e *Entry, s *Site, env jspat.Env, calleeGroups, groups Groups, resolved bool) bool {
	for _, c := range e.Constraints {
		matched := false
		for _, text := range bindingTexts(c.Metavar, s, env, calleeGroups, resolved) {
			if g := reMatch(*c.Regex, text); g != nil {
				for k, v := range g {
					groups[k] = v
				}
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// bindingTexts are the texts a constraint on mv is tried on, in order. A
// bound literal is read only as written, quotes included, as OpenGrep reads
// it: the unquoted value reach resolves it to would pass a regex written to
// exclude the quoted names.
func bindingTexts(mv string, s *Site, env jspat.Env, calleeGroups Groups, resolved bool) []string {
	v, ok := env[mv]
	if !ok {
		if g, ok := calleeGroups[strings.TrimPrefix(mv, "$")]; ok {
			return []string{g}
		}
		return nil
	}
	var out []string
	if v.Node != nil && (v.Node.Kind == jspat.String || v.Node.Kind == jspat.Number) {
		if i := s.argIndex(v); i >= 0 && s.node.texts[i] != "" {
			return []string{s.node.texts[i]} // the source text: jspat writes strings double-quoted
		}
		return []string{v.Node.Text}
	}
	if v.Node != nil && v.Node.Text != "" {
		out = append(out, v.Node.Text)
	}
	if !resolved {
		return out
	}
	if i := s.argIndex(v); i >= 0 && s.node.resolved[i] != "" {
		out = append(out, s.node.resolved[i])
	}
	if v.Resolved != "" {
		out = append(out, v.Resolved)
	}
	return out
}

// fillValue is the value a metavariable fills a metadata template with, as
// cfMetavarValue reads a call argument: the literal a name resolves to,
// else the bound text.
func fillValue(s *Site, v jspat.Value) string {
	text := ""
	if i := s.argIndex(v); i >= 0 {
		text = s.node.texts[i]
	} else if v.Node != nil {
		text = v.Node.Text
	}
	if v.Resolved != "" && (text == "" || reMatchOK(cfIdentRx, text)) {
		return v.Resolved
	}
	return text
}

// nodeFocus reports a focus-metavariable rule at the bound argument: a whole
// top-level argument becomes the finding's FocusArg (the scanner recovers its
// columns from the call's lines); a binding inside an argument keeps the
// call's position, with its text.
func nodeFocus(f *Finding, e *Entry, s *Site, env jspat.Env, fr *Frag) {
	if e.FocusMetavar == "" {
		return
	}
	v, ok := env[e.FocusMetavar]
	if !ok || v.Node == nil {
		return
	}
	if s.Kind == siteObjectLiteral && s.node.lit != nil {
		// An object's source is at hand: the finding moves to the value.
		if sp, ok := s.node.lit.valueAt(s.node.litWord, v.Node.Text); ok {
			f.Line, f.Col, f.EndCol, f.EndLine = sp.line, sp.col, sp.endCol, 0
			if sp.endLine != sp.line {
				f.EndLine = sp.endLine
			}
		}
		f.FocusText = v.Node.Text
		return
	}
	if i := s.argIndex(v); i >= 0 {
		f.FocusArg = &i
		f.FocusText = s.node.texts[i]
		return
	}
	f.FocusText = v.Node.Text
	// A value inside an argument: found in the call's own source.
	if pos := fr.callSource(s); pos != nil {
		if sp, ok := pos.valueAt(0, v.Node.Text); ok {
			f.Line, f.Col, f.EndCol, f.EndLine = sp.line, sp.col, sp.endCol, 0
			if sp.endLine != sp.line {
				f.EndLine = sp.endLine
			}
		}
	}
}

// nodeProduced: each of the entry's producers holds for the site, whose
// argument bindings are env: the value Use binds reads a variable (a name
// not after a `.`) that an earlier call of the site's function, matching one
// of From, assigned or destructured into.
func nodeProduced(e *Entry, s *Site, fr *Frag, env jspat.Env) bool {
	return producersHold(e.Producers, s, fr, env)
}

// producersHold: each producer holds for the call s whose argument bindings
// are env.
func producersHold(producers []*NodeProducer, s *Site, fr *Frag, env jspat.Env) bool {
	for _, p := range producers {
		v, ok := env[p.Use]
		if !ok || v.Node == nil || !p.holds(s, fr, v.Node.Text) {
			return false
		}
	}
	return true
}

func (p *NodeProducer) holds(s *Site, fr *Frag, text string) bool {
	_, ok := p.match(s, fr, text)
	return ok
}

// match is the groups of the first producer call that holds for the value
// text.
func (p *NodeProducer) match(s *Site, fr *Frag, text string) (Groups, bool) {
	for _, name := range jsReadNames(text) {
		for _, a := range fr.assigners(s, name, p.Via) {
			for _, f := range p.From {
				if g, _, ok := nodeCall(f, a, fr, 1); ok {
					return g, true
				}
			}
		}
	}
	return nil, false
}

// producerGroups are the groups the producers' calls bind (a regex group
// on the producer call fills the finding's metadata like the call's own).
func producerGroups(producers []*NodeProducer, s *Site, fr *Frag, env jspat.Env) Groups {
	out := Groups{}
	for _, p := range producers {
		v, ok := env[p.Use]
		if !ok || v.Node == nil {
			continue
		}
		if g, ok := p.match(s, fr, v.Node.Text); ok {
			for k, val := range g {
				out[k] = val
			}
		}
	}
	return out
}

// jsReadName is an identifier not written after a `.` (or `?.`).
var jsReadName = regexp.MustCompile(`(^|[^.\w$])([A-Za-z_$][\w$]*)`)

// jsReadNames are the variables an expression's text reads.
func jsReadNames(text string) []string {
	ms := jsReadName.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[2])
	}
	return out
}

// prepareNode prepares the producer's calls.
func (p *NodeProducer) prepareNode() {
	for _, f := range p.From {
		f.prepareNode()
	}
}

// withinHolds: the entry has no within calls, or the site lies within a call
// of its function that one of them matches.
func withinHolds(e *Entry, s *Site, fr *Frag, callers []*Site) bool {
	if len(e.Within) == 0 {
		return true
	}
	for _, t := range callers {
		if t == s || t.Kind == siteObjectLiteral || t.Kind == siteRead || !spanContains(t, s) {
			continue
		}
		for _, w := range e.Within {
			if _, _, ok := nodeCall(w, t, fr, 1); ok {
				return true
			}
		}
	}
	return false
}

// writtenAsMember: the site's callee text is the namespace binding followed
// by the callee's path (`ns.keys.gen` for keys.gen, `new ns.x.C` for
// x.(C).<init>), however wrapped (`(0, ns.f)`). A path regex only needs a
// member access.
func (c *NodeCallee) writtenAsMember(s *Site) bool {
	raw := strings.TrimPrefix(jsDotted(norm(s.Raw)), "new")
	raw = strings.TrimSuffix(strings.TrimPrefix(raw, "(0,"), ")")
	if !strings.Contains(raw, ".") {
		return false
	}
	if c.Path == "" {
		return true
	}
	path := strings.TrimSuffix(c.Path, ".<init>")
	want := strings.Count(path, ".") + 1
	if _, rest, _ := strings.Cut(raw, "."); strings.HasPrefix(rest, "default.") && !strings.HasPrefix(path, "default.") {
		want++ // `ns.default.f()`, a compiled interop of a default import, keyed m.f
	}
	return strings.Count(raw, ".") == want
}

// notProduced: one of the entry's not_producers holds for the site.
func notProduced(e *Entry, s *Site, fr *Frag, env jspat.Env) bool {
	for _, p := range e.NotProducers {
		if producersHold([]*NodeProducer{p}, s, fr, env) {
			return true
		}
	}
	return false
}

// writtenInline: the callee text starts with a require or import call.
func writtenInline(raw string) bool {
	t := strings.TrimPrefix(norm(raw), "new")
	t = strings.TrimPrefix(strings.TrimPrefix(t, "(0,"), "(")
	t = strings.TrimPrefix(t, "await")
	return strings.HasPrefix(t, "require(") || strings.HasPrefix(t, "import(")
}

// candidateKeys are the keys an unbound call on a merged module object may
// have: each candidate module with the callee text after the receiver.
func candidateKeys(s *Site) []string {
	if len(s.node.candidates) == 0 {
		return nil
	}
	_, rest, ok := strings.Cut(norm(s.Raw), ".")
	if !ok {
		return nil
	}
	out := make([]string, len(s.node.candidates))
	for i, m := range s.node.candidates {
		out[i] = m + "." + rest
	}
	return out
}

// candidateHolds reads an import callee on an unbound call whose receiver
// holds a merged module object (`H = Object.assign({}, require(a),
// require(b))`, `H.f()`): one of the candidate modules with the rest of the
// callee text is the callee's key, as OpenGrep's text match under the
// require guards reads it.
func (c *NodeCallee) candidateHolds(s *Site, fr *Frag) (Groups, bool) {
	if c.Bind != BindImport || !s.node.unbound || c.New {
		return nil, false
	}
	for _, key := range candidateKeys(s) {
		if c.PathRegex != "" {
			if g := c.pathMatch(key); g != nil && c.writtenHolds(s, fr) {
				return g, true
			}
			continue
		}
		if c.keySet[key] && c.writtenHolds(s, fr) {
			return Groups{}, true
		}
	}
	return nil, false
}

// reportSite is where the finding of e on s starts: an assigned object
// literal's variable for a `$O = {...}` rule, a focused value inside an
// object literal, else s.
func reportSite(e *Entry, s *Site, env jspat.Env, fr *Frag) *Site {
	if e.Callee != nil && e.Callee.Assigned && s.node.assignedCol > 0 {
		cp := *s
		cp.Line, cp.Col = s.node.assignedLine, s.node.assignedCol
		return &cp
	}
	return focusSite(e, s, env, fr)
}

// jsStringIndex is a string-literal subscript (`["sha256"]`).
var jsStringIndex = regexp.MustCompile(`\[\s*["'\x60]([A-Za-z_$][\w$]*)["'\x60]\s*\]`)

// jsDotted writes a callee text's string-literal subscripts as members
// (`hash["sha256"]` -> `hash.sha256`), as reach keys them.
func jsDotted(raw string) string {
	return jsStringIndex.ReplaceAllString(raw, ".$1")
}
