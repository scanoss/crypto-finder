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

// The matcher side of the compiler's Python extensions (compile_py_ext.go):
// nested call arguments, origins (insides and object flow), not_inside, and
// constant entries matched against the fragment's constant references.

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Origin is where a metavariable's object comes from (a pattern-inside, or
// an object-flow taint rule's sources): its class is one of Types (the
// fragment resolved the receiver's class), or it is a local / inline call
// that matches one of From (card call patterns, via var or chain).
type Origin struct {
	Metavar string     `json:"metavar"`
	Types   []string   `json:"types"`
	From    []JSONMeta `json:"from"`
	// NotFrom: calls the factories exclude (an object-flow source's
	// pattern-not), checked on the local's latest assignment.
	NotFrom []JSONMeta `json:"not_from"`
	// Made: Go types whose objects a composite literal or a declaration
	// source makes; unlike Types, a value of the type holds one only where
	// such a literal or declaration reaches it (go_flow.go).
	Made []string `json:"made,omitempty"`

	pattern *OMap // {via: [var, chain], from: {any: From}}, built by prepare
	not     []any // NotFrom as card call patterns
}

var pyRecvMetavar = regexp.MustCompile(`^(\$[A-Z_0-9]+)\s*\.`)

// prepare builds what the extension fields need once the index is decoded.
func (ix *Index) prepare() {
	for _, e := range ix.Entries {
		e.prepare()
	}
}

func (e *Entry) prepare() {
	for _, g := range e.Insides {
		for _, o := range g {
			items := make([]any, len(o.From))
			for i, f := range o.From {
				items[i] = cardPatternFromJSON(f.M)
			}
			o.pattern = omap("via", []any{"var", "chain"}, "from", omap(strAny, items))
			for _, f := range o.NotFrom {
				o.not = append(o.not, cardPatternFromJSON(f.M))
			}
		}
	}
	for i := range e.Args {
		if e.Args[i].Call != nil {
			e.Args[i].Call.prepare()
		}
	}
	for _, n := range e.NotInside {
		n.prepare()
	}
}

// cardPatternFromJSON gives a card call pattern decoded from JSON the types
// a card loaded from YAML has: integer argument keys.
func cardPatternFromJSON(m *OMap) *OMap {
	out := &OMap{}
	for i, k := range m.Keys {
		v := m.Vals[i]
		if k == any("args") {
			args := &OMap{}
			am := as[*OMap](v)
			for j, ak := range am.Keys {
				key := ak
				if n, err := strconv.Atoi(as[string](ak)); err == nil {
					key = int64(n)
				}
				args.Set(key, am.Vals[j])
			}
			v = args
		}
		out.Set(k, v)
	}
	return out
}

// receiverMetavar is the metavariable the entry's pattern binds to the
// receiver (`$X.m(...)`), or "".
func (e *Entry) receiverMetavar() string {
	if e.Receiver != strAny {
		return ""
	}
	if e.ReceiverVar != "" {
		return e.ReceiverVar
	}
	if m := pyRecvMetavar.FindStringSubmatch(e.Pattern); m != nil {
		return m[1]
	}
	return ""
}

// nestedMatch: every nested call argument of e is a call written at the
// site's argument that matches it (with its constraints); its groups and
// metavariable bindings are added to groups.
func nestedMatch(e *Entry, s *Site, fr *Frag, groups Groups) bool { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	for i := range e.Args {
		a := &e.Args[i]
		if a.Kind != "call" || a.Call == nil {
			continue
		}
		p := a.param(s.Params)
		if p == nil {
			return false
		}
		inner := fr.siteFor(s.Caller, p.ArgumentExpression, s.Line, s.LineOK)
		if inner == nil {
			return false
		}
		g := callMatches(a.Call, inner, fr)
		if g == nil || !constraintsHold(a.Call, inner, g, fr) {
			return false
		}
		for k, v := range g {
			groups[k] = v
		}
		if mv := a.Call.MethodMetavar; mv != nil && inner.Method != "" {
			groups[strings.TrimPrefix(*mv, "$")] = inner.Method
		}
		for j := range a.Call.Args {
			sa := &a.Call.Args[j]
			if sa.Kind == strMetavar && sa.Name != nil {
				if sp := sa.param(inner.Params); sp != nil && sp.ArgumentExpression != "" {
					groups[strings.TrimPrefix(*sa.Name, "$")] = sp.ArgumentExpression
				}
			}
		}
	}
	return true
}

// insidesHold: in every origin group of e, one origin holds for the site.
func insidesHold(e *Entry, s *Site, fr *Frag) bool {
	for _, g := range e.Insides {
		ok := false
		for _, o := range g {
			if fr.originHolds(e, s, o) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// originHolds: the value o's metavariable binds at the site (the receiver,
// or an argument) is an object of one of o's types, or comes from a call
// matching one of o's from patterns.
func (fr *Frag) originHolds(e *Entry, s *Site, o *Origin) bool { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var val Val
	if fr.Go && e.Flow != flowObject {
		return fr.goProducerHolds(e, s, o)
	}
	if fr.Go && e.receiverMetavar() == o.Metavar {
		return fr.goOriginHolds(s, o)
	}
	if e.receiverMetavar() == o.Metavar { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		text := fr.receiverText(s)
		val = Val{Text: text, HasText: text != "", Caller: s.Caller, Line: s.Line, LineOK: s.LineOK}
		cls := s.receiverClass()
		typed := cls != "" && slices.Contains(o.Types, cls)
		if last := fr.lastAssignment(s, text); last != nil && len(o.From) > 0 {
			// A local last assigned from another call (a same-file factory
			// returning the object) still holds one when the graph typed
			// the receiver as one of the types, unless that call is excluded.
			return o.assignedFrom(last, text, fr) || typed && !o.excludes(last, text, fr)
		}
		if typed {
			return true
		}
	} else {
		var p *Param
		for i := range e.Args {
			if a := &e.Args[i]; a.Kind == strMetavar && a.Name != nil && *a.Name == o.Metavar {
				p = a.param(s.Params)
				break
			}
		}
		if p == nil {
			return false
		}
		val = Val{Text: p.ArgumentExpression, HasText: p.ArgumentExpression != "", Param: p, Caller: s.Caller, Line: s.Line, LineOK: s.LineOK}
		if len(o.Types) > 0 {
			types := make([]any, len(o.Types))
			for i, t := range o.Types {
				types[i] = t
			}
			if len(mValue(omap(strType, types), val, Env{}, fr)) > 0 {
				return true
			}
		}
	}
	if len(o.From) == 0 {
		return false
	}
	if last := fr.lastAssignment(s, val.Text); last != nil {
		return o.assignedFrom(last, val.Text, fr)
	}
	return len(mValue(o.pattern, val, Env{}, fr)) > 0
}

// excludes: the call a local was last assigned from matches one of the
// origin's exclusions (not_from).
func (o *Origin) excludes(last *Site, name string, fr *Frag) bool {
	ex := Expr{Site: last, Caller: last.Caller, Assigned: name}
	for _, n := range o.not {
		for range mCall(n, ex, Env{}, fr) {
			return true
		}
	}
	return false
}

// assignedFrom: the call a local was last assigned from (OpenGrep's taint
// is flow sensitive: a reassignment from another call ends it) matches one
// of the origin's factories and none of its exclusions.
func (o *Origin) assignedFrom(last *Site, name string, fr *Frag) bool {
	ex := Expr{Site: last, Caller: last.Caller, Assigned: name}
	for _, n := range o.not {
		for range mCall(n, ex, Env{}, fr) {
			return false
		}
	}
	for _, item := range listOf(as[*OMap](o.pattern.GetOr("from")).GetOr(strAny)) {
		for range mCall(item, ex, Env{}, fr) {
			return true
		}
	}
	return false
}

// lastAssignment is the call site the local name was last assigned from
// before the site, in the site's function; nil when the fragment records no
// call assigned to it before the site, or (Python) when another binding of
// the name ends that assignment before the site (pyReaches).
func (fr *Frag) lastAssignment(s *Site, name string) *Site { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	if !identMatch(name) || !s.LineOK {
		return nil
	}
	var last *Site
	for _, a := range fr.VarSites[pairKey(s.Caller, name)] {
		if !a.LineOK || a.Line > s.Line || a.Line == s.Line && (!a.ColOK || !s.ColOK || a.Col >= s.Col) {
			continue
		}
		if last == nil || a.Line > last.Line || a.Line == last.Line && a.Col > last.Col {
			last = a
		}
	}
	if last != nil && fr.Python && !fr.pyReaches(last, name, s.Line, s.Col) {
		return nil // a later binding that is no call (`k = other`) ends it
	}
	return last
}

// notInsideHit: the site is written inside a call of its function (itself,
// its arguments or its receiver chain: OpenGrep's range inclusion) that
// matches one of pats.
func notInsideHit(pats []*Entry, s *Site, fr *Frag) bool {
	if len(pats) == 0 {
		return false
	}
	for _, outer := range fr.ByCaller[s.Caller] {
		if !outer.contains(s) {
			continue
		}
		for _, n := range pats {
			if g := callMatches(n, outer, fr); g != nil && constraintsHold(n, outer, g, fr) {
				return true
			}
		}
	}
	return false
}

// refInsideHit: the constant reference is written inside a call of its
// function that matches one of pats.
func refInsideHit(pats []*Entry, ref *Site, fr *Frag) bool {
	if len(pats) == 0 {
		return false
	}
	for _, outer := range fr.ByCaller[ref.Caller] {
		if !outer.contains(ref) {
			continue
		}
		for _, n := range pats {
			if g := callMatches(n, outer, fr); g != nil && constraintsHold(n, outer, g, fr) {
				return true
			}
		}
	}
	for _, n := range pats {
		if n.Receiver != strNone || n.Method == nil {
			continue
		}
		if fr.refInBuiltinCall(ref, *n.Method) || ref.RefContext == pyTypeCheck && pyTypeCheckCalls[*n.Method] {
			return true
		}
	}
	return false
}

// pyTypeCheck is the position of a constant the call graph found tested by
// isinstance / issubclass (callgraph.ConstantRefTypeCheck), however its call
// is laid out over lines.
const pyTypeCheck = "type_check"

var pyTypeCheckCalls = map[string]bool{"isinstance": true, "issubclass": true}

// pyBuiltinCalls are the builtins rules exclude constants inside of; the
// fragment exports no call to a builtin, so the source line tells.
var pyBuiltinCalls = map[string]bool{"isinstance": true, "issubclass": true, strType: true, "getattr": true, "hasattr": true}

// refInBuiltinCall: the constant reference is written, on its line, inside
// the argument list of a call of builtin name (`isinstance(x, (hashes.MD5,
// ...))`), read from the fragment's source line.
func (fr *Frag) refInBuiltinCall(ref *Site, name string) bool {
	if !pyBuiltinCalls[name] || !ref.ColOK {
		return false
	}
	line, ok := fr.Lines[ref.File][ref.Line]
	if !ok || ref.Col < 1 || ref.Col-1 > len(line) {
		return false
	}
	before := line[:ref.Col-1]
	for i := strings.LastIndex(before, name+"("); i >= 0; i = strings.LastIndex(before[:i], name+"(") {
		if i > 0 && (isIdentByte(before[i-1]) || before[i-1] == '.') {
			continue
		}
		depth := 0
		for _, c := range before[i+len(name):] {
			switch c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			}
		}
		if depth > 0 {
			return true
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// constantMatch matches a constant entry against a Python constant reference
// (qualified through the file's imports): the owner is the entry's type and
// the name its method (or matches its method regex). It returns the groups
// (with the method metavariable bound to the name), nil for no match.
func constantMatch(e *Entry, r *Site, fr *Frag) Groups {
	text := norm(fr.qualifyIn(r.Caller, norm(r.Raw)))
	dot := strings.LastIndexByte(text, '.')
	if dot < 0 || e.Type == nil || text[:dot] != *e.Type {
		return nil
	}
	name := text[dot+1:]
	groups := Groups{}
	if e.Method != nil {
		if name != *e.Method {
			return nil
		}
	} else {
		g := e.methodMatch(name)
		if g == nil {
			return nil
		}
		for k, v := range g {
			groups[k] = v
		}
	}
	if e.MethodMetavar != nil {
		groups[strings.TrimPrefix(*e.MethodMetavar, "$")] = name
	}
	return groups
}

// constantAt: the entry reports a reference at the reference's position
// kind: one of At when given (else any but a comparison the policy keeps
// out), never one of NotAt.
func (fr *Frag) constantAt(e *Entry, r *Site) bool {
	for _, k := range e.NotAt {
		if r.RefContext == k {
			return false
		}
	}
	if len(e.At) > 0 {
		for _, k := range e.At {
			if r.RefContext == k {
				return true
			}
		}
		return false
	}
	return !fr.comparisonRef(r.RefContext) || fr.reportComparison(r)
}

// matchConstantEntries reports the constant entries at the fragment's
// constant references.
func matchConstantEntries(entries []*Entry, fr *Frag, seen map[string]bool) []*Finding {
	if len(entries) == 0 || !fr.Python {
		return nil
	}
	var findings []*Finding
	for _, r := range fr.Refs {
		for _, e := range entries {
			if !fr.constantAt(e, r) {
				continue
			}
			groups := constantMatch(e, r, fr)
			if groups == nil || refInsideHit(e.NotInside, r, fr) {
				continue
			}
			key := findingKey(e.RuleID, r, nil)
			if seen[key] {
				continue
			}
			seen[key] = true
			fg := fillGroups{}
			for k, v := range groups {
				v := v
				fg[k] = &v
			}
			findings = append(findings, &Finding{
				RuleID: e.RuleID, File: r.File, Line: r.Line, LineOK: r.LineOK, Col: r.Col, ColOK: r.ColOK,
				Taint: e.Taint, How: "constant:" + r.RefContext, Resolution: r.Resolution, SiteKind: r.Kind,
				Callee: r.Raw, Metadata: fillCF(e.Metadata.M, fg, r, e), Approx: append([]string{}, e.DroppedClauses...),
				Caller: r.Caller, EndCol: r.EndCol, EndLine: r.EndLine,
			})
		}
	}
	return findings
}

// pyTypeMetavarMatch: the callee's class (resolved, or as written) is a class
// of the entry's module named by its type metavariable, whose name matches
// the type regex; the name (and the regex groups) go into groups.
func pyTypeMetavarMatch(e *Entry, cls string, s *Site, groups Groups) bool {
	module := strings.TrimSuffix(*e.Type, "."+*e.TypeMetavar)
	name := ""
	if rest, ok := strings.CutPrefix(cls, module+"."); ok && !strings.Contains(rest, ".") {
		name = rest
	} else if raw, ok := strings.CutPrefix(norm(s.Raw), module+"."); ok && strings.HasSuffix(raw, "."+s.Method) {
		name = strings.TrimSuffix(raw, "."+s.Method)
	}
	if name == "" || strings.Contains(name, ".") {
		return false
	}
	if e.TypeRegex != nil {
		g := reMatch(*e.TypeRegex, name)
		if g == nil {
			return false
		}
		for k, v := range g {
			groups[k] = v
		}
	}
	groups[strings.TrimPrefix(*e.TypeMetavar, "$")] = name
	return true
}

// pyStringMatches: the argument is a string literal (as written, or its
// resolved value) whose content the regex finds ("=~/re/" in a pattern).
func pyStringMatches(rx string, p *Param) bool {
	for _, v := range []string{p.ArgumentExpression, p.ResolvedValue} {
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			return reSearch(pcreToPy(rx), v[1:len(v)-1]) != nil
		}
	}
	return false
}

// pyStringContent is the content of a Python string argument (as written,
// or its resolved value), nil when it is none.
func pyStringContent(p *Param) *string {
	for _, v := range []string{p.ArgumentExpression, p.ResolvedValue} {
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			c := v[1 : len(v)-1]
			return &c
		}
	}
	return nil
}

// pyContainerArg: the argument is a display of the container argument's
// kind (dict or list) holding its dict keys.
func pyContainerArg(a *IndexArg, p *Param) bool {
	text := norm(p.ArgumentExpression)
	if a.Value == nil || !strings.HasPrefix(text, *a.Value) {
		return false
	}
	for _, k := range a.Keys { // the text's literals have double quotes (dq)
		if !strings.Contains(text, k+":") {
			return false
		}
	}
	return true
}

// pyDisplayLiterals are the string literals written inside an argument (a
// dict / list display, a call's arguments, an expression): OpenGrep's taint
// written into a container or passed through a call taints the result.
func pyDisplayLiterals(p *Param) []valueHow {
	text := p.ArgumentExpression
	if len(text) < 2 || text[0] == '"' && text[len(text)-1] == '"' {
		return nil // a plain literal is already a value
	}
	var out []valueHow
	for _, lit := range literalRx.FindAllString(text, -1) { // double quotes (dq)
		out = append(out, valueHow{"direct", lit})
	}
	return out
}

// pyDictValueMatches: the value written for the constraint's key in the
// dict display argument (as written, or qualified through the file's
// imports for a dotted-name constraint) matches its regex; the groups are
// added.
func pyDictValueMatches(c *Constraint, p *Param, s *Site, fr *Frag, groups Groups) bool {
	value := pyDictValue(norm(p.ArgumentExpression), *c.DictKey) // the container's keys are there
	m := reMatch(*c.Regex, value)
	if m == nil && c.Qualified && fr != nil {
		m = reMatch(*c.Regex, qualify(value, fr.Names[s.File]))
	}
	if m == nil {
		return false
	}
	for k, v := range m {
		groups[k] = v
	}
	return true
}

// pyDictValue is the value text of key in a dict display (whitespace
// removed), at the top level of the display.
func pyDictValue(text, key string) string {
	inner := strings.TrimSuffix(text[1:], "}")
	for _, entry := range splitArgs(inner) {
		if k, v, ok := strings.Cut(entry, ":"); ok && k == key {
			return v
		}
	}
	return ""
}
