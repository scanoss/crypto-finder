// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"cmp"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// Go object flow (go-port audit T4/T7). A taint rule whose sources are calls
// (`acme.NewThing(...)`) compiles as Python's object flow does: the sink's
// receiver carries an origin. A Go site's receiver holds what a source call
// returns, within one file as OpenGrep's --taint-intrafile reads it, when it
// is
//
//   - a call chained on one (`acme.NewThing(1).Seal(..)`);
//   - a local last assigned from one, or from a call one flows into
//     (`t := wrap(acme.NewThing(1))`): taint passes through a call whose
//     receiver or argument holds it;
//   - a parameter a caller in the same file passes one for.
//
// A source that is a typed metavariable holds any value of its type. A
// composite literal or declaration source holds a local assigned such a
// literal (or, without assignment facts, a local of its type no call
// assigned), a parameter a caller in the same file passes one for, and what
// a function of the same file returns as one. With the fragment's
// assignment facts (1.36) a local copied from another (`u := t`) and a field
// a composite literal fills (`h.Thing`) are followed too.

// goFlowDepth bounds how many calls, locals and callers a flow crosses.
const goFlowDepth = 8

// goFlow follows a Go site's receiver back to the calls of an origin;
// done memoizes each call site's result.
type goFlow struct {
	fr    *Frag
	o     *Origin
	done  map[*Site]bool
	names map[string]bool // name at a position: what name gave there
}

// goOriginHolds: the receiver of a Go site holds a source's object.
func (fr *Frag) goOriginHolds(s *Site, o *Origin) bool {
	fl := &goFlow{fr: fr, o: o, done: map[*Site]bool{}, names: map[string]bool{}}
	return fl.receiver(s, 0)
}

// receiver: what s is called on holds a source's object: a value of one of
// the origin's types (a typed metavariable source), what a factory returns,
// or an object a composite literal or declaration source makes.
func (fl *goFlow) receiver(s *Site, depth int) bool {
	cls := s.receiverClass()
	if goTypeIn(cls, fl.o.Types) {
		return true
	}
	text := fl.fr.receiverText(s)
	switch {
	case text == "" || depth > goFlowDepth:
		return false
	case strings.HasSuffix(text, ")"):
		if inner := fl.fr.goChained(s); inner != nil {
			return fl.site(inner, depth+1)
		}
		return false
	}
	return fl.name(s, text, cls, depth)
}

// name: the local, parameter or field read as text at the site holds a
// source's object. A local holds what the assignments that reach the site
// give (goReaching): a call's result, a copy of another local (`u := t`),
// or a composite literal of a made type (go_values kind assign, 1.36). A
// parameter, or a local no assignment reaches for sure, also holds what a
// caller in the same file passes. Without assignment facts, a local no
// call assigned holds a made type's object when it has that type.
func (fl *goFlow) name(at *Site, text, cls string, depth int) bool {
	if depth > goFlowDepth {
		return false
	}
	if base, field, ok := strings.Cut(text, "."); ok && identMatch(base) && identMatch(field) {
		return fl.field(at, base, field, depth)
	}
	if !identMatch(text) {
		return false
	}
	key := text + "@" + at.File + ":" + strconv.Itoa(at.Line) + ":" + strconv.Itoa(at.Col)
	if held, ok := fl.names[key]; ok {
		return held
	}
	fl.names[key] = false // a cycle holds nothing
	held := fl.localName(at, text, cls, depth)
	fl.names[key] = held
	return held
}

// localName is name for a plain local or parameter (memoized by name).
func (fl *goFlow) localName(at *Site, text, cls string, depth int) bool {
	defs := fl.localDefs(at, text, depth)
	held, killed := fl.fr.goReaching(at, defs)
	if held || killed {
		return held
	}
	for i, name := range fl.fr.GoParams[at.Caller] {
		if name == text {
			return fl.callers(at, i, depth+1)
		}
	}
	return len(defs) == 0 && goTypeIn(cls, fl.o.Made)
}

// goDef is an assignment of a local or a field, where it is written, and
// whether what it assigns holds a source's object.
type goDef struct {
	file      string
	line, col int
	holds     func() bool
}

// goReaching reads the definitions written before the site, in source
// order, as OpenGrep's flow-sensitive taint does: the latest one whose
// innermost block holds the site is the value the site starts from (an
// earlier one is overwritten), and each later one, in a branch the site may
// not have come through, may hold instead. held: one of those holds a
// source's object; killed: one of them holds the site for sure, so nothing
// before it (a parameter's value) reaches. A fragment without blocks reads
// the latest definition as the one that holds.
func (fr *Frag) goReaching(at *Site, defs []goDef) (held, killed bool) {
	start := 0
	for i := len(defs) - 1; i >= 0; i-- {
		if fr.goCovers(defs[i].file, defs[i].line, defs[i].col, at) {
			start, killed = i, true
			break
		}
	}
	for _, d := range defs[start:] {
		if d.holds() {
			return true, killed
		}
	}
	return false, killed
}

// goCovers: the site lies in the innermost block of the position; without
// the fragment's blocks, any position does.
func (fr *Frag) goCovers(file string, line, col int, at *Site) bool {
	if !fr.HasGoBlocks {
		return true
	}
	b := fr.goBlockOf(file, line, col)
	return b == nil || goSpanHolds(b.StartLine, b.StartCol, b.EndLine, b.EndCol, at.Line, at.Col)
}

// localDefs are the assignments of the local name written before the site
// in its function and file, in source order: the calls assigned to it, and
// the assignment facts that are no call.
func (fl *goFlow) localDefs(at *Site, name string, depth int) []goDef {
	var defs []goDef
	calls := map[int]bool{}
	for _, t := range fl.fr.VarSites[pairKey(at.Caller, name)] {
		if t.File != at.File || !t.before(at) {
			continue
		}
		calls[t.Line] = true
		defs = append(defs, goDef{t.File, t.Line, t.Col, func() bool { return fl.site(t, depth+1) }})
	}
	for _, a := range fl.fr.GoAssigns[pairKey(at.Caller, name)] {
		if a.file != at.File || a.line > at.Line || a.line == at.Line && a.col >= at.Col {
			continue
		}
		if fl.fr.goShadows(a, at) {
			defs = slices.DeleteFunc(defs, func(d goDef) bool { return d.line == a.line })
			continue
		}
		if calls[a.line] {
			continue
		}
		defs = append(defs, goDef{a.file, a.line, a.col, func() bool { return fl.assigned(at, a, depth) }})
	}
	slices.SortFunc(defs, func(x, y goDef) int { return cmp.Or(cmp.Compare(x.line, y.line), cmp.Compare(x.col, y.col)) })
	return defs
}

// Operators of a go_values assign fact that declare their names.
const (
	goOpDeclare = ":="
	goOpVar     = "var"
)

// goShadows: the assignment declares the name (`:=`, var) in a block that
// does not hold the site, so it is another variable than the one the site
// reads (`if c { t := acme.New() }` then `t.Seal()`). A declaration in an
// if or switch header counts as the enclosing block's, as OpenGrep's taint
// reads it.
func (fr *Frag) goShadows(a *goAssign, at *Site) bool {
	if a.op != goOpDeclare && a.op != goOpVar {
		return false
	}
	return !fr.goCovers(a.file, a.line, a.col, at)
}

// assigned: a local assignment that is no call gives a source's object: a
// composite literal of a made type, or a copy of another local or
// parameter, read where the assignment is.
func (fl *goFlow) assigned(at *Site, a *goAssign, depth int) bool {
	v := strings.TrimSpace(a.value)
	switch {
	case v == "":
		return false
	case fl.madeText(a.file, v):
		return true
	case identMatch(v) || strings.Count(v, ".") == 1 && !strings.ContainsAny(v, "()[]{} "):
		return fl.name(goAt(at, a.line, a.col), v, "", depth+1)
	}
	return false
}

// field: `base.field` holds a source's object when a definition of it that
// reaches the site does: base's composite literal, when any of its elements
// (nested literals included) holds one, as OpenGrep taints the whole
// object (`h := &holder{Thing: acme.NewThing(1)}`, then `h.Thing.Seal()`);
// or a later store to the field (`h.Thing = acme.Other()` overwrites it).
func (fl *goFlow) field(at *Site, base, field string, depth int) bool {
	defs := fl.baseDefs(at, base, field, depth)
	for i := range fl.fr.GoValueFacts[at.File] {
		v := &fl.fr.GoValueFacts[at.File][i]
		if v.Kind != goFactStore || v.Function != at.Caller || v.Receiver != base || len(v.Fields) != 1 || v.Fields[0].Name != field {
			continue
		}
		if v.Line > at.Line || v.Line == at.Line && v.StartCol >= at.Col {
			continue
		}
		f := v.Fields[0]
		defs = append(defs, goDef{at.File, v.Line, v.StartCol, func() bool { return fl.valueHolds(at, f.Value, f.Line, f.StartCol, depth) }})
	}
	slices.SortFunc(defs, func(x, y goDef) int { return cmp.Or(cmp.Compare(x.line, y.line), cmp.Compare(x.col, y.col)) })
	held, _ := fl.fr.goReaching(at, defs)
	return held
}

// baseDefs are the assignments of a field's local written before the site:
// a composite literal holds the field when an element does, a copy of
// another local when that local's field does, and a call's result nothing
// the flow can read.
func (fl *goFlow) baseDefs(at *Site, base, field string, depth int) []goDef {
	var defs []goDef
	calls := map[int]bool{}
	for _, t := range fl.fr.VarSites[pairKey(at.Caller, base)] {
		if t.File == at.File && t.before(at) {
			calls[t.Line] = true
			defs = append(defs, goDef{t.File, t.Line, t.Col, func() bool { return false }})
		}
	}
	for _, a := range fl.fr.GoAssigns[pairKey(at.Caller, base)] {
		if a.file != at.File || a.line > at.Line || a.line == at.Line && a.col >= at.Col {
			continue
		}
		if fl.fr.goShadows(a, at) {
			defs = slices.DeleteFunc(defs, func(d goDef) bool { return d.line == a.line })
			continue
		}
		if calls[a.line] {
			continue
		}
		defs = append(defs, goDef{a.file, a.line, a.col, func() bool {
			if v := strings.TrimSpace(a.value); identMatch(v) {
				return fl.field(goAt(at, a.line, a.col), v, field, depth+1)
			}
			return fl.literalHolds(at, a, depth)
		}})
	}
	return defs
}

// literalHolds: an element of the composite literal (or one nested in it)
// the assignment a writes holds a source's object.
func (fl *goFlow) literalHolds(at *Site, a *goAssign, depth int) bool {
	for i := range fl.fr.GoValueFacts[a.file] {
		v := &fl.fr.GoValueFacts[a.file][i]
		if v.Kind != goFactComposite || v.Function != at.Caller || !goSpanHolds(a.line, a.col, a.endLine, a.end, v.Line, v.StartCol) {
			continue
		}
		for _, f := range v.Fields {
			if fl.valueHolds(at, f.Value, f.Line, f.StartCol, depth) {
				return true
			}
		}
	}
	return false
}

// valueHolds: an expression written at the position holds a source's
// object: a made composite, a call that returns one, or a local that does.
func (fl *goFlow) valueHolds(at *Site, value string, line, col, depth int) bool {
	if fl.madeText(at.File, value) {
		return true
	}
	if cs := fl.fr.goCallStarting(at.Caller, at.File, line, col); cs != nil {
		return fl.site(cs, depth+1)
	}
	return identMatch(value) && fl.name(goAt(at, line, col), value, "", depth+1)
}

// goCallStarting is the call of the function written at the position.
func (fr *Frag) goCallStarting(caller, file string, line, col int) *Site {
	for _, t := range fr.ByCaller[caller] {
		if t.File == file && t.Line == line && t.ColOK && t.Col == col && !t.GoValue {
			return t
		}
	}
	return nil
}

// goAt is a position in the site's function, for reading what a name held
// there.
func goAt(s *Site, line, col int) *Site {
	return &Site{File: s.File, Caller: s.Caller, Line: line, LineOK: true, Col: col, ColOK: true, Go: true}
}

// goTypeIn: the Go class is one of types, written with its import path or
// with its package's name.
func goTypeIn(cls string, types []string) bool {
	if cls == "" {
		return false
	}
	short := goShortClass(cls)
	for _, t := range types {
		if cls == t || short == t {
			return true
		}
	}
	return false
}

// madeText: an argument written in file as a composite literal of a made
// type. With the fragment's import specs, the literal's qualifier names the
// type's package when the file imports the path without an alias and no
// other import binds the qualifier: its implicit name, or a package name
// that is not the path's last element (`jose` at .../go-jose/v4). A literal
// through an aliased import does not: OpenGrep's `import "p"` clause does
// not cover an aliased import of p, nor does a pattern written `p.T{...}`
// match `alias.T{...}` (pinned by testdata/go_object/src/alias.go). Without
// import specs, the qualifier is compared with the path's implicit name.
func (fl *goFlow) madeText(file, text string) bool {
	m := rxGoSourceComposite.FindStringSubmatch(goLiteralHead(strings.TrimSpace(text)))
	if m == nil {
		return false
	}
	dot := strings.IndexByte(m[1], '.')
	if dot <= 0 {
		return false
	}
	qual, typ := m[1][:dot], m[1][dot:]
	for _, t := range fl.o.Made {
		if t == m[1] {
			return true
		}
		path, ok := strings.CutSuffix(t, typ)
		switch {
		case !ok:
		case !fl.fr.GoImports:
			if goShortClass(t) == m[1] {
				return true
			}
		case fl.fr.goQualifies(file, qual, path):
			return true
		}
	}
	return false
}

// goQualifies: in file, the package qualifier qual names the import path,
// which the file imports without an alias.
func (fr *Frag) goQualifies(file, qual, path string) bool {
	aliases := fr.GoAliases[file]
	if _, ok := aliases[qual]; ok {
		return false
	}
	if !fr.GoImportPaths[file][path] || slices.Contains(slices.Collect(maps.Values(aliases)), path) {
		return false
	}
	if goImplicitImportName(path) == qual {
		return true
	}
	for p := range fr.GoImportPaths[file] {
		if p != path && goImplicitImportName(p) == qual {
			return false
		}
	}
	return true
}

// goLiteralHead writes a composite literal `&T{...fields...}` as `&T{...}`.
func goLiteralHead(text string) string {
	if i := strings.IndexByte(text, '{'); i > 0 && strings.HasSuffix(text, "}") {
		return text[:i] + "{...}"
	}
	return text
}

// site: the call t returns a source's object, as a call matching one of
// the origin's factories, or a call whose receiver or argument holds one.
func (fl *goFlow) site(t *Site, depth int) bool {
	if held, ok := fl.done[t]; ok {
		return held
	}
	fl.done[t] = false // a cycle holds nothing
	held := fl.o.assignedFrom(t, t.AssignedVar, fl.fr) || fl.returnsMade(t)
	if !held && depth <= goFlowDepth {
		held = fl.receiver(t, depth)
		for _, i := range t.ParamIdx {
			if held {
				break
			}
			if p := t.Params[i]; p != nil {
				held = fl.nodes(t, p.SourceNodes, depth+1)
			}
		}
	}
	fl.done[t] = held
	return held
}

// returnsMade: t calls a function of the same file that returns a
// composite literal of a made type (`return &acme.Client{...}`).
func (fl *goFlow) returnsMade(t *Site) bool {
	if t.GoCallee == "" || len(fl.o.Made) == 0 || fl.fr.CallerFile[t.GoCallee] != t.File {
		return false
	}
	for i := range fl.fr.GoReturns[t.GoCallee] {
		if n := &fl.fr.GoReturns[t.GoCallee][i]; n.Type == "EXPRESSION" && fl.madeText(t.File, n.Value) {
			return true
		}
	}
	return false
}

// nodes: an argument's source nodes trace to a source's object.
func (fl *goFlow) nodes(s *Site, nodes []SourceNode, depth int) bool {
	if depth > goFlowDepth {
		return false
	}
	for i := range nodes {
		n := &nodes[i]
		switch n.Type {
		case srcCallResult:
			if t := fl.fr.goCallAt(s, n); t != nil {
				if fl.site(t, depth) {
					return true
				}
				continue
			}
		case srcParameter:
			if n.ParameterIndex != nil && fl.callers(s, *n.ParameterIndex, depth+1) {
				return true
			}
			continue
		}
		if fl.nodes(s, n.SourceNodes, depth) {
			return true
		}
	}
	return false
}

// callers: a caller written in the same file passes, for the parameter at
// index of s's function, a source's object (OpenGrep's taint follows no
// other file).
func (fl *goFlow) callers(s *Site, index, depth int) bool {
	if !fl.fr.ResolveParams || depth > goFlowDepth {
		return false
	}
	for _, cs := range fl.fr.Incoming[s.Caller] {
		if cs.File != s.File {
			continue
		}
		if p := cs.Params[index]; p != nil && (fl.madeText(cs.File, p.ArgumentExpression) || fl.nodes(cs, p.SourceNodes, depth)) {
			return true
		}
	}
	return false
}

// goChained is the call a Go method call is chained on: the longest call of
// the same function that starts where s starts and ends before it.
func (fr *Frag) goChained(s *Site) *Site {
	var best *Site
	for _, t := range fr.ByCaller[s.Caller] {
		if t == s || t.File != s.File || t.Line != s.Line || t.Col != s.Col || !t.ColOK || !s.ColOK || !rustEndsBefore(t, s) {
			continue
		}
		if best == nil || rustEndsBefore(best, t) {
			best = t
		}
	}
	return best
}

// goCallAt is the call a CALL_RESULT node of an argument at s names: a call
// of the same function on the node's line whose written text is the node's.
func (fr *Frag) goCallAt(s *Site, n *SourceNode) *Site {
	if n.Location == nil {
		return nil
	}
	want := strings.Join(strings.Fields(n.Value), "")
	for _, t := range fr.ByCaller[s.Caller] {
		if t.File != s.File || t.Line != n.Location.Line || !t.ColOK || t.EndLine > t.Line {
			continue
		}
		line, ok := fr.Lines[t.File][t.Line]
		if !ok || t.Col < 1 || t.EndCol-1 > len(line) || t.EndCol <= t.Col {
			continue
		}
		if strings.Join(strings.Fields(line[t.Col-1:t.EndCol-1]), "") == want {
			return t
		}
	}
	return nil
}

// goParamNames are a Go fragment's parameter names, by function.
func goParamNames(frag *FragmentJSON) map[string][]string {
	out := map[string][]string{}
	for i := range frag.Functions {
		if f := &frag.Functions[i]; len(f.ParameterNames) > 0 {
			out[f.Key] = f.ParameterNames
		}
	}
	return out
}

// flowObject is an entry's flow when its insides are a taint rule's object
// sources (compile_py_ext.go objectFlowSinks).
const flowObject = "object"

// goProducerHolds: the receiver or argument o's metavariable binds at a Go
// site is a local some earlier assignment in the site's function assigned
// from a call matching one of o's producers (compile_go_producer.go). A
// later reassignment does not end it, as OpenGrep's pattern-inside reads
// `$V := f(..) ... sink($V)`.
func (fr *Frag) goProducerHolds(e *Entry, s *Site, o *Origin) bool {
	name := fr.originName(e, s, o)
	if !identMatch(name) || !s.LineOK {
		return false
	}
	for _, a := range fr.VarSites[pairKey(s.Caller, name)] {
		if a.before(s) && o.assignedFrom(a, name, fr) && fr.goInScope(a, s, name) {
			return true
		}
	}
	return false
}

// goInScope: the site s is in the rest of the block the assignment a is
// written in, or in a block nested in it, as OpenGrep's `...` after a
// pattern-inside runs (it does not mind a nested block shadowing the
// name). The fragment holds no block extents, so the source lines tell: s is
// not indented less than a, and no other assignment of the name indented as
// a is written between them. Such an assignment may open a sibling block
// (`block, err = des.NewCipher(..)` in the next case of a switch), which
// OpenGrep does not reach; it may also reassign in the same block, which
// OpenGrep still reports, but the lines cannot tell the two apart, and a
// finding with another algorithm's name is worse than a missed one. Without
// the lines, s is taken to be in scope.
func (fr *Frag) goInScope(a, s *Site, name string) bool {
	if in, ok := fr.goBlockScope(a, s); ok {
		return in
	}
	da, okA := fr.goIndent(a)
	ds, okS := fr.goIndent(s)
	if !okA || !okS {
		return true
	}
	if ds < da {
		return false
	}
	for _, b := range fr.VarSites[pairKey(s.Caller, name)] {
		if b == a || !a.before(b) || !b.before(s) {
			continue
		}
		if db, ok := fr.goIndent(b); ok && db == da {
			return false
		}
	}
	return true
}

// goIndent is the width of the leading white space of a site's line.
func (fr *Frag) goIndent(s *Site) (int, bool) {
	line, ok := fr.Lines[s.File][s.Line]
	if !ok {
		return 0, false
	}
	return len(line) - len(strings.TrimLeft(line, " \t")), true
}

// originName is the text the metavariable of o binds at s: the receiver,
// or the argument it names.
func (fr *Frag) originName(e *Entry, s *Site, o *Origin) string {
	if e.receiverMetavar() == o.Metavar {
		return fr.receiverText(s)
	}
	for i := range e.Args {
		if a := &e.Args[i]; a.Kind == strMetavar && a.Name != nil && *a.Name == o.Metavar {
			if p := a.param(s.Params); p != nil {
				return strings.TrimSpace(p.ArgumentExpression)
			}
			return ""
		}
	}
	return ""
}

// before: the call s is written before the call t, both positioned.
func (s *Site) before(t *Site) bool {
	if !s.LineOK || s.Line > t.Line {
		return false
	}
	return s.Line < t.Line || s.ColOK && t.ColOK && s.Col < t.Col
}

// goAssign is one name an assignment of a Go function body binds
// (go_values kind assign): where, how (":=", "=", "var"), and the one
// right-hand expression as written, "" when there are several.
type goAssign struct {
	file, op, value string
	line, col       int
	endLine, end    int // where the statement ends (end column exclusive)
	pos             int // the name's place on the left-hand side
}

// goAssigns indexes a fragment's assignments by (function, name).
func goAssigns(frag *FragmentJSON) map[string][]*goAssign {
	out := map[string][]*goAssign{}
	for file, values := range frag.GoValues {
		for i := range values {
			v := &values[i]
			if v.Kind != goFactAssign {
				continue
			}
			for pos, name := range v.Names {
				if name == "_" {
					continue
				}
				k := pairKey(v.Function, name)
				out[k] = append(out[k], &goAssign{
					file: file, op: v.Op, value: v.Value, line: v.Line, col: v.StartCol,
					endLine: max(v.EndLine, v.Line), end: v.EndCol, pos: pos,
				})
			}
		}
	}
	for _, l := range out {
		slices.SortFunc(l, func(a, b *goAssign) int { return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.col, b.col)) })
	}
	return out
}

// goBlockOf is the innermost block of the file that holds the position.
func (fr *Frag) goBlockOf(file string, line, col int) *graphfrag.GraphFragmentGoBlock {
	var best *graphfrag.GraphFragmentGoBlock
	for i := range fr.GoBlocks[file] {
		b := &fr.GoBlocks[file][i]
		if !goSpanHolds(b.StartLine, b.StartCol, b.EndLine, b.EndCol, line, col) {
			continue
		}
		if best == nil || goSpanHolds(best.StartLine, best.StartCol, best.EndLine, best.EndCol, b.StartLine, b.StartCol) {
			best = b
		}
	}
	return best
}

// goBlockScope reads goInScope from the fragment's blocks (1.36), which tell
// exactly: s lies in a's innermost block, which holds the blocks nested in
// it and no sibling; for an assignment in the header of an if, for, switch
// or select, in that statement's own blocks. ok is false without blocks.
func (fr *Frag) goBlockScope(a, s *Site) (in, ok bool) {
	if !fr.HasGoBlocks {
		return false, false
	}
	if chain := fr.goHeaderBlocks(a); chain != nil {
		for _, b := range chain {
			if goSpanHolds(b.StartLine, b.StartCol, b.EndLine, b.EndCol, s.Line, s.Col) {
				return true, true
			}
		}
		return false, true
	}
	if b := fr.goBlockOf(a.File, a.Line, a.Col); b != nil {
		return goSpanHolds(b.StartLine, b.StartCol, b.EndLine, b.EndCol, s.Line, s.Col), true
	}
	return false, false
}

// rxGoHeader matches the start of an if, for, switch or select statement
// up to an assignment in its header.
var rxGoHeader = regexp.MustCompile(`^(?:\}\s*else\s+)?(if|for|switch|select)\b`)

// goHeaderBlocks are the blocks of the statement whose header holds the
// call a (`if block, err := blk.NewCipher(k); err == nil {`): the names it
// assigns are scoped to that statement, as Go and OpenGrep read them. They
// are the first block written after a, then each block that continues the
// statement: for an if, an else that opens on the line where the previous
// block closes; for a switch or select, each later case clause, written at
// the first clause's column, until a line of the function with calls at
// the statement's own depth shows the statement has ended (blank lines and
// comments between clauses are none). A for has its body only. nil when a
// is no header assignment.
func (fr *Frag) goHeaderBlocks(a *Site) []*graphfrag.GraphFragmentGoBlock {
	line, ok := fr.Lines[a.File][a.Line]
	if !ok || !a.ColOK || a.Col < 1 || a.Col-1 > len(line) {
		return nil
	}
	m := rxGoHeader.FindStringSubmatch(strings.TrimSpace(line[:a.Col-1]))
	if m == nil {
		return nil
	}
	depth := len(line) - len(strings.TrimLeft(line, " \t"))
	blocks := fr.GoBlocks[a.File]
	var chain []*graphfrag.GraphFragmentGoBlock
	for i := range blocks {
		b := &blocks[i]
		if b.StartLine < a.Line || b.StartLine == a.Line && b.StartCol <= a.Col {
			continue
		}
		if len(chain) == 0 {
			chain = append(chain, b)
			continue
		}
		prev := chain[len(chain)-1]
		if goSpanHolds(prev.StartLine, prev.StartCol, prev.EndLine, prev.EndCol, b.StartLine, b.StartCol) {
			continue // nested in a block of the statement
		}
		if !fr.goContinues(m[1], a.File, depth, chain[0], prev, b) {
			break
		}
		chain = append(chain, b)
	}
	return chain
}

// goContinues: the block b continues the statement a header of kind opened,
// after its block prev.
func (fr *Frag) goContinues(kind, file string, depth int, first, prev, b *graphfrag.GraphFragmentGoBlock) bool {
	switch kind {
	case "if":
		return b.StartLine == prev.EndLine
	case "switch", "select":
		if b.StartCol != first.StartCol || b.StartLine <= prev.EndLine {
			return false
		}
		for l := prev.EndLine + 1; l < b.StartLine; l++ {
			if text, ok := fr.Lines[file][l]; ok && len(text)-len(strings.TrimLeft(text, " \t")) <= depth {
				return false
			}
		}
		return true
	}
	return false
}

// goSpanHolds: the position lies in the span (end exclusive).
func goSpanHolds(sl, sc, el, ec, line, col int) bool {
	after := line > sl || line == sl && col >= sc
	before := line < el || line == el && col < ec
	return after && before
}

// goCallValues are the calls a Go argument's source nodes trace to
// (`c := shapes.P384(); f(c)`, `f(wrap(shapes.P256()))`), as written: a
// taint source that is a call (`$F()` with a metavariable-regex on $F,
// compile_go_flow.go) matches their text.
func goCallValues(p *Param) []valueHow {
	var out []valueHow
	walkNodes(p.SourceNodes, func(n *SourceNode) {
		if n.Type == srcCallResult && n.Value != "" {
			out = append(out, valueHow{"resolved", n.Value})
		}
	})
	return out
}
