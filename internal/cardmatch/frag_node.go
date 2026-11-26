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

// The node (JavaScript/TypeScript) fragment: its call sites read in reach's
// own terms. It shares nothing with loadSites: a node site's callee is its
// target key, never read through parseKey's Java regex.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/cardmatch/internal/jspat"
)

const ecosystemNode = "node"

// node: the fragment is read as a node fragment (newNodeFrag).
func (f *FragmentJSON) node() bool {
	return f.ScanMetadata.Ecosystem == ecosystemNode
}

// nodeSite is what a node site carries beyond Site.
type nodeSite struct {
	key     string // reach's callee key (target_key)
	chainID string
	// unbound: reach bound the callee to no import and no typed receiver,
	// so its key is the caller's own module path and the method name.
	unbound bool
	hasArgs bool // the fragment lists the call's arguments
	// The arguments parsed once (nodeArgs); argsOK is false when one of them
	// is missing from the fragment.
	parsed bool
	args   []jspat.Concrete
	argsOK bool
	// texts and resolved are each argument's text and resolved value as
	// reach wrote them.
	texts, resolved []string
	// lit and litWord: an object literal site's source (the outermost
	// literal's) and the word its object starts at, to place a focus inside
	// it.
	lit     *textPos
	litWord int
	// candidates: the modules a merged module object the receiver holds
	// combines (Object.assign of requires).
	candidates []string
	// An object literal assigned to a variable: the variable and where the
	// declarator or assignment target starts.
	assignedLine, assignedCol int
}

// nodeFrag is what only the node pass reads of a fragment.
type nodeFrag struct {
	chains map[string][]*Site // caller + chain id -> links, innermost first
	vars   map[string][]*Site // caller + variable -> the sites assigned to it, in source order
	// destructured: caller + name -> the sites whose result a destructuring
	// declaration on the call's line takes the name from, in source order.
	destructured map[string][]*Site
	// objects: a site per object literal, outermost and nested
	// (siteObjectLiteral), matched by literal entries only.
	objects []*Site
	imports map[string][]graphfrag.GraphFragmentImport
	// functions: the fragment's functions by key; enclosing caches, per
	// function, the functions of its file whose lines hold it, tightest
	// first (enclosingFunctions).
	functions map[string]*FunctionJSON
	// byFile: the keys of the fragment's functions by file, so finding a
	// function's enclosing ones reads its own file only.
	byFile    map[string][]string
	enclosing map[string][]string
}

// newNodeFrag builds the Frag of a node fragment from its external calls. A
// site's Class is the callee's owner in reach's terms (`acme-crypto.AES`,
// `acme-crypto.x.Y` for a constructor) and Method its name.
func newNodeFrag(frag *FragmentJSON) *Frag {
	fns := make(map[string]*FunctionJSON, len(frag.Functions))
	byFile := map[string][]string{}
	for i := range frag.Functions {
		fn := &frag.Functions[i]
		fns[fn.Key] = fn
		byFile[fn.FilePath] = append(byFile[fn.FilePath], fn.Key)
	}
	data := &nodeFrag{
		chains: map[string][]*Site{}, vars: map[string][]*Site{}, destructured: map[string][]*Site{}, imports: frag.Imports,
		functions: fns, byFile: byFile, enclosing: map[string][]string{},
	}
	fr := &Frag{
		Node: true, NodeData: data, Incoming: map[string][]*Site{}, ByCaller: map[string][]*Site{},
		CallerFile: map[string]string{}, Lines: frag.SourceLines,
	}
	for i := range frag.ExternalCalls {
		s := nodeSiteOf(&frag.ExternalCalls[i], fns[frag.ExternalCalls[i].CallerKey])
		s.ID = len(fr.Sites)
		n := s.node
		fr.Sites = append(fr.Sites, s)
		fr.ByCaller[s.Caller] = append(fr.ByCaller[s.Caller], s)
		if _, ok := fr.CallerFile[s.Caller]; !ok {
			fr.CallerFile[s.Caller] = s.File
		}
		if n.chainID != "" {
			k := pairKey(s.Caller, n.chainID)
			data.chains[k] = append(data.chains[k], s)
		}
		if s.AssignedVar != "" {
			k := pairKey(s.Caller, s.AssignedVar)
			data.vars[k] = append(data.vars[k], s)
		}
		for _, name := range destructuredNames(frag.SourceLines, s) {
			k := pairKey(s.Caller, name)
			data.destructured[k] = append(data.destructured[k], s)
		}
	}
	for _, s := range nodeReadSites(frag.PropertyReads, fns) {
		s.ID = len(fr.Sites)
		fr.Sites = append(fr.Sites, s)
		fr.ByCaller[s.Caller] = append(fr.ByCaller[s.Caller], s)
		if s.AssignedVar != "" {
			k := pairKey(s.Caller, s.AssignedVar)
			data.vars[k] = append(data.vars[k], s)
		}
	}
	nodeIncoming(frag, fr)
	data.objects = nodeObjectSites(frag.ObjectLiterals)
	for i, o := range data.objects {
		o.ID = len(fr.Sites) + i // after the calls: findings are told apart by site
		if o.AssignedVar != "" {
			k := pairKey(o.Caller, o.AssignedVar)
			data.vars[k] = append(data.vars[k], o)
		}
	}
	for _, links := range data.chains {
		// Every link of a chain starts where the chain does: the inner link
		// ends first.
		sort.SliceStable(links, func(i, j int) bool { return endBefore(links[i], links[j]) })
	}
	for _, m := range []map[string][]*Site{data.vars, data.destructured} {
		for _, sites := range m {
			sort.SliceStable(sites, func(i, j int) bool { return startBefore(sites[i], sites[j]) })
		}
	}
	return fr
}

// nodeSiteOf is the site of one external call of a node fragment; fn is its
// caller, nil when the fragment does not list it.
func nodeSiteOf(e *ExternalJSON, fn *FunctionJSON) *Site {
	owner, name := nodeCallee(e.TargetKey, e.MethodName)
	s := &Site{
		Caller: e.CallerKey, Class: owner, Method: name, Raw: e.Raw, Resolution: e.Resolution,
		Kind: "external", ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar, EndLine: e.EndLine,
	}
	n := &nodeSite{key: e.TargetKey, chainID: e.ChainID, hasArgs: e.EntryCall != nil, candidates: e.CandidateModules}
	if fn != nil {
		s.File, s.CallerPackage = fn.FilePath, fn.Package
		// reach keys a call of a method of a value nothing typed by the
		// caller's module (`m.digest`), or by the bare name (`digest`) when
		// the module declares a function of that key.
		n.unbound = fn.Package != "" && (e.TargetKey == fn.Package+"."+e.MethodName || e.TargetKey == e.MethodName)
	}
	if e.Line != nil {
		s.Line, s.LineOK = *e.Line, true
	}
	if e.StartCol != nil {
		s.Col, s.ColOK = *e.StartCol, true
	}
	if e.EndCol != nil {
		s.EndCol = *e.EndCol
	}
	s.Params, s.ParamIdx, s.ParamOrder = paramMap(e.EntryCall)
	// reach writes no arity for a node call: the arguments it lists are all
	// of them.
	s.Arity = e.Arity
	if k := len(s.ParamIdx); k > 0 && s.ParamIdx[k-1]+1 > s.Arity {
		s.Arity = s.ParamIdx[k-1] + 1
	}
	s.node = n
	return s
}

func endBefore(a, b *Site) bool {
	al, bl := max(a.EndLine, a.Line), max(b.EndLine, b.Line)
	if al != bl {
		return al < bl
	}
	return a.EndCol < b.EndCol
}

func startBefore(a, b *Site) bool {
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Col < b.Col
}

// nodeCallee splits a node callee key into the callee's owner and name:
//
//	acme-crypto.AES.encrypt   -> acme-crypto.AES, encrypt
//	acme-crypto.x.(Y).<init>  -> acme-crypto.x.Y, <init>
//	(SubtleCrypto).digest     -> SubtleCrypto, digest
//
// The module/member boundary inside the owner is not recovered (specifiers
// hold dots: "hash.js"); entries carry full keys, so nothing needs it.
func nodeCallee(targetKey, methodName string) (owner, name string) {
	owner, name = "", methodName
	if i := strings.LastIndexByte(targetKey, '.'); i >= 0 && (methodName == "" || targetKey[i+1:] == methodName) {
		owner, name = targetKey[:i], targetKey[i+1:]
	}
	return strings.NewReplacer("(", "", ")", "").Replace(owner), name
}

// nodeArgs are the site's arguments parsed once, with the values reach
// resolved them to; false when the fragment does not list them all.
func (s *Site) nodeArgs() ([]jspat.Concrete, bool) {
	n := s.node
	if n.parsed {
		return n.args, n.argsOK
	}
	n.parsed = true
	if !n.hasArgs {
		return nil, false
	}
	texts, resolved := make([]string, s.Arity), make([]string, s.Arity)
	split := false
	args := make([]jspat.Concrete, s.Arity)
	for i := range args {
		p := s.Params[i]
		if p == nil || p.ArgumentExpression == "" {
			return nil, false
		}
		texts[i], resolved[i] = p.ArgumentExpression, p.ResolvedValue
		node := &jspat.Node{Kind: jspat.Opaque, Text: p.ArgumentExpression}
		if nodes := jspat.ParseConcreteArgs(p.ArgumentExpression); len(nodes) == 1 {
			node = nodes[0]
		} else {
			split = true
		}
		args[i] = jspat.Concrete{Node: node, Resolved: jsLiteralValue(p.ResolvedValue)}
	}
	if split {
		// reach v0.1.1 lists the arguments after a shift (`f(a, 1 << 14, 8)`)
		// as one text: the list read whole has them all. Only the arguments
		// before the joined one keep their resolved values.
		whole := jspat.ParseConcreteArgs(strings.Join(texts, ", "))
		joined := make([]jspat.Concrete, len(whole))
		jtexts, jresolved := make([]string, len(whole)), make([]string, len(whole))
		keep := true
		for i, node := range whole {
			joined[i].Node, jtexts[i] = node, node.Text
			keep = keep && i < len(args) && norm(texts[i]) == norm(node.Text)
			if keep {
				joined[i].Resolved, jtexts[i], jresolved[i] = args[i].Resolved, texts[i], resolved[i]
			}
		}
		args, texts, resolved = joined, jtexts, jresolved
	}
	n.args, n.argsOK, n.texts, n.resolved = args, true, texts, resolved
	return args, true
}

// jsLiteralValue is a resolved value as jspat compares it: a string's
// content, anything else as reach wrote it.
func jsLiteralValue(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		if s, err := strconv.Unquote(v); err == nil {
			return s
		}
		return v[1 : len(v)-1]
	}
	return v
}

// argIndex is the index of the top-level argument a binding is, -1 when it
// is not one (a part of an argument, or a callee segment).
func (s *Site) argIndex(v jspat.Value) int {
	args, _ := s.nodeArgs()
	for i, a := range args {
		if v.Node != nil && a.Node == v.Node {
			return i
		}
	}
	return -1
}

// producer is the site whose value the receiver of s is: via "var" the last
// assignment of s's receiver variable before s in the same function, via
// "chain" the previous link of s's chain. nil when there is none.
func (fr *Frag) producer(s *Site, via string) *Site {
	switch via {
	case viaVar:
		if s.ReceiverVar == "" {
			return nil
		}
		return fr.varProducer(s, s.ReceiverVar)
	case viaChain:
		if s.node.chainID == "" {
			return nil
		}
		var prev *Site
		for _, l := range fr.NodeData.chains[pairKey(s.Caller, s.node.chainID)] {
			if l == s {
				return prev
			}
			prev = l
		}
	}
	return nil
}

// varProducer is the call whose result the variable name holds at s: the
// last call of s's function before s assigned to it or, when the function
// assigns it none, the last one before s of the tightest function around it
// that assigns it (a closure's captured `ecdh`), else the last one the file's
// module scope assigns to it (a module-level `const w = new W()` used inside
// a function, which OpenGrep's `...` reaches).
func (fr *Frag) varProducer(s *Site, name string) *Site {
	var last *Site
	for _, a := range fr.NodeData.vars[pairKey(s.Caller, name)] {
		if a != s && startBefore(a, s) {
			last = a
		}
	}
	if last != nil || s.CallerPackage == "" {
		return last
	}
	for _, outer := range fr.NodeData.enclosingFunctions(s.Caller) {
		for _, a := range fr.NodeData.vars[pairKey(outer, name)] {
			if startBefore(a, s) {
				last = a
			}
		}
		if last != nil {
			return last
		}
	}
	module := s.CallerPackage + "." + nodeModuleFunction
	if module == s.Caller {
		return nil
	}
	for _, a := range fr.NodeData.vars[pairKey(module, name)] {
		if last == nil || startBefore(a, s) {
			last = a
		}
	}
	return last
}

// enclosingFunctions are the functions of caller's file whose lines strictly
// hold caller's, tightest first, the module function left out. A fragment
// whose functions carry no lines gives none.
func (d *nodeFrag) enclosingFunctions(caller string) []string {
	if out, ok := d.enclosing[caller]; ok {
		return out
	}
	var out []string
	fn := d.functions[caller]
	if fn != nil && fn.StartLine > 0 && fn.EndLine >= fn.StartLine {
		for _, key := range d.byFile[fn.FilePath] {
			f := d.functions[key]
			// Spans are lines only (fragments carry no function columns
			// before graph-fragment-1.38), so a function on exactly the
			// caller's lines cannot be told from a sibling and is not taken
			// as enclosing it: a captured variable of a one-line closure
			// (minified code) is not followed.
			if key == caller || strings.HasSuffix(key, "."+nodeModuleFunction) ||
				f.StartLine > fn.StartLine || f.EndLine < fn.EndLine || f.EndLine-f.StartLine == fn.EndLine-fn.StartLine {
				continue
			}
			out = append(out, key)
		}
		sort.Slice(out, func(i, j int) bool {
			a, b := d.functions[out[i]], d.functions[out[j]]
			if sa, sb := a.EndLine-a.StartLine, b.EndLine-b.StartLine; sa != sb {
				return sa < sb
			}
			return out[i] < out[j]
		})
	}
	d.enclosing[caller] = out
	return out
}

// nodeModuleFunction is the name reach gives a Node file's module-level code.
const nodeModuleFunction = "<module>"

// innerLink: s is a link of t's chain inside t (any link before t), so the
// value s makes is part of t's receiver.
func (fr *Frag) innerLink(s, t *Site) bool {
	if t.node.chainID == "" || s.node.chainID != t.node.chainID || s.Caller != t.Caller {
		return false
	}
	for _, l := range fr.NodeData.chains[pairKey(t.Caller, t.node.chainID)] {
		switch l {
		case t:
			return false
		case s:
			return true
		}
	}
	return false
}

// notImportsHit: the site's file imports one of the modules at or before
// the site's line. A fragment without node imports (reach v0.1.1 writes
// none) never hits.
func (fr *Frag) notImportsHit(s *Site, modules []string) bool {
	if len(modules) == 0 {
		return false
	}
	for _, im := range fr.NodeData.imports[s.File] {
		if inList(im.Module, modules) && (im.Line == 0 || !s.LineOK || im.Line <= s.Line) {
			return true
		}
	}
	return false
}

// destructuringDecl is a declaration that destructures what follows it, as
// the text of a line before a call: `const { a, b: c } = ` (`await` allowed).
var destructuringDecl = regexp.MustCompile(`(?:^|[;{(\s])(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*(?:await\s+)?$`)

// destructuredNames are the local names a destructuring declaration written
// on the site's line, right before the call, takes from the call's result
// (`const { a, b: c, d = 1, ...e } = f()` -> a, c, d, e). A declaration that
// spans lines or nests patterns gives none.
func destructuredNames(lines map[string]map[int]string, s *Site) []string {
	line, ok := lines[s.File][s.Line]
	if !ok || !s.ColOK || s.Col < 1 || s.Col-1 > len(line) {
		return nil
	}
	// The declaration ends right before the call, so only the tail of the
	// line can hold it. Matching the whole prefix costs a pass over the line
	// per site, which is quadratic on a one-line minified bundle.
	before, start := line[:s.Col-1], 0
	if len(before) > maxDestructuringDeclBytes {
		start = len(before) - maxDestructuringDeclBytes
		before = before[start:]
	}
	idx := destructuringDecl.FindStringSubmatchIndex(before)
	if idx == nil {
		return nil
	}
	// A cut window's start is not the line's start: a match `^` anchors there
	// must have a boundary before it in the line, or the keyword is the tail
	// of a longer identifier (`xconst { a } = `).
	if start > 0 && idx[0] == 0 && !isDeclBoundary(before[0]) && !isDeclBoundary(line[start-1]) {
		return nil
	}
	var out []string
	for _, part := range strings.Split(before[idx[2]:idx[3]], ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "..."))
		if _, local, ok := strings.Cut(part, ":"); ok {
			part = local
		}
		part, _, _ = strings.Cut(part, "=")
		if part = strings.TrimSpace(part); jsIdentRe.MatchString(part) {
			out = append(out, part)
		}
	}
	return out
}

// maxDestructuringDeclBytes bounds the text before a call searched for a
// destructuring declaration. A declaration longer than it gives no names.
const maxDestructuringDeclBytes = 1024

// isDeclBoundary reports whether c may precede a declaration keyword, as
// destructuringDecl's `[;{(\s]` (RE2's \s: tab, newline, form feed, carriage
// return, space).
func isDeclBoundary(c byte) bool {
	switch c {
	case ';', '{', '(', ' ', '\t', '\n', '\f', '\r':
		return true
	}
	return false
}

// jsIdentRe is a JavaScript identifier (ASCII).
var jsIdentRe = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// assigners are the sites of s's function before s whose result goes to
// name through via (producers).
func (fr *Frag) assigners(s *Site, name, via string) []*Site {
	m := fr.NodeData.vars
	if via == viaDestructure {
		m = fr.NodeData.destructured
	}
	var out []*Site
	for _, a := range m[pairKey(s.Caller, name)] {
		if a != s && startBefore(a, s) {
			out = append(out, a)
		}
	}
	return out
}

// siteObjectLiteral is the Kind of an object literal site.
const siteObjectLiteral = "object_literal"

// nodeObjectSites are the sites of a fragment's object literals: each
// outermost literal and every object nested in it (OpenGrep matches an
// object pattern on any object expression), in file and source order. A
// site's one argument is the object.
func nodeObjectSites(objects map[string][]graphfrag.GraphFragmentObjectLiteral) []*Site {
	files := make([]string, 0, len(objects))
	for f := range objects {
		files = append(files, f)
	}
	sort.Strings(files)
	var out []*Site
	for _, file := range files {
		for _, o := range objects[file] {
			out = append(out, literalSites(file, o)...)
		}
	}
	return out
}

// literalSites are the sites of one outermost object literal and the
// objects nested in it, outer first.
func literalSites(file string, o graphfrag.GraphFragmentObjectLiteral) []*Site {
	nodes := jspat.ParseConcreteArgs(o.Text)
	if len(nodes) != 1 || nodes[0].Kind != jspat.Object {
		return nil
	}
	var out []*Site
	pos := newTextPos(o)
	walkObjects(nodes[0], func(n *jspat.Node) {
		span := objectSpan{line: o.Line, col: o.StartCol, endLine: max(o.EndLine, o.Line), endCol: o.EndCol}
		word, ok := 0, true
		if len(out) > 0 || pos.from > 0 {
			span, ok = pos.at(n.Text)
			word = pos.from - 1
		}
		if !ok {
			return
		}
		s := objectSite(file, o.CallerKey, span, n)
		s.node.lit, s.node.litWord = pos, word
		if word == 0 && o.AssignedVar != "" {
			s.AssignedVar = o.AssignedVar
			s.node.assignedLine, s.node.assignedCol = o.Line, o.AssignStartCol
			if o.AssignLine != 0 {
				s.node.assignedLine = o.AssignLine
			}
		}
		out = append(out, s)
	})
	return out
}

// objectSpan is where an object literal is: start line and column, end line
// and end column (exclusive), 1-based.
type objectSpan struct{ line, col, endLine, endCol int }

func objectSite(file, caller string, sp objectSpan, n *jspat.Node) *Site {
	endLine := sp.endLine
	if endLine == sp.line {
		endLine = 0
	}
	return &Site{
		File: file, Caller: caller, Line: sp.line, LineOK: true, Col: sp.col, ColOK: true, EndCol: sp.endCol, EndLine: endLine,
		Kind: siteObjectLiteral, Arity: 1,
		Params: map[int]*Param{0: {ArgumentExpression: n.Text}}, ParamIdx: []int{0}, ParamOrder: []int{0},
		node: &nodeSite{hasArgs: true, parsed: true, argsOK: true, args: []jspat.Concrete{{Node: n}}, texts: []string{n.Text}, resolved: []string{""}},
	}
}

// walkObjects calls f on n and every object nested in it, outer first.
func walkObjects(n *jspat.Node, f func(*jspat.Node)) {
	if n == nil {
		return
	}
	if n.Kind == jspat.Object {
		f(n)
	}
	for _, k := range n.Kids {
		walkObjects(k, f)
	}
	for _, p := range n.Props {
		walkObjects(p.Value, f)
	}
}

// textPos finds a nested object in an object literal's source. jspat keeps
// normalised text (quotes, separators) and no offsets, so the object is
// found by its word characters (identifiers, numbers, string contents) in
// the source's, from the end of the previous one (objects come outer
// first, in source order), and starts at the `{` before its first word.
type textPos struct {
	lit   graphfrag.GraphFragmentObjectLiteral
	words string
	raw   []int // words index -> byte offset in lit.Text
	from  int
}

func newTextPos(o graphfrag.GraphFragmentObjectLiteral) *textPos {
	p := &textPos{lit: o}
	var b strings.Builder
	for i := 0; i < len(o.Text); i++ {
		if isWordByte(o.Text[i]) {
			b.WriteByte(o.Text[i])
			p.raw = append(p.raw, i)
		}
	}
	p.words = b.String()
	return p
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// at is where the object of text is.
func (p *textPos) at(text string) (objectSpan, bool) {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if isWordByte(text[i]) {
			b.WriteByte(text[i])
		}
	}
	words := b.String()
	if words == "" || p.from > len(p.words) {
		return objectSpan{}, false
	}
	k := p.wordIndex(p.from, words)
	if k < 0 {
		return objectSpan{}, false
	}
	p.from = k + 1
	start := strings.LastIndexByte(p.lit.Text[:p.raw[k]], '{')
	end := closingBrace(p.lit.Text, start)
	if start < 0 || end < 0 {
		return objectSpan{}, false
	}
	line, col := p.lineCol(start)
	endLine, endCol := p.lineCol(end + 1)
	return objectSpan{line: line, col: col, endLine: endLine, endCol: endCol}, true
}

// lineCol is the line and column (1-based) of byte off of the literal.
func (p *textPos) lineCol(off int) (int, int) {
	before := p.lit.Text[:off]
	nl := strings.Count(before, "\n")
	if nl == 0 {
		return p.lit.Line, p.lit.StartCol + off
	}
	return p.lit.Line + nl, off - strings.LastIndexByte(before, '\n')
}

// closingBrace is the offset of the `}` that closes the `{` at start, past
// strings and comments; -1 when there is none.
func closingBrace(text string, start int) int {
	if start < 0 {
		return -1
	}
	depth := 0
	for i := start; i < len(text); i++ {
		switch c := text[i]; c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		case '\'', '"', '`':
			i = skipString(text, i)
		case '/':
			i = skipComment(text, i)
		}
	}
	return -1
}

// skipString is the offset of the quote closing the string opened at i.
func skipString(text string, i int) int {
	q := text[i]
	for i++; i < len(text) && text[i] != q; i++ {
		if text[i] == '\\' {
			i++
		}
	}
	return i
}

// skipComment is the offset of the last byte of a comment starting at i (i
// itself when none does).
func skipComment(text string, i int) int {
	if i+1 >= len(text) {
		return i
	}
	switch text[i+1] {
	case '/':
		if j := strings.IndexByte(text[i:], '\n'); j >= 0 {
			return i + j
		}
		return len(text)
	case '*':
		if j := strings.Index(text[i+2:], "*/"); j >= 0 {
			return i + j + 3
		}
	}
	return i
}

// valueAt is where the value of text (a string, a name, a member chain) is
// inside the object starting at word: a string from quote to quote, else
// its run of word characters and dots.
func (p *textPos) valueAt(word int, text string) (objectSpan, bool) {
	if sp, ok := p.stringAt(word, text); ok {
		return sp, true
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if isWordByte(text[i]) {
			b.WriteByte(text[i])
		}
	}
	words := b.String()
	if words == "" || word < 0 || word > len(p.words) {
		return objectSpan{}, false
	}
	k := p.wordIndex(word, words)
	if k < 0 {
		return objectSpan{}, false
	}
	start, end, ok := p.valueRun(p.raw[k])
	if !ok {
		return objectSpan{}, false
	}
	line, col := p.lineCol(start)
	endLine, endCol := p.lineCol(end)
	return objectSpan{line: line, col: col, endLine: endLine, endCol: endCol}, true
}

// valueRun is the extent of the value whose first word character is at
// start: a string from quote to quote, else its run of word characters and
// dots.
func (p *textPos) valueRun(start int) (from, end int, ok bool) {
	text := p.lit.Text
	if q := text[max(start-1, 0)]; start > 0 && (q == '\'' || q == '"' || q == '`') {
		closing := strings.IndexByte(text[start:], q)
		if closing < 0 {
			return 0, 0, false
		}
		return start - 1, start + closing + 1, true
	}
	end = start
	for end < len(text) && (isWordByte(text[end]) || text[end] == '.') {
		end++
	}
	return start, end, true
}

// wordIndex is the first index at or after from where words starts and ends
// on whole words of the source (`A256GCM` is not found in `A256GCMKW`); -1
// when there is none.
func (p *textPos) wordIndex(from int, words string) int {
	for from <= len(p.words) {
		k := strings.Index(p.words[from:], words)
		if k < 0 {
			return -1
		}
		k += from
		first, last := p.raw[k], p.raw[k+len(words)-1]
		if (first == 0 || !isWordByte(p.lit.Text[first-1])) && (last+1 >= len(p.lit.Text) || !isWordByte(p.lit.Text[last+1])) {
			return k
		}
		from = k + 1
	}
	return -1
}

// stringAt is where the string literal text (jspat writes it in double
// quotes) is, written with any quote, from the object starting at word.
func (p *textPos) stringAt(word int, text string) (objectSpan, bool) {
	if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' || word < 0 || word >= len(p.raw) {
		return objectSpan{}, false
	}
	inner, from := text[1:len(text)-1], max(p.raw[word]-1, 0)
	best := -1
	for _, q := range []string{"'", "\"", "`"} {
		if k := strings.Index(p.lit.Text[from:], q+inner+q); k >= 0 && (best < 0 || from+k < best) {
			best = from + k
		}
	}
	if best < 0 {
		return objectSpan{}, false
	}
	line, col := p.lineCol(best)
	endLine, endCol := p.lineCol(best + len(inner) + 2)
	return objectSpan{line: line, col: col, endLine: endLine, endCol: endCol}, true
}

// enclosed: the site's expression stands in one of the places kinds names:
// a direct argument of another call of its function ("argument"), or a
// property value of an object literal of its file ("property"). It is read
// on the source; a site whose text is unknown stands nowhere.
func (fr *Frag) enclosed(s *Site, kinds []string, callers []*Site) bool {
	if len(kinds) == 0 {
		return false
	}
	text, ok := fr.siteText(s)
	if !ok {
		return false
	}
	for _, k := range kinds {
		if k == enclosedArgument && argumentOfAny(s, text, callers) || k == enclosedProperty && fr.propertyOfAny(s, text) {
			return true
		}
	}
	return false
}

// argumentOfAny: text, s's expression, is a direct argument of a call that
// encloses s.
func argumentOfAny(s *Site, text string, callers []*Site) bool {
	for _, t := range callers {
		if t != s && t.Kind != siteObjectLiteral && t.Kind != siteRead && spanContains(t, s) && isArgumentOf(t, text) {
			return true
		}
	}
	return false
}

// propertyOfAny: text, s's expression, is a property value of an object
// literal that encloses s.
func (fr *Frag) propertyOfAny(s *Site, text string) bool {
	for _, o := range fr.NodeData.objects {
		if o != s && o.File == s.File && spanContains(o, s) && isPropertyOf(o, text) {
			return true
		}
	}
	return false
}

// siteText is the site's expression as jspat writes it: an object literal's
// object, or a one-line call's source.
func (fr *Frag) siteText(s *Site) (string, bool) {
	if s.Kind == siteObjectLiteral {
		return s.node.args[0].Node.Text, true
	}
	line, ok := fr.Lines[s.File][s.Line]
	if !ok || !s.ColOK || s.EndCol <= s.Col || s.EndLine != 0 && s.EndLine != s.Line || s.EndCol-1 > len(line) {
		return "", false
	}
	nodes := jspat.ParseConcreteArgs(line[s.Col-1 : s.EndCol-1])
	if len(nodes) != 1 {
		return "", false
	}
	return nodes[0].Text, true
}

func isArgumentOf(t *Site, text string) bool {
	args, ok := t.nodeArgs()
	if !ok {
		return false
	}
	for _, a := range args {
		if a.Node != nil && a.Node.Text == text {
			return true
		}
	}
	return false
}

func isPropertyOf(o *Site, text string) bool {
	for _, p := range o.node.args[0].Node.Props {
		if p.Value != nil && !p.Spread && p.Value.Text == text {
			return true
		}
	}
	return false
}

// spanContains: s lies within t (t's end known).
func spanContains(t, s *Site) bool {
	if t.EndCol == 0 || !t.ColOK || !s.ColOK {
		return false
	}
	tEnd, sEnd := [2]int{max(t.EndLine, t.Line), t.EndCol}, [2]int{max(s.EndLine, s.Line), s.EndCol}
	if s.EndCol == 0 {
		sEnd = [2]int{s.Line, s.Col}
	}
	before := func(a, b [2]int) bool { return a[0] < b[0] || a[0] == b[0] && a[1] <= b[1] }
	return before([2]int{t.Line, t.Col}, [2]int{s.Line, s.Col}) && before(sEnd, tEnd)
}

// callSource is a locator over the call's source text, from its start column
// to its end, nil when the fragment's source lines do not cover it.
func (fr *Frag) callSource(s *Site) *textPos {
	if !s.ColOK || s.EndCol == 0 {
		return nil
	}
	end := max(s.EndLine, s.Line)
	var b strings.Builder
	for l := s.Line; l <= end; l++ {
		line, ok := fr.Lines[s.File][l]
		if !ok {
			return nil
		}
		from, to := 0, len(line)
		if l == s.Line {
			from = min(s.Col-1, len(line))
		}
		if l == end {
			to = min(max(s.EndCol-1, from), len(line))
		}
		if l > s.Line {
			b.WriteByte('\n')
		}
		b.WriteString(line[from:to])
	}
	return newTextPos(graphfrag.GraphFragmentObjectLiteral{Line: s.Line, StartCol: s.Col, Text: b.String()})
}

// bindsModule: name is one of the file's own import bindings of one of
// modules (`const name = require(m)`, `import name from m`, `import * as
// name`, `import { name } from m`).
func (fr *Frag) bindsModule(file, name string, modules []string) bool {
	for _, im := range fr.NodeData.imports[file] {
		local := im.Alias
		if local == "" {
			local = im.Name
		}
		if local == name && inList(im.Module, modules) {
			return true
		}
	}
	return false
}

// siteRead is the Kind of a property read site.
const siteRead = "property_read"

// nodeReadSites are the sites of a fragment's property reads, in file and
// source order: each a site with the key, receiver and assigned variable a
// call of the property would have, and no arguments.
func nodeReadSites(reads map[string][]graphfrag.GraphFragmentPropertyRead, fns map[string]*FunctionJSON) []*Site {
	files := make([]string, 0, len(reads))
	for f := range reads {
		files = append(files, f)
	}
	sort.Strings(files)
	var out []*Site
	for _, file := range files {
		for _, r := range reads[file] {
			line, col, end := r.Line, r.StartCol, r.EndCol
			s := nodeSiteOf(&ExternalJSON{
				CallerKey: r.CallerKey, TargetKey: r.TargetKey, MethodName: r.MethodName, Raw: r.Raw,
				Line: &line, StartCol: &col, EndCol: &end, EndLine: r.EndLine,
				ReceiverVar: r.ReceiverVar, AssignedVar: r.AssignedVar, CandidateModules: r.CandidateModules,
			}, fns[r.CallerKey])
			if s.File == "" {
				s.File = file
			}
			s.Kind = siteRead
			out = append(out, s)
		}
	}
	return out
}

// nodeIncoming files the fragment's calls between functions by callee, with
// the arguments written at each call: a taint rule follows a parameter of the
// sink's function into the calls of that function (paramValues). These sites
// are never matched against entries, so they stay out of fr.Sites.
func nodeIncoming(frag *FragmentJSON, fr *Frag) {
	strs := frag.InternalEdgeStrings
	str := func(i int) string {
		if i < 0 || i >= len(strs) {
			return ""
		}
		return strs[i]
	}
	for i := range frag.InternalEdges {
		c := &frag.InternalEdges[i]
		if c.N[0] < 0 || c.N[0] >= len(frag.Functions) || c.N[1] < 0 || c.N[1] >= len(frag.Functions) {
			continue
		}
		caller, callee := &frag.Functions[c.N[0]], &frag.Functions[c.N[1]]
		s := &Site{
			File: caller.FilePath, Line: c.N[2], LineOK: true, Caller: caller.Key, CallerPackage: caller.Package,
			Method: str(c.N[5]), Arity: c.N[6], Resolution: str(c.N[3]), Kind: "internal",
			Col: c.N[10], ColOK: true, EndCol: c.N[11], EndLine: c.EndLine,
		}
		s.Params, s.ParamIdx, s.ParamOrder = paramMap(c.Entry)
		fr.Incoming[callee.Key] = append(fr.Incoming[callee.Key], s)
	}
}
