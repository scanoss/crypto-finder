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

// The node (JavaScript/TypeScript) entries: what an entry's callee is, in the
// terms reach resolves a call site to, and the checks a loaded node entry must
// pass. The rule compiler writes them (compile_node.go); the matcher reads them.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/scanoss/crypto-finder/internal/cardmatch/internal/jspat"
)

// NodeBind says how a node entry's callee is identified.
type NodeBind string

// The callee binds of a node entry.
const (
	// BindImport: reach resolved the call through an import. The site's
	// callee key is <module>.<Path> for one of Modules.
	BindImport NodeBind = "import"
	// BindGlobal: a platform interface reach names itself: the key is Path,
	// `(SubtleCrypto).digest`, `(Crypto).getRandomValues`.
	BindGlobal NodeBind = "global"
	// BindWritten: a rule spelling of a name no guard binds: the site's
	// callee text is Path, however reach bound it (OpenGrep reads the text);
	// with Modules, the file imports one of them at or before the call (the
	// branch's import guard).
	BindWritten NodeBind = "written"
	// BindText: a callee the rule writes as a chain headed by an unbound
	// metavariable (`$GEN($TYPE)` with a metavariable-regex, `$R.sign`): the
	// site's callee text, however reach bound it, matches PathRegex, whose
	// named groups bind the metavariables; their regexes are constraints.
	// With Modules, the file imports one of them at or before the call (the
	// branch's import guard).
	BindText NodeBind = "text"
	// BindLiteral: an object literal the rule writes with no call around it
	// (`{..., algorithm: "HS256", ...}`): the site is an object literal of
	// the fragment (outermost or nested), ArgPattern its one argument; with
	// Modules, the file imports one of them at or before it (the rule's
	// import guard).
	BindLiteral NodeBind = "literal"
	// BindObject: a call on the value another call produced (`$R =
	// $NS.f(...)` then `$R.m(...)`, or `$NS.f(...).m(...)`). Path is the
	// method alone; From are the producers, Via how the value travels.
	BindObject NodeBind = "object"
)

// Ways a BindObject callee's receiver comes from its producer.
const (
	viaVar   = "var"   // assigned to a variable, the method called on it
	viaChain = "chain" // the method called on the call itself
	// viaDestructure: a destructuring binder takes the name from the call's
	// result (`const {..., $K, ...} = f()`); producers only.
	viaDestructure = "destructure"
)

// The places a not_enclosed entry rules out.
const (
	enclosedArgument = "argument"
	enclosedProperty = "property"
)

// NodeProducer requires that the value an argument metavariable (Use) binds
// reads a variable an earlier call of the site's own function produced: one
// of From, whose result is assigned to the variable (Via var) or
// destructured into it (Via destructure).
type NodeProducer struct {
	Use  string   `json:"use"`
	Via  string   `json:"via"`
	From []*Entry `json:"from"`
}

func (p *NodeProducer) validate() error {
	if !jspat.IsMetavar(p.Use) {
		return fmt.Errorf("producers: use %q is not a metavariable", p.Use)
	}
	if p.Via != viaVar && p.Via != viaDestructure {
		return fmt.Errorf("producers: via %q", p.Via)
	}
	if len(p.From) == 0 {
		return errors.New("producers: no from")
	}
	for _, f := range p.From {
		if f.Callee == nil {
			return errors.New("producers: a from entry has no callee")
		}
		if err := f.validateNodeCall(); err != nil {
			return fmt.Errorf("producers: %w", err)
		}
		if err := f.Callee.validate(); err != nil {
			return fmt.Errorf("producers: %w", err)
		}
	}
	return nil
}

// NodeCallee is the callee of a node entry.
//
// Path is the callee key exactly as reach writes it, minus the `<module>.`
// prefix for BindImport: `AES.encrypt`, `x.(Y).<init>` for `new x.Y()`,
// `x.(Y).meth` for a method on such an instance, `default` for a call of the
// module binding itself and `(default).<init>` for a `new` of it. PathRegex
// replaces Path when a segment is a metavariable that is not a finite list; it
// is matched against the same text, and its named groups bind metavariables.
type NodeCallee struct {
	Bind NodeBind `json:"bind"`
	// Modules are import specifiers, verbatim ("crypto" and "node:crypto"
	// are two).
	Modules   []string `json:"modules,omitempty"`
	Path      string   `json:"path,omitempty"`
	PathRegex string   `json:"path_regex,omitempty"`
	// New: the rule writes `new`.
	New bool `json:"new,omitempty"`
	// LocalRegex constrains the local name the call is written with (the
	// head identifier of the site's callee text): a namespace binder whose
	// metavariable has a metavariable-regex.
	LocalRegex string `json:"local_regex,omitempty"`
	// LocalFirst: the head identifier of the site's callee text is the
	// first segment of its path under the module: the call is written with
	// the local name a destructuring binder gave the export it names
	// (`const { $NS } = require(m); $NS.f()`), not through a namespace.
	LocalFirst bool `json:"local_first,omitempty"`
	// Member: the call is written as a member access (`ns.f()`, `(0,
	// ns.f)()`), as a namespace binding's member is; reach gives the bare
	// `f()` of a named import the same key.
	Member bool `json:"member,omitempty"`
	// Wrapped: the call goes through a variable an interop wrapper set
	// (`$R = $W($NS)` then `$R.f()`): the head of the callee text is not
	// one of the file's own bindings of the module.
	Wrapped bool `json:"wrapped,omitempty"`
	// Inline: the call is written on the require or import call itself
	// (`require("m").f()`); reach keys `ns.f()` the same.
	Inline bool `json:"inline,omitempty"`
	// Assigned: BindLiteral only, the rule writes `$O = {...}`: the object
	// is assigned to a variable, and the finding starts at the variable.
	Assigned bool `json:"assigned,omitempty"`
	// Written: BindGlobal only, the callee as the rule writes it with no
	// import (`crypto.randomUUID`, metavariables allowed). reach gives every
	// spelling of a global object the same key; OpenGrep matches the one
	// written, so the site's callee text must unify with it.
	Written string `json:"written,omitempty"`
	// Props: BindObject only, the property chain between the produced value
	// and the method (`utils` in `$I.utils.keccak256()` on `$I = new W()`):
	// the site's callee text is `<variable>.<Props>.<Path>`, the variable
	// holding the producer's result (Via var).
	Props string `json:"props,omitempty"`
	// From / Via: BindObject only.
	From []*Entry `json:"from,omitempty"`
	Via  []string `json:"via,omitempty"`

	keySet  map[string]bool // keys() as a set (prepareNode)
	written *jspat.Node     // Written parsed (prepareNode)
}

// keys are the callee keys a fixed-path import or global callee stands for,
// one per module; nil for the others.
func (c *NodeCallee) keys() []string {
	if c.Path == "" {
		return nil
	}
	switch c.Bind {
	case BindImport:
		out := make([]string, len(c.Modules))
		for i, m := range c.Modules {
			out[i] = m + "." + c.Path
		}
		return out
	case BindGlobal:
		return []string{c.Path}
	case BindWritten, BindObject, BindText, BindLiteral:
	}
	return nil
}

// NodeConsumer is a call that must take the site's call on, the shape of a
// rule whose context passes the matched call to another call
// (`$SINK(.., $DRAW, ..)`, `$MAT = $DRAW ... $S.encrypt({iv: $MAT})`,
// `$OBJ = <call> ... $OBJ.sign({padding: $P})`, with focus on the matched
// call). The consumer is a call of the site's own function whose callee text
// matches CalleeRegex and whose method matches MethodRegex (each when set),
// whose arguments unify with ArgPattern under Constraints, and that takes the
// site:
//
//	inline:   Use binds the site's call itself (a call it spans)
//	var:      Use binds the variable the site's result is assigned to (on the
//	          site's line or later)
//	receiver: its receiver is the site's result, through that variable or a
//	          chain (the object callee's producer rule)
type NodeConsumer struct {
	Via         string       `json:"via"`
	CalleeRegex string       `json:"callee_regex,omitempty"`
	MethodRegex string       `json:"method_regex,omitempty"`
	ArgPattern  *string      `json:"arg_pattern,omitempty"`
	Use         string       `json:"use,omitempty"`
	Constraints []Constraint `json:"constraints,omitempty"`
	// Producers: an argument metavariable of the consumer a context binds
	// to a call's result, as Entry.Producers.
	Producers []*NodeProducer `json:"producers,omitempty"`

	entry *Entry // ArgPattern and Constraints as an entry, for the argument matcher (prepareNode)
}

// The ways a consumer takes the site's call.
const (
	ConsumeInline   = "inline"
	ConsumeVar      = "var"
	ConsumeReceiver = "receiver"
)

func (c *NodeConsumer) validate() error {
	for _, p := range c.Producers {
		if err := p.validate(); err != nil {
			return fmt.Errorf("consumer: %w", err)
		}
	}
	switch c.Via {
	case ConsumeInline, ConsumeVar:
		if c.Use == "" || c.ArgPattern == nil {
			return fmt.Errorf("consumer %s: needs arg_pattern and use", c.Via)
		}
	case ConsumeReceiver:
		if c.Use != "" {
			return errors.New("consumer receiver: use belongs to inline and var")
		}
	default:
		return fmt.Errorf("consumer: via %q", c.Via)
	}
	if err := checkOptionalRegexes(c.CalleeRegex, c.MethodRegex); err != nil {
		return fmt.Errorf("consumer regex: %w", err)
	}
	e := c.asEntry()
	bound, err := e.validateArgPattern()
	if err != nil {
		return fmt.Errorf("consumer: %w", err)
	}
	if c.Use != "" && !bound[c.Use] {
		return fmt.Errorf("consumer: use %s is not bound in the argument pattern", c.Use)
	}
	return checkNodeConstraints(e.Constraints)
}

// checkOptionalRegexes checks each regex that is set.
func checkOptionalRegexes(rxs ...string) error {
	for _, rx := range rxs {
		if rx == "" {
			continue
		}
		if err := checkRegex(rx); err != nil {
			return err
		}
	}
	return nil
}

// checkNodeConstraints: each node constraint names a metavariable and a
// valid regex.
func checkNodeConstraints(cs []Constraint) error {
	for _, k := range cs {
		if k.Metavar == "" || k.ArgIndex != nil || k.Regex == nil {
			return errors.New("constraint: a node constraint names a metavariable and a regex")
		}
		if err := checkRegex(*k.Regex); err != nil {
			return fmt.Errorf("constraint %s: %w", k.Metavar, err)
		}
	}
	return nil
}

// asEntry is the consumer's argument pattern and constraints as an entry.
func (c *NodeConsumer) asEntry() *Entry {
	if c.entry != nil {
		return c.entry
	}
	c.entry = &Entry{ArgPattern: c.ArgPattern, Constraints: c.Constraints}
	if c.ArgPattern == nil {
		return c.entry
	}
	args, err := jspat.ParseArgs(*c.ArgPattern)
	if err != nil {
		return c.entry
	}
	minArgs, maxArgs := jspat.Arity(args)
	c.entry.MinArity, c.entry.jsArgs = minArgs, args
	if maxArgs >= 0 {
		c.entry.MaxArity = &maxArgs
	}
	return c.entry
}

var errNodeField = errors.New("node field on an entry without a callee")

// validateNode checks every node entry of the index: the callee's
// invariants per bind, the argument pattern, the constraints and the nested
// entries. A Java or Python entry must carry none of the node fields.
func (ix *Index) validateNode() error {
	for i, e := range ix.Entries {
		if err := e.validateNode(); err != nil {
			return fmt.Errorf("entry %d (%s): %w", i, e.RuleID, err)
		}
	}
	return nil
}

func (e *Entry) validateNode() error {
	if e.Callee == nil {
		// Constraint.Metavar is not checked: Python constraints name their
		// metavariable too.
		if e.ArgPattern != nil || e.FocusMetavar != "" || len(e.NotImports) > 0 || len(e.Consumers) > 0 || len(e.NotRegexes) > 0 || len(e.Producers) > 0 || len(e.NotEntries) > 0 {
			return errNodeField
		}
		return nil
	}
	if err := e.validateNodeCall(); err != nil {
		return err
	}
	if err := e.Callee.validate(); err != nil {
		return err
	}
	if err := validateNodeNots(e.NotCalls); err != nil {
		return err
	}
	if err := e.validateNodeExtras(); err != nil {
		return err
	}
	if err := e.validateNodeWithin(); err != nil {
		return err
	}
	return e.validateNodeLists()
}

// validateNodeWithin checks a node entry's within entries.
func (e *Entry) validateNodeWithin() error {
	for _, w := range e.Within {
		if w.Callee == nil {
			return errors.New("within: an entry has no callee")
		}
		if err := w.validateNodeCall(); err != nil {
			return fmt.Errorf("within: %w", err)
		}
		if err := w.Callee.validate(); err != nil {
			return fmt.Errorf("within: %w", err)
		}
	}
	return nil
}

// validateNodeLists checks a node entry's not_enclosed, not_entries and
// not_imports.
func (e *Entry) validateNodeLists() error {
	for _, k := range e.NotEnclosed {
		if k != enclosedArgument && k != enclosedProperty {
			return fmt.Errorf("not_enclosed: %q", k)
		}
	}
	for _, n := range e.NotEntries {
		if n.Callee == nil {
			return errors.New("not_entries: an entry has no callee")
		}
		if err := n.validateNode(); err != nil {
			return fmt.Errorf("not_entries: %w", err)
		}
	}
	for _, m := range e.NotImports {
		if m == "" {
			return errors.New("not_imports: empty module")
		}
	}
	return nil
}

// validateNodeCall checks what every node call pattern carries: no Java or
// Python argument fields, an argument pattern jspat reads with the arity it
// gives, a focus metavariable bound in it, and metavariable constraints.
func (e *Entry) validateNodeCall() error {
	if len(e.Args) > 0 || e.Type != nil || e.MethodRegex != nil || len(e.Insides) > 0 || len(e.NotInside) > 0 {
		return errors.New("a node entry has a Java or Python field")
	}
	bound, err := e.validateArgPattern()
	if err != nil {
		return err
	}
	if e.FocusMetavar != "" && !bound[e.FocusMetavar] {
		return fmt.Errorf("focus_metavar %s is not bound in the argument pattern", e.FocusMetavar)
	}
	for _, c := range e.Constraints {
		if c.Metavar == "" || c.ArgIndex != nil || c.Regex == nil {
			return errors.New("constraint: a node constraint names a metavariable and a regex")
		}
		if err := checkRegex(*c.Regex); err != nil {
			return fmt.Errorf("constraint %s: %w", c.Metavar, err)
		}
	}
	return nil
}

// validateArgPattern parses the argument pattern, checks the arity against
// it and returns the metavariables it binds.
func (e *Entry) validateArgPattern() (map[string]bool, error) {
	bound := map[string]bool{}
	minArgs, maxArgs := 0, -1
	if e.ArgPattern != nil {
		args, err := jspat.ParseArgs(*e.ArgPattern)
		if err != nil {
			return nil, fmt.Errorf("arg_pattern %q: %w", *e.ArgPattern, err)
		}
		minArgs, maxArgs = jspat.Arity(args)
		bound = jsMetavars(args)
	}
	gotMax := -1
	if e.MaxArity != nil {
		gotMax = *e.MaxArity
	}
	if e.MinArity != minArgs || gotMax != maxArgs {
		return nil, fmt.Errorf("arity %d..%d does not match the argument pattern", e.MinArity, gotMax)
	}
	return bound, nil
}

func checkRegex(rx string) error {
	_, err := regexp2.Compile(pyToNet(rx), regexp2.None)
	return err
}

func (c *NodeCallee) validate() error { //nolint:gocognit,gocyclo // one case per bind, each a short list of invariants
	if c.Bind != BindLiteral && (c.Path == "") == (c.PathRegex == "") {
		return fmt.Errorf("callee %s: exactly one of path and path_regex", c.Bind)
	}
	if c.PathRegex != "" {
		if err := checkRegex(c.PathRegex); err != nil {
			return fmt.Errorf("callee path_regex: %w", err)
		}
	}
	if c.LocalRegex != "" {
		if err := checkRegex(c.LocalRegex); err != nil {
			return fmt.Errorf("callee local_regex: %w", err)
		}
	}
	if c.Bind != BindObject && (len(c.From) > 0 || len(c.Via) > 0 || c.Props != "") {
		return fmt.Errorf("callee %s: from and via belong to object callees", c.Bind)
	}
	if c.Bind != BindImport && (c.Bind != BindLiteral && c.Bind != BindText && c.Bind != BindWritten && len(c.Modules) > 0 || c.LocalRegex != "" || c.LocalFirst || c.Member || c.Wrapped || c.Inline) {
		return fmt.Errorf("callee %s: modules, local_regex and local_first belong to import callees", c.Bind)
	}
	if c.Written != "" {
		if c.Bind != BindGlobal {
			return fmt.Errorf("callee %s: written belongs to global callees", c.Bind)
		}
		if _, err := jspat.ParseExpr(c.Written, true); err != nil {
			return fmt.Errorf("callee written: %w", err)
		}
	}
	switch c.Bind {
	case BindImport:
		if len(c.Modules) == 0 {
			return errors.New("callee import: no modules")
		}
		for _, m := range c.Modules {
			if m == "" {
				return errors.New("callee import: empty module")
			}
		}
		if c.New && c.Path != "" && !strings.HasSuffix(c.Path, ").<init>") {
			return fmt.Errorf("callee import: new with path %q", c.Path)
		}
	case BindGlobal:
		if c.New || c.Path != "" && !strings.HasPrefix(c.Path, "(") {
			return fmt.Errorf("callee global: path %q is not an interface member", c.Path)
		}
	case BindWritten:
		if c.PathRegex != "" {
			return errors.New("callee written: a written callee has a fixed path")
		}
	case BindLiteral:
		if c.Path != "" || c.PathRegex != "" || c.New {
			return errors.New("callee literal: a literal callee has no path and no new")
		}
	case BindText:
		if c.PathRegex == "" || c.Path != "" {
			return errors.New("callee text: a text callee has a path regex and no path")
		}
	case BindObject:
		if c.PathRegex != "" || strings.Contains(c.Path, ".") || c.New {
			return fmt.Errorf("callee object: path %q is not one method name", c.Path)
		}
		if len(c.From) == 0 || len(c.Via) == 0 {
			return errors.New("callee object: no from or via")
		}
		if c.Props != "" && (len(c.Via) != 1 || c.Via[0] != viaVar || !jsPropChain.MatchString(c.Props)) {
			return fmt.Errorf("callee object: props %q needs via var and a dotted name chain", c.Props)
		}
		for _, v := range c.Via {
			if v != viaVar && v != viaChain {
				return fmt.Errorf("callee object: via %q", v)
			}
		}
		for _, f := range c.From {
			if f.Callee == nil {
				return errors.New("callee object: a from entry has no callee")
			}
			if err := f.validateNodeCall(); err != nil {
				return fmt.Errorf("from: %w", err)
			}
			if err := f.Callee.validate(); err != nil {
				return fmt.Errorf("from: %w", err)
			}
		}
	default:
		return fmt.Errorf("callee: unknown bind %q", c.Bind)
	}
	return nil
}

// jsMetavars are the metavariables a pattern binds, at any depth.
func jsMetavars(nodes []*jspat.Node) map[string]bool {
	out := map[string]bool{}
	var walk func(n *jspat.Node)
	walk = func(n *jspat.Node) {
		if n == nil {
			return
		}
		if n.Kind == jspat.Metavar {
			out[n.Name] = true
		}
		if n.Kind == jspat.Member && n.Meta {
			out[n.Name] = true
		}
		for _, k := range n.Kids {
			walk(k)
		}
		for _, p := range n.Props {
			if p.KeyVar != "" {
				out[p.KeyVar] = true
			}
			walk(p.Value)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	return out
}

// validateNodeNots checks a node entry's not_calls. A not_calls entry tests
// the same callee as its entry: it carries its own argument pattern, and the
// not_calls it makes an exception for (a nested pattern-not's pattern-nots).
func validateNodeNots(nots []*Entry) error {
	for _, n := range nots {
		if n.Callee != nil || len(n.NotImports) > 0 || len(n.Consumers) > 0 || len(n.NotRegexes) > 0 || len(n.Producers) > 0 || len(n.NotEntries) > 0 {
			return errors.New("not_calls: a node not_calls entry has only an argument pattern and exceptions")
		}
		if err := n.validateNodeCall(); err != nil {
			return fmt.Errorf("not_calls: %w", err)
		}
		if err := validateNodeNots(n.NotCalls); err != nil {
			return err
		}
	}
	return nil
}

// validateNodeExtras checks a node entry's consumers and not_regexes.
func (e *Entry) validateNodeExtras() error {
	for _, c := range e.Consumers {
		if err := c.validate(); err != nil {
			return err
		}
	}
	for _, pr := range append(append([]*NodeProducer{}, e.Producers...), e.NotProducers...) {
		if err := pr.validate(); err != nil {
			return err
		}
	}
	for _, rx := range e.NotRegexes {
		if err := checkRegex(rx); err != nil {
			return fmt.Errorf("not_regexes: %w", err)
		}
	}
	return nil
}

// jsPropChain is a property chain: names joined by dots.
var jsPropChain = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$`)
