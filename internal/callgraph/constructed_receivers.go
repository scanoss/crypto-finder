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

package callgraph

import (
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
)

// returnedObjects is what a function's own return statements yield as
// objects. A parser fills it from the function's body, never from a nested
// function, closure or class body:
//
//   - classes holds one entry per return that builds a new instance, as the
//     class identity (Package and Type, no Name). A parser that cannot tell a
//     class instantiation from a plain call (Python's `return Name(...)`)
//     records the callee with its name as the Type; the builder keeps it only
//     when the graph declares methods on that class.
//   - sites holds the position of each returned call a parser cannot tell
//     from a class instantiation (Python's `return Name(...)`). The builder
//     reads the call's resolved callee there and keeps it only as a class the
//     graph declares methods on.
//   - other is set when some return yields anything else: a variable, a
//     field, a call result, a conditional.
//
// A return of nil, None, null or undefined yields no object and is not
// recorded: no method can be called on it.
type returnedObjects struct {
	classes []FunctionID
	sites   []returnedCallSite
	other   bool
}

// returnedCallSite is the position of a returned call, as FunctionCall
// records it.
type returnedCallSite struct {
	line, startCol, endCol int
}

func (r *returnedObjects) addClass(pkg, typ string) {
	if typ == "" {
		r.other = true
		return
	}
	r.classes = append(r.classes, FunctionID{Package: pkg, Type: typ})
}

func (r *returnedObjects) markOther() {
	r.other = true
}

// localBinders names, per language, the syntax nodes that bind a local name,
// and the field that holds what they bind. Every name such a node binds is
// counted, whatever the bound value is, so a local assigned once from a
// factory and again from a field reads as bound twice.
var (
	goLocalBinders = map[string][]string{
		"short_var_declaration": {"left"}, "assignment_statement": {"left"},
		"var_spec": {"name"}, "range_clause": {"left"},
	}
	javaLocalBinders = map[string][]string{
		"variable_declarator": {"name"}, "assignment_expression": {"left"},
		"enhanced_for_statement": {"name"}, "catch_formal_parameter": {"name"},
	}
	nodeLocalBinders = map[string][]string{
		"variable_declarator": {"name"}, "assignment_expression": {"left"},
		"augmented_assignment_expression": {"left"}, "for_in_statement": {"left"},
	}
	pythonLocalBinders = map[string][]string{
		"assignment": {"left"}, "augmented_assignment": {"left"},
		"for_statement": {"left"}, "for_in_clause": {"left"},
		"named_expression": {"name"}, "as_pattern": {"alias"},
	}
	rustLocalBinders = map[string][]string{
		"let_declaration": {"pattern"}, "assignment_expression": {"left"},
		"compound_assignment_expr": {"left"}, "for_expression": {"pattern"},
	}
)

// countLocalBindings counts, over a whole function body, nested functions
// included, how many times each plain name is bound by a node binders lists.
// A name reached only through a field, member, attribute or index target
// (`this.h = x`, `self.h = x`, `h[0] = x`) is not a local binding.
func countLocalBindings(body *sitter.Node, src []byte, binders map[string][]string) map[string]int {
	counts := make(map[string]int)
	var names func(n *sitter.Node)
	names = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case goNodeIdentifier:
			counts[n.Content(src)]++
			return
		case "field_expression", javaNodeFieldAccess, "member_expression", "attribute",
			"subscript", "subscript_expression", "index_expression", "selector_expression",
			"array_access", goNodeTypeIdentifier, goNodeGenericType, "type_annotation":
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			names(n.NamedChild(i))
		}
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		for _, field := range binders[n.Type()] {
			for i := 0; i < int(n.ChildCount()); i++ {
				if n.FieldNameForChild(i) == field {
					names(n.Child(i))
				}
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(body)
	return counts
}

// typeMethods indexes every method the graph declares by its owning type,
// "package|Type" with a Go pointer marker dropped, then by method name.
type typeMethods map[string]map[string]FunctionID

func indexTypeMethods(graph *CallGraph) typeMethods {
	index := make(typeMethods)
	for _, fn := range graph.Functions {
		if fn == nil || fn.ID.Type == "" || fn.OwnerType == ownerTypeInterface {
			continue
		}
		key := typeMethodsKey(fn.ID.Package, fn.ID.Type)
		if index[key] == nil {
			index[key] = make(map[string]FunctionID)
		}
		index[key][fn.ID.Name] = fn.ID
	}
	return index
}

func typeMethodsKey(pkg, typ string) string {
	return pkg + "|" + strings.TrimLeft(typ, "*")
}

// declaredClass resolves a class a return constructs to a type the graph
// declares methods on. A Java nested class is declared under its outer
// class (`Hashers.Standard`) while `new Standard()` inside the outer class
// names it simply; the one declared type of the package ending in that
// simple name is taken, and none when two share it.
func (m typeMethods) declaredClass(class FunctionID) (string, bool) {
	key := typeMethodsKey(class.Package, class.Type)
	if _, ok := m[key]; ok {
		return key, true
	}
	prefix := class.Package + "|"
	suffix := "." + strings.TrimLeft(class.Type, "*")
	found := ""
	for candidate := range m {
		if !strings.HasPrefix(candidate, prefix) || !strings.HasSuffix(candidate, suffix) {
			continue
		}
		if found != "" {
			return "", false
		}
		found = candidate
	}
	return found, found != ""
}

// constructedClass is the one class every object-yielding return of the
// function declared under key constructs, as a typeMethods key.
func (m typeMethods) constructedClass(graph *CallGraph, key string) (string, bool) {
	decl := graph.Functions[key]
	if decl == nil || decl.constructed.other {
		return "", false
	}
	classes := decl.constructed.classes
	for _, site := range decl.constructed.sites {
		instantiated, ok := instantiatedClass(decl, site)
		if !ok {
			return "", false
		}
		classes = append(classes[:len(classes):len(classes)], instantiated)
	}
	if len(classes) == 0 {
		return "", false
	}
	class := ""
	for _, c := range classes {
		resolved, ok := m.declaredClass(c)
		if !ok || (class != "" && resolved != class) {
			return "", false
		}
		class = resolved
	}
	return class, true
}

// instantiatedClass reads the class a returned call at site instantiates off
// its resolved callee: `Name(...)` resolved as package.Name names the class
// package.Name; a constructor callee names its own type. Whether that class
// exists is declaredClass's question.
func instantiatedClass(decl *FunctionDecl, site returnedCallSite) (FunctionID, bool) {
	for i := range decl.Calls {
		call := &decl.Calls[i]
		if call.Line != site.line || call.StartCol != site.startCol || call.EndCol != site.endCol {
			continue
		}
		switch {
		case BaseFunctionName(call.Callee.Name) == constructorMethodName:
			return FunctionID{Package: call.Callee.Package, Type: call.Callee.Type}, call.Callee.Type != ""
		case call.Callee.Type == "" && call.Callee.Name != "":
			return FunctionID{Package: call.Callee.Package, Type: call.Callee.Name}, true
		}
		return FunctionID{}, false
	}
	return FunctionID{}, false
}

// receiverProducers maps each local variable of fn that is bound exactly
// once in its body, by a call's result, onto that call's callee key. A name
// bound anywhere else too, by any value, in a nested block or a closure (the
// parser's localBindings), and a parameter, whose value may come from the
// caller, map to nothing: the object the call is made on may then be another.
func receiverProducers(fn *FunctionDecl) map[string]string {
	producers := make(map[string]string)
	params := make(map[string]bool, len(fn.Parameters))
	for _, param := range fn.Parameters {
		params[param.Name] = true
	}
	seen := make(map[string]bool)
	for i := range fn.Calls {
		call := &fn.Calls[i]
		v := call.AssignedVar
		if v == "" || params[v] || fn.localBindings[v] != 1 {
			continue
		}
		if seen[v] {
			// Two calls claim the one binding (a chain records its root's
			// variable on more than one link): which one binds it is unclear.
			delete(producers, v)
			continue
		}
		seen[v] = true
		producers[v] = call.Callee.String()
	}
	return producers
}

// resolveConstructedReceivers points a method call on a local variable at the
// method of the class the variable's object was built from, when the
// function that produced it constructs that one class on every return:
//
//	h := liba.Standard()     // func Standard() Hasher { return standard{} }
//	h.Sum(data)              // standard.Sum, not every Hasher implementation
//
// Without it the call is typed by the producer's declared return, an
// interface, trait or base class, and dispatch either fans out to every
// implementation the graph knows (so a factory that builds a harmless one
// still reaches the crypto one) or, when the receiver is not typed at all,
// links nothing. The object's own class is exact: an instance built as
// `standard{}` or `new Standard()` is no subclass, so no other override can
// run.
//
// The call keeps its callee unless that class itself declares a method of the
// same name (and arity, where the name carries it). It runs before the caller
// index is built, so the index links the class's method directly.
func resolveConstructedReceivers(graph *CallGraph) int {
	r := constructedReceiverResolver{graph: graph, methods: indexTypeMethods(graph), classes: make(map[string]constructedClassAnswer)}
	resolved := 0
	for _, fn := range graph.Functions {
		resolved += r.resolveFunction(fn)
	}
	if resolved > 0 {
		log.Debug().Int("resolved", resolved).Msg("Resolved method calls on constructed receivers")
	}
	return resolved
}

type constructedClassAnswer struct {
	class string
	ok    bool
}

// constructedReceiverResolver memoizes, per producer, the class it constructs.
type constructedReceiverResolver struct {
	graph   *CallGraph
	methods typeMethods
	classes map[string]constructedClassAnswer
}

func (r *constructedReceiverResolver) classOf(producer string) (string, bool) {
	answer, known := r.classes[producer]
	if !known {
		answer.class, answer.ok = r.methods.constructedClass(r.graph, producer)
		r.classes[producer] = answer
	}
	return answer.class, answer.ok
}

func (r *constructedReceiverResolver) resolveFunction(fn *FunctionDecl) int {
	var producers map[string]string
	resolved := 0
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.ReceiverVar == "" || call.StaticReceiver {
			continue
		}
		if producers == nil {
			producers = receiverProducers(fn)
		}
		producer, ok := producers[call.ReceiverVar]
		if !ok {
			continue
		}
		class, ok := r.classOf(producer)
		if !ok {
			continue
		}
		target, ok := r.methods[class][call.Callee.Name]
		if !ok || target == call.Callee {
			continue
		}
		call.Callee = target
		resolved++
	}
	return resolved
}
