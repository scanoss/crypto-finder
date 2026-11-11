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

// receiverProducers maps each local variable of fn that a call's result is
// bound to, onto that call's callee key. A variable bound by two different
// callees, and a parameter (whose value may come from the caller instead),
// map to nothing.
func receiverProducers(fn *FunctionDecl) map[string]string {
	producers := make(map[string]string)
	conflicted := make(map[string]bool)
	for _, param := range fn.Parameters {
		conflicted[param.Name] = true
	}
	for i := range fn.Calls {
		call := &fn.Calls[i]
		v := call.AssignedVar
		if v == "" || conflicted[v] {
			continue
		}
		key := call.Callee.String()
		if prev, seen := producers[v]; seen && prev != key {
			delete(producers, v)
			conflicted[v] = true
			continue
		}
		producers[v] = key
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
