// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// PythonContractTypeResolver is a thin, contract-only type resolver for the
// Python ecosystem. It annotates FunctionDecl.ReturnType with the return type
// declared in the Python contracts KB when:
//   - The function's fully-qualified name and arity match an unconditional
//     contract in the KB, AND
//   - The function's ReturnType is currently empty (parser did not set it).
//
// This resolver is NOT a general Python type inference engine. It does not
// infer types for arbitrary Python code and does not traverse import or
// assignment chains on its own. Chains through untyped intermediates are an
// accepted, documented limitation (see REQ-4.2, CC-4 in the spec).
//
// The resolver always returns nil error — contract gaps are never fatal.
type PythonContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewPythonContractTypeResolver creates a resolver backed by the supplied KB.
// If kb is nil, the resolver is a safe no-op (produces no type resolutions).
func NewPythonContractTypeResolver(kb *contracts.KnowledgeBase) *PythonContractTypeResolver {
	return &PythonContractTypeResolver{kb: kb}
}

// NewPythonContractTypeResolverFromEmbedded creates a resolver by loading the
// embedded Python KB lazily. If the KB cannot be loaded, the resolver is a
// safe no-op. This is the constructor wired into NewTypeResolverForEcosystem.
func NewPythonContractTypeResolverFromEmbedded() *PythonContractTypeResolver {
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		// Graceful degradation: no KB → resolver is a no-op.
		return &PythonContractTypeResolver{kb: nil}
	}
	return &PythonContractTypeResolver{kb: kb}
}

// ResolveTypes iterates over each FunctionDecl in the graph and, for any
// function with an empty ReturnType whose FQN + arity match an unconditional
// contract in the KB, sets ReturnType to the contract's declared return type.
//
// sourceRoots is unused by this resolver (contract-only, no filesystem access).
func (r *PythonContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}

	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			// Parser already set a return type — do not overwrite.
			continue
		}

		fqn := pythonFunctionFQN(fn)
		arity := len(fn.Parameters)
		contractList := r.kb.ContractsForTolerant(fqn, arity)

		// Find the first unconditional contract (When == nil) and apply it.
		for i := range contractList {
			c := &contractList[i]
			if c.When == nil && c.Return.Type != "" {
				fn.ReturnType = c.Return.Type
				break
			}
		}
	}

	return nil
}

// PythonTypeResolverChain composes the Python ecosystem's type resolvers in
// order (row 13, python-parser-parity-2, design.md D7): contract-KB
// resolution first (unconditional signature matches against the embedded
// KB), an optional dependency resolver second (row 14's
// PythonDependencyTypeResolver — nil until that row wires it in, a safe
// no-op), then propagatePythonAssignedVarTypes LAST — so the resolver-half
// receiver-type propagation can see any ReturnType either earlier step
// itself just filled in. Reverting row 14 (dependency nil) leaves rows A-C
// (including this chain's own propagation step) green; reverting this
// row's propagation step is a config change, not implemented here.
type PythonTypeResolverChain struct {
	contract   *PythonContractTypeResolver
	dependency TypeResolver
}

// NewPythonTypeResolverChain creates a chain backed by the embedded
// contract KB, plus a dependency resolver with an uncached (nil-cache,
// always-re-index) signature cache — safe on its own, but every caller
// that cares about repeated-scan performance should call
// SetSignatureIndexCache with a real cache (e.g. NewDiskPythonSignatureIndexCache,
// mirroring JavaBytecodeTypeResolver.SetBytecodeIndexCache — 12.5,
// row 14, python-parser-parity-2).
func NewPythonTypeResolverChain() *PythonTypeResolverChain {
	return &PythonTypeResolverChain{
		contract:   NewPythonContractTypeResolverFromEmbedded(),
		dependency: NewPythonDependencyTypeResolver(nil),
	}
}

// SetSignatureIndexCache reconfigures the chain's dependency resolver to
// use the given cache (12.5, row 14, python-parser-parity-2) — mirrors
// JavaBytecodeTypeResolver.SetBytecodeIndexCache's post-construction
// injection pattern, wired from internal/cli/scan.go.
func (c *PythonTypeResolverChain) SetSignatureIndexCache(cache PythonSignatureIndexCache) {
	c.dependency = NewPythonDependencyTypeResolver(cache)
}

// ResolveTypes runs the contract resolver, the optional dependency
// resolver, then propagatePythonAssignedVarTypes, in that fixed order.
// Always returns nil — an inner resolver's own error is already absorbed
// by design (contract/dependency resolvers document a nil-error,
// graceful-degradation contract); propagation itself performs no I/O and
// cannot fail.
func (c *PythonTypeResolverChain) ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error {
	if c.contract != nil {
		if err := c.contract.ResolveTypes(graph, sourceRoots); err != nil {
			return err
		}
	}
	if c.dependency != nil {
		if err := c.dependency.ResolveTypes(graph, sourceRoots); err != nil {
			return err
		}
	}
	var kb *contracts.KnowledgeBase
	if c.contract != nil {
		kb = c.contract.kb
	}
	propagatePythonAssignedVarTypes(graph, kb)
	return nil
}

// propagatePythonAssignedVarTypes performs one ordered pass over each
// Python-origin FunctionDecl's own Calls (row 13's resolver half): for a
// call with a non-empty AssignedVar whose Callee has a knowable return
// type, that var->type binding is recorded; a LATER call in the SAME decl
// whose ReceiverVar matches a tracked var has its Callee Package/Type
// rewritten to the tracked type and ResolvedReceiverType set. A rebind whose
// callee has no knowable return type INVALIDATES the tracked entry, so a
// stale type cannot reach a later call on the same name.
//
// Never crosses FunctionDecl boundaries, matching the parser's own scope-local
// bounding for partials/callables (row 11) and the parser-half varTypes
// (row 13 §10.2).
//
// THAT BOUND IS NOT LEXICAL-SCOPE CORRECTNESS, and the difference is
// load-bearing. This pass sees only `fn.Calls`, so a rebind that is not a CALL
// leaves no trace it can act on: a `for` target, a `with ... as`, a tuple
// unpack, a comprehension target, or a literal assignment. A nested `def` is
// also not a separate FunctionDecl — its calls are attributed to the enclosing
// decl and its parameter list is invisible here — so a nested parameter
// shadowing an outer name inherits the outer binding. Both shapes are pinned
// as known limitations by
// TestPythonAssignedVarTypes_KnownLimitation_RebindWithoutACallIsInvisible.
// Closing either needs statement-level binding events, or nested defs as their
// own decls, from the parser.
//
// THE RETURN TYPE IS TAKEN FROM THE IN-GRAPH DECL FIRST AND FROM THE
// CONTRACT KB SECOND. Only the first of those existed originally, and it
// cannot reach a DEPENDENCY's factory: when a consumer's own code is the
// scanned tree, the library's `FunctionDecl` is not in `graph.Functions`
// at all, so `callee == nil` and no binding was ever recorded. The effect
// was that a contract's `return.type` resolved a receiver only inside a
// single chained expression — `PrivateKey(secret).sign(msg)` — and never
// across the assignment real code writes:
//
//	key = PrivateKey(secret)   # coincurve.PrivateKey.<init>, contracted
//	sig = key.sign(message)    # keyed <module>.key.sign — joined nothing
//
// Measured on a probe consumer before this fallback existed: the chained
// form emitted `coincurve.PrivateKey.sign(builtins.bytes)` while the
// two-line form emitted `consumer2.key.sign(?)`, and the same split shows
// on the already-merged `ecdsa` contract (`sk = SigningKey.generate()`
// then `sk.sign(..)` emitted `<module>.sk.sign`). Since the operation
// entries of every Python contract in the KB hang off a factory's return
// type, that made most of them unreachable for the dominant call shape.
//
// The KB lookup uses ContractsForTolerant, the same entry point the
// contract resolver above uses, so the arity tolerance Python needs for
// default arguments and kwargs applies identically. Only an unconditional
// contract (`When == nil`) with a non-empty return type is used: a
// conditional return depends on argument VALUES, which this pass does not
// evaluate.
//
// Gated to `.py`/`.pyi`-sourced declarations ONLY (FunctionDecl.FilePath):
// AssignedVar/ReceiverVar are language-agnostic FunctionCall fields shared
// by every parser, so an ungated pass would risk mutating an unrelated
// ecosystem's calls on a coincidental variable-name match — unlike the
// contract resolver above, whose FQN+arity KB lookup is inherently
// self-limiting to the Python KB's own method names.
func propagatePythonAssignedVarTypes(graph *CallGraph, kb *contracts.KnowledgeBase) {
	for _, fn := range graph.Functions {
		if fn == nil || len(fn.Calls) == 0 || !isPythonSourceFile(fn.FilePath) {
			continue
		}
		propagatePythonAssignedVarTypesForDecl(fn, graph, kb)
	}
}

// pythonCalleeReturnType reports the return type of a call's callee and the
// package that declared it, preferring an in-graph FunctionDecl and falling
// back to the contract KB for a callee the scanned tree does not declare.
//
// The two sources are deliberately ordered this way: an in-graph decl is the
// scanned source's own truth and must win, so wiring the KB in cannot change
// any result that already resolved. The KB is consulted only where the old
// code returned nothing at all.
func pythonCalleeReturnType(
	call *FunctionCall,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
) (returnType, declPackage string) {
	if callee := graph.Functions[call.Callee.String()]; callee != nil && callee.ReturnType != "" {
		return callee.ReturnType, callee.ID.Package
	}
	if kb == nil || len(kb.Contracts) == 0 {
		return "", ""
	}
	// NOT call.Callee.String(): FunctionID.String() renders a method as
	// "pkg.(Type).Name" — parenthesised — while the KB is keyed
	// "pkg.Type.Name". Looking the KB up with the String() form silently
	// resolves nothing for every METHOD or constructor, while still working
	// for a module-level function (empty Type, so no parentheses appear).
	// That asymmetry is exactly what a "a call was produced" assertion would
	// have missed, so pythonCallFQN mirrors pythonFunctionFQN instead.
	contractList := kb.ContractsForTolerant(pythonCallFQN(call), len(call.Arguments))
	for i := range contractList {
		c := &contractList[i]
		if c.When == nil && c.Return.Type != "" {
			// A contract return type is written fully qualified, so
			// pythonSplitAssignedType splits it at its last separator and
			// never consults declPackage. The callee's own package is the
			// correct fallback for the bare-name case regardless: the type
			// belongs to the factory's package, not to the caller's.
			return c.Return.Type, call.Callee.Package
		}
	}
	return "", ""
}

// pythonTrackedAssignedType records what propagatePythonAssignedVarTypesForDecl
// learned about a local variable from an earlier call's AssignedVar plus
// its callee's ReturnType: the raw (possibly dotted) type name, plus the
// DECLARING decl's own package (the function that carried the return-type
// annotation) — consulted only when the type name itself carries no
// package prefix (G1, PR #310 phase-2 review).
type pythonTrackedAssignedType struct {
	name        string
	declPackage string
}

// pythonSplitAssignedType resolves tracked's raw type name into its
// Package/Type components (G1, PR #310 phase-2 review). A Python return
// annotation is occasionally already fully qualified (a contract-KB return
// type such as "cryptography.hazmat.primitives.ciphers.Cipher" split at
// its LAST separator: Package is everything before it, Type is the final
// segment. A bare name ("Cipher") carries no package of its own — it must
// be resolved against the package that DECLARED it (the function whose
// ReturnType produced this binding), never the CALLING decl's own package:
// a factory living in a different package/dependency than its caller must
// not have its return type silently reassigned to the caller's package.
func pythonSplitAssignedType(tracked pythonTrackedAssignedType) (pkg, typ string) {
	if idx := strings.LastIndex(tracked.name, "."); idx > 0 && idx < len(tracked.name)-1 {
		return tracked.name[:idx], tracked.name[idx+1:]
	}
	return tracked.declPackage, tracked.name
}

// propagatePythonAssignedVarTypesForDecl runs propagatePythonAssignedVarTypes's
// document-order pass for exactly one FunctionDecl, extracted purely to
// keep the outer function's cyclomatic/cognitive complexity low.
func propagatePythonAssignedVarTypesForDecl(
	fn *FunctionDecl,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
) {
	var varTypes map[string]pythonTrackedAssignedType
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.ReceiverVar != "" && varTypes != nil {
			if tracked, ok := varTypes[call.ReceiverVar]; ok {
				pkg, typ := pythonSplitAssignedType(tracked)
				call.Callee.Package = pkg
				call.Callee.Type = typ
				call.ResolvedReceiverType = typ
			}
		}
		if call.AssignedVar == "" {
			continue
		}
		returnType, declPackage := pythonCalleeReturnType(call, graph, kb)
		if returnType == "" {
			// INVALIDATE ON RE-BIND. This assignment rebinds the variable to
			// something whose type is not knowable, so any type learned from an
			// EARLIER assignment to the same name is now stale and must not
			// reach a later receiver call. Without this delete the previous
			// binding stayed live and over-propagated:
			//
			//	key = PrivateKey(s)   # contracted, binds key -> PrivateKey
			//	key = helper()        # unknowable; the binding must be dropped
			//	key.sign(m)           # was keyed coincurve.PrivateKey.sign
			//
			// Re-binding to another CONTRACTED factory was always correct,
			// because the assignment below overwrites the entry — which is what
			// localizes this to the unknowable-return path alone.
			delete(varTypes, call.AssignedVar)
			continue
		}
		if varTypes == nil {
			varTypes = make(map[string]pythonTrackedAssignedType)
		}
		varTypes[call.AssignedVar] = pythonTrackedAssignedType{name: returnType, declPackage: declPackage}
	}
}

// isPythonSourceFile reports whether filePath is a Python source/stub file
// — the same suffix test PythonParser.ParseDirectory itself uses to select
// files to parse.
func isPythonSourceFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".py") || strings.HasSuffix(filePath, ".pyi")
}

// pythonCallFQN derives the fully-qualified callee name for a FunctionCall in
// the spelling the Python contracts KB uses: "Package.Type.Name" for a method
// or constructor, "Package.Name" for a module-level function. It is the
// call-site mirror of pythonFunctionFQN, and it exists because
// FunctionID.String() renders a type-qualified id as "Package.(Type).Name",
// which no KB key matches.
func pythonCallFQN(call *FunctionCall) string {
	if call.Callee.Type != "" {
		return call.Callee.Package + "." + call.Callee.Type + "." + call.Callee.Name
	}
	return call.Callee.Package + "." + call.Callee.Name
}

// pythonFunctionFQN derives the fully-qualified method name for a FunctionDecl
// as it appears in the Python contracts KB: "Package.Type.Name" for methods,
// "Package.Name" for module-level functions.
//
// This must match the KB's `method:` field exactly.
func pythonFunctionFQN(fn *FunctionDecl) string {
	if fn.ID.Type != "" {
		return fn.ID.Package + "." + fn.ID.Type + "." + fn.ID.Name
	}
	return fn.ID.Package + "." + fn.ID.Name
}
