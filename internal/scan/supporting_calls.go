package scan

import "github.com/scanoss/crypto-finder/internal/callgraph"

// objectIdentity is the minimal per-call identity the object-lifecycle grouping
// policy needs: the variable a call is invoked on, the variable its result is
// bound to, and the fluent-chain group it belongs to. It is the shared currency
// between the live-scan export (which projects it from callgraph.FunctionCall)
// and the annotate-from-cache path (which projects it from a graph-fragment-1.4
// edge's receiver_var/assigned_var/chain_id). Both paths run the SAME selection
// policy (isLifecycleSibling) so they pick the identical set of supporting calls.
type objectIdentity struct {
	ReceiverVar string
	AssignedVar string
	ChainID     string
}

// isLifecycleSibling reports whether call belongs to the lifecycle of the crypto
// object identified by terminal. It is the single source of truth for the
// object-lifecycle selection policy; callers must exclude the terminal call
// itself. A call is a lifecycle sibling when:
//
//   - it is invoked on one of the terminal's object variables (ReceiverVar match);
//   - it is a sibling link of the same fluent chain (ChainID match);
//   - it produced one of the terminal's object variables (AssignedVar match).
func isLifecycleSibling(call, terminal objectIdentity) bool {
	matchesObjectVar := func(v string) bool {
		return v != "" && (v == terminal.ReceiverVar || v == terminal.AssignedVar)
	}
	if matchesObjectVar(call.ReceiverVar) {
		return true
	}
	if terminal.ChainID != "" && call.ChainID == terminal.ChainID {
		return true
	}
	if matchesObjectVar(call.AssignedVar) {
		return true
	}
	return false
}

// deriveObjectLifecycleCalls returns the calls in fn that belong to the
// lifecycle of the crypto object identified by a terminal crypto call. This is
// the callgraph-derived replacement for rule-tagged "supporting calls": rules
// detect only the terminal crypto operation, and the surrounding setup/lifecycle
// calls are recovered structurally from the call graph.
//
// The crypto object's identity is the set of variables the terminal call touches
// directly: the variable it is invoked on (ReceiverVar) and/or the variable its
// result is bound to (AssignedVar). A call is part of the object's lifecycle when
// any of the following holds:
//
//   - it is invoked on one of the object variables (ReceiverVar match) — e.g.
//     digest.update(...) for a SHA3Digest object;
//   - it is a sibling link of the same fluent chain (ChainID match) — e.g.
//     Password.hash(p) and addRandomSalt() for a ...withBcrypt() terminal;
//   - it produced one of the object variables (AssignedVar match) — e.g. the
//     ECKeyPairGenerator constructor for a generator.generateKeyPair() terminal.
//
// The terminal call itself is always excluded. Scope is deliberately
// object-lifecycle, not data-flow closure: calls bound to a different variable
// that merely flow into the object as arguments (e.g. an ECKeyGenerationParameters
// instance passed to init) are not pulled in.
func deriveObjectLifecycleCalls(fn *callgraph.FunctionDecl, terminal *callgraph.FunctionCall) []*callgraph.FunctionCall {
	if fn == nil || terminal == nil {
		return nil
	}

	terminalID := objectIdentity{
		ReceiverVar: terminal.ReceiverVar,
		AssignedVar: terminal.AssignedVar,
		ChainID:     terminal.ChainID,
	}

	out := make([]*callgraph.FunctionCall, 0)
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c == terminal {
			continue
		}
		callID := objectIdentity{ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID}
		if isLifecycleSibling(callID, terminalID) {
			out = append(out, c)
		}
	}
	return out
}
