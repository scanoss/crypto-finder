package scan

import "github.com/scanoss/crypto-finder/internal/callgraph"

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

	objectVars := make(map[string]bool, 2)
	if terminal.ReceiverVar != "" {
		objectVars[terminal.ReceiverVar] = true
	}
	if terminal.AssignedVar != "" {
		objectVars[terminal.AssignedVar] = true
	}

	out := make([]*callgraph.FunctionCall, 0)
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c == terminal {
			continue
		}
		if isObjectLifecycleCall(c, terminal, objectVars) {
			out = append(out, c)
		}
	}
	return out
}

// isObjectLifecycleCall reports whether call c belongs to the lifecycle of the
// crypto object identified by the terminal call and its object variables.
func isObjectLifecycleCall(c, terminal *callgraph.FunctionCall, objectVars map[string]bool) bool {
	if c.ReceiverVar != "" && objectVars[c.ReceiverVar] {
		return true
	}
	if terminal.ChainID != "" && c.ChainID == terminal.ChainID {
		return true
	}
	if c.AssignedVar != "" && objectVars[c.AssignedVar] {
		return true
	}
	return false
}
