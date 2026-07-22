package scan

import "github.com/scanoss/crypto-finder/internal/callgraph"

// objectIdentity is the minimal per-call identity the object-lifecycle grouping
// policy needs: the variable a call is invoked on, the variable its result is
// bound to, and the fluent-chain group it belongs to. It is the shared currency
// between the live-scan export (which projects it from callgraph.FunctionCall)
// and the annotate-from-cache path (which projects it from a graph-fragment-1.4
// edge's receiver_var/assigned_var/chain_id). Both paths run the same directional
// selector below so they pick the identical set of supporting calls.
type objectIdentity struct {
	ReceiverVar string
	AssignedVar string
	ChainID     string
}

type lifecycleSelector struct {
	calls       []objectIdentity
	selected    []bool
	downVisited map[string]bool
	upVisited   map[string]bool
}

// lifecycleCallIndices returns the directional receiver/assignment lifecycle
// around one terminal call. Factory terminals walk down into the objects they
// produce; operations walk up through their unique producer path. Keeping those
// directions separate prevents sibling products of one factory from becoming
// supporting calls for each other.
func lifecycleCallIndices(calls []objectIdentity, terminalIdx int) []int {
	if terminalIdx < 0 || terminalIdx >= len(calls) {
		return nil
	}

	selector := lifecycleSelector{
		calls:       calls,
		selected:    make([]bool, len(calls)),
		downVisited: make(map[string]bool),
		upVisited:   make(map[string]bool),
	}
	selector.selected[terminalIdx] = true
	terminal := calls[terminalIdx]
	selector.selectChain(terminal.ChainID)
	switch {
	case terminal.ReceiverVar == "":
		selector.selectDescendants(terminal.AssignedVar)
	case terminal.AssignedVar != "" && selector.hasReceiver(terminal.AssignedVar):
		selector.selectDescendants(terminal.AssignedVar)
		selector.selectReceiverCalls(terminal.ReceiverVar, terminal.AssignedVar)
		selector.selectAncestors(terminal.ReceiverVar)
	default:
		selector.selectReceiverCalls(terminal.ReceiverVar, "")
		selector.selectAncestors(terminal.ReceiverVar)
	}

	out := make([]int, 0, len(calls)-1)
	for i := range calls {
		if i != terminalIdx && selector.selected[i] {
			out = append(out, i)
		}
	}
	return out
}

func (s *lifecycleSelector) hasReceiver(objectVar string) bool {
	for i := range s.calls {
		if s.calls[i].ReceiverVar == objectVar {
			return true
		}
	}
	return false
}

func (s *lifecycleSelector) selectChain(chainID string) {
	if chainID == "" {
		return
	}
	for i := range s.calls {
		if s.calls[i].ChainID == chainID {
			s.selected[i] = true
		}
	}
}

func (s *lifecycleSelector) selectDescendants(objectVar string) {
	if objectVar == "" || s.downVisited[objectVar] {
		return
	}
	s.downVisited[objectVar] = true
	for i := range s.calls {
		if s.calls[i].ReceiverVar != objectVar {
			continue
		}
		s.selected[i] = true
		s.selectChain(s.calls[i].ChainID)
		if s.calls[i].AssignedVar != objectVar {
			s.selectDescendants(s.calls[i].AssignedVar)
		}
	}
}

func (s *lifecycleSelector) selectAncestors(objectVar string) {
	if objectVar == "" || s.upVisited[objectVar] {
		return
	}
	s.upVisited[objectVar] = true
	for i := range s.calls {
		if s.calls[i].AssignedVar != objectVar {
			continue
		}
		s.selected[i] = true
		s.selectChain(s.calls[i].ChainID)
		parentVar := s.calls[i].ReceiverVar
		if parentVar != "" {
			s.selectReceiverCalls(parentVar, objectVar)
			s.selectAncestors(parentVar)
		}
	}
}

func (s *lifecycleSelector) selectReceiverCalls(receiverVar, pathChild string) {
	for i := range s.calls {
		if s.calls[i].ReceiverVar != receiverVar {
			continue
		}
		assigned := s.calls[i].AssignedVar
		if pathChild != "" && assigned != "" && assigned != receiverVar && assigned != pathChild {
			continue
		}
		s.selected[i] = true
		s.selectChain(s.calls[i].ChainID)
	}
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

	identities := make([]objectIdentity, len(fn.Calls))
	terminalIdx := -1
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c == terminal {
			terminalIdx = i
		}
		identities[i] = objectIdentity{ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID}
	}

	indices := lifecycleCallIndices(identities, terminalIdx)
	out := make([]*callgraph.FunctionCall, 0, len(indices))
	for _, i := range indices {
		out = append(out, &fn.Calls[i])
	}
	return out
}
