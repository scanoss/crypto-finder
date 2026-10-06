// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// receiverCurveRole returns the contract's receiver contribution to keySize,
// or nil when the contract reads its size from arguments only.
func receiverCurveRole(contract *contracts.Contract) *contracts.ParameterContract {
	for i := range contract.Parameters {
		role := &contract.Parameters[i]
		if role.Receiver && role.Contributes != nil && role.Contributes.Property == keySizeProperty {
			return role
		}
	}
	return nil
}

// resolvedKeyLengthFromReceiver reads the key size off the curve a call is
// invoked on: `ecdh.P256().GenerateKey(r)`, or `c.GenerateKey(r)` after
// `c := ecdh.P256()`. The receiver's producing call names the curve, and the
// contract's derivation turns that name into bits.
//
// It answers only when the receiver is unambiguous, and returns nil otherwise:
//   - a fluent chain must hold exactly the terminal call and one producer;
//   - a local variable must be bound once, by the call that produced it. A
//     parameter, a reassignment, a branch that rebinds it, or a variable whose
//     address is taken has more bindings than producing calls;
//   - every producer must name the same curve.
func resolvedKeyLengthFromReceiver(
	ctx *exportBuildContext,
	matches []contracts.Contract,
	fn *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
) *graphfrag.ResolvedKeyLength {
	if ctx == nil || fn == nil || call == nil {
		return nil
	}
	for i := range matches {
		role := receiverCurveRole(&matches[i])
		if role == nil {
			continue
		}
		return resolvedKeyLengthFromProducers(receiverProducers(fn, call))
	}
	return nil
}

func receiverProducers(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall) []*callgraph.FunctionCall {
	var producers []*callgraph.FunctionCall
	switch {
	case call.ReceiverVar != "":
		for i := range fn.Calls {
			if candidate := &fn.Calls[i]; candidate != call && candidate.AssignedVar == call.ReceiverVar && candidate.Line <= call.Line {
				producers = append(producers, candidate)
			}
		}
		if call.ReceiverBindings != len(producers) {
			return nil
		}
	case call.ChainID != "":
		for i := range fn.Calls {
			if candidate := &fn.Calls[i]; candidate != call && candidate.ChainID == call.ChainID {
				producers = append(producers, candidate)
			}
		}
		if len(producers) != 1 {
			return nil
		}
	}
	return producers
}

func resolvedKeyLengthFromProducers(producers []*callgraph.FunctionCall) *graphfrag.ResolvedKeyLength {
	if len(producers) == 0 {
		return nil
	}
	bits := 0
	for _, producer := range producers {
		if len(producer.Arguments) != 0 {
			return nil
		}
		producerBits, ok := ecCurveConstructorBits(fullFunctionName(producer.Callee))
		if !ok || (bits != 0 && producerBits != bits) {
			return nil
		}
		bits = producerBits
	}
	last := producers[len(producers)-1]
	return &graphfrag.ResolvedKeyLength{
		Bits:       &bits,
		Provenance: keyLengthProvenanceConstant,
		SourceCall: graphfrag.SourceCallRef{
			FunctionName: fullFunctionName(last.Callee),
			Line:         last.Line,
		},
	}
}

// withReceiverKeyLength combines the size read from a call's arguments with the
// one read from its receiver. The two are one key's size, so they must agree:
// two different sizes publish nothing rather than a guess between them.
func withReceiverKeyLength(fromArguments, fromReceiver *graphfrag.ResolvedKeyLength) *graphfrag.ResolvedKeyLength {
	switch {
	case fromReceiver == nil:
		return fromArguments
	case fromArguments == nil || fromArguments.Bits == nil:
		return fromReceiver
	case *fromArguments.Bits == *fromReceiver.Bits:
		return fromArguments
	default:
		return nil
	}
}
