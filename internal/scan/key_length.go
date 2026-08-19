// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	// keySizeProperty is the contract contribution this evaluator consumes.
	// Contracts contribute other properties too (algorithm, curve, nonceSize);
	// only keySize yields resolved_key_length evidence.
	keySizeProperty = "keySize"

	keyLengthProvenanceConstant = "constant"
	keyLengthProvenanceUnknown  = "unknown"

	// maxKeyLengthSourceDepth bounds the walk from a supporting call's argument
	// back to the contract-marked call that produced it.
	maxKeyLengthSourceDepth = 8

	// maxKeyMaterialBytes rejects implausible array allocations rather than
	// overflowing a bit count derived from them.
	maxKeyMaterialBytes = 4096
)

// byteArrayAllocation matches a Java array-allocation expression whose element
// count is a literal, e.g. `new byte[32]`.
var byteArrayAllocation = regexp.MustCompile(`^new\s+byte\s*\[\s*(\d+)\s*]$`)

// resolvedKeyLengthFromContract derives raw key-length evidence for a
// structurally derived supporting call. It publishes configured bits, not a
// policy interpretation, and retains unknown provenance without fabricating a
// value.
//
// Evidence arrives in two shapes. The supporting call may carry the key size
// itself (`generator.init(256)`), or it may receive a parameter object that
// carries it (`generator.initialize(spec)` after `new ECGenParameterSpec(..)`).
// The spec constructor is not part of the generator's object lifecycle, so it
// is never a supporting call of its own; its value reaches the export as an
// argument source node instead.
func resolvedKeyLengthFromContract(
	ctx *exportBuildContext,
	matches []contracts.Contract,
	call *callgraph.FunctionCall,
	parameters []callGraphParameter,
	parameterTypes []string,
) *graphfrag.ResolvedKeyLength {
	if call == nil {
		return nil
	}
	for i := range matches {
		contract := &matches[i]
		role := keySizeParameterRole(contract)
		if role == nil || !contractParameterTypesMatch(contract, parameters, parameterTypes) {
			continue
		}
		return resolvedKeyLengthForRole(contract.Method, call.Line, parameters, role)
	}
	return resolvedKeyLengthFromParameterSources(ctx, parameters)
}

// keySizeParameterRole returns the contract's key-size-contributing parameter,
// or nil when the contract contributes no key size.
func keySizeParameterRole(contract *contracts.Contract) *contracts.ParameterContract {
	for i := range contract.Parameters {
		role := &contract.Parameters[i]
		if role.Index == nil || role.Contributes == nil {
			continue
		}
		if role.Contributes.Property == keySizeProperty {
			return role
		}
	}
	return nil
}

func resolvedKeyLengthForRole(
	functionName string,
	line int,
	parameters []callGraphParameter,
	role *contracts.ParameterContract,
) *graphfrag.ResolvedKeyLength {
	resolved := &graphfrag.ResolvedKeyLength{
		Provenance: keyLengthProvenanceUnknown,
		SourceCall: graphfrag.SourceCallRef{
			FunctionName:   functionName,
			Line:           line,
			ParameterIndex: *role.Index,
		},
	}
	for i := range parameters {
		parameter := &parameters[i]
		if parameter.ParameterIndex != *role.Index {
			continue
		}
		if bits, ok := resolveContractKeyBits(parameter.ResolvedValue, role.Contributes.Derivation); ok {
			resolved.Bits = &bits
			resolved.Provenance = keyLengthProvenanceConstant
		}
		break
	}
	return resolved
}

// contractParameterTypesMatch selects the contract overload using call-site
// provenance before falling back to resolver metadata. Resolver metadata can
// collapse same-arity platform overloads; a declared source parameter type (or
// a literal whose type is established by the contract) is more precise here.
func contractParameterTypesMatch(contract *contracts.Contract, parameters []callGraphParameter, parameterTypes []string) bool {
	if len(contract.ParameterTypes) != len(parameters) {
		return false
	}
	for index, expected := range contract.ParameterTypes {
		parameter := &parameters[index]
		for sourceIndex := range parameter.SourceNodes {
			source := &parameter.SourceNodes[sourceIndex]
			if declared := strings.TrimSpace(source.DeclaredType); declared != "" {
				if declared != expected {
					return false
				}
				goto nextParameter
			}
		}
		if expected == "int" && looksLikeIntegerLiteralExpr(parameter.ArgumentExpression) {
			goto nextParameter
		}
		if index >= len(parameterTypes) || strings.TrimSpace(parameterTypes[index]) != expected {
			return false
		}
	nextParameter:
	}
	return true
}

// resolvedKeyLengthFromParameterSources looks for a contract-marked producer
// behind one of the call's arguments — the parameter-spec constructors the JCA
// uses to carry a key size into initialize/init.
func resolvedKeyLengthFromParameterSources(
	ctx *exportBuildContext,
	parameters []callGraphParameter,
) *graphfrag.ResolvedKeyLength {
	if ctx == nil || ctx.kb == nil {
		return nil
	}
	for i := range parameters {
		if resolved := resolvedKeyLengthFromSourceNodes(ctx, parameters[i].SourceNodes, 0); resolved != nil {
			return resolved
		}
	}
	return nil
}

func resolvedKeyLengthFromSourceNodes(
	ctx *exportBuildContext,
	nodes []exportSourceNode,
	depth int,
) *graphfrag.ResolvedKeyLength {
	if depth >= maxKeyLengthSourceDepth {
		return nil
	}
	for i := range nodes {
		node := &nodes[i]
		if node.Type == sourceNodeTypeCallResult && node.CallTarget != "" {
			if resolved := resolvedKeyLengthFromProducer(ctx, node); resolved != nil {
				return resolved
			}
		}
		if resolved := resolvedKeyLengthFromSourceNodes(ctx, node.SourceNodes, depth+1); resolved != nil {
			return resolved
		}
	}
	return nil
}

// resolvedKeyLengthFromProducer reads the key size off a producing call whose
// contract marks one argument as key-size-contributing.
//
// A producer's nested source nodes are its arguments in declaration order, so
// their count is its arity. In-project callees also carry their resolved return
// sources there; the resulting arity mismatch simply misses the contract, which
// keeps this fail-closed for anything but a library call.
func resolvedKeyLengthFromProducer(ctx *exportBuildContext, node *exportSourceNode) *graphfrag.ResolvedKeyLength {
	arguments := node.SourceNodes
	matches := ctx.kb.ContractsFor(node.CallTarget, len(arguments))
	for i := range matches {
		contract := &matches[i]
		role := keySizeParameterRole(contract)
		if role == nil || *role.Index >= len(arguments) {
			continue
		}
		argument := &arguments[*role.Index]
		resolved := &graphfrag.ResolvedKeyLength{
			Provenance: keyLengthProvenanceUnknown,
			SourceCall: graphfrag.SourceCallRef{
				FunctionName:   contract.Method,
				Line:           sourceNodeLine(node),
				ParameterIndex: *role.Index,
			},
		}
		if bits, ok := resolveContractKeyBits(argument.Value, role.Contributes.Derivation); ok {
			resolved.Bits = &bits
			resolved.Provenance = keyLengthProvenanceConstant
		}
		return resolved
	}
	return nil
}

func sourceNodeLine(node *exportSourceNode) int {
	if node.Location == nil {
		return 0
	}
	return node.Location.Line
}

// resolveContractKeyBits applies the derivation declared by the matched
// contract contribution. Unresolved values fail closed rather than being
// interpreted or fabricated.
func resolveContractKeyBits(value, derivation string) (int, bool) {
	value = strings.TrimSpace(value)
	switch derivation {
	case string(contracts.DerivationArgumentValue):
		// The JCA keysize argument is already expressed in raw bits.
		bits, err := strconv.Atoi(value)
		return bits, err == nil && bits > 0
	case string(contracts.DerivationArgumentBitLength):
		return keyMaterialBits(value)
	case string(contracts.DerivationArgumentCurveBits):
		return ecCurveFieldBits(value)
	default:
		return 0, false
	}
}

// keyMaterialBits reads the bit length of key material whose size is fixed at
// the call site: a literal byte-array allocation or a string literal.
func keyMaterialBits(value string) (int, bool) {
	if match := byteArrayAllocation.FindStringSubmatch(value); match != nil {
		length, err := strconv.Atoi(match[1])
		if err != nil || length <= 0 || length > maxKeyMaterialBytes {
			return 0, false
		}
		return length * 8, true
	}
	if literal, ok := unquoteLiteral(value); ok && literal != "" && len(literal) <= maxKeyMaterialBytes {
		return len(literal) * 8, true
	}
	return 0, false
}

// ecCurveFieldBits maps a standard elliptic-curve name to its field size in
// bits. Only names this table knows resolve; an unlisted or non-standard curve
// stays unresolved rather than being guessed from the digits in its name.
func ecCurveFieldBits(value string) (int, bool) {
	name, ok := unquoteLiteral(value)
	if !ok {
		return 0, false
	}
	bits, ok := ecCurveBits[strings.ToLower(strings.TrimSpace(name))]
	return bits, ok
}

// ecCurveBits covers the SEC, NIST and Brainpool curve names accepted by
// ECGenParameterSpec, including the X9.62/NIST aliases for the same curve.
var ecCurveBits = map[string]int{
	// SEC prime curves and their X9.62 / NIST aliases.
	"secp160k1": 160, "secp160r1": 160, "secp160r2": 160,
	"secp192k1": 192,
	"secp192r1": 192, "prime192v1": 192, "p-192": 192, "nistp192": 192,
	"secp224k1": 224,
	"secp224r1": 224, "p-224": 224, "nistp224": 224,
	"secp256k1": 256,
	"secp256r1": 256, "prime256v1": 256, "p-256": 256, "nistp256": 256,
	"secp384r1": 384, "p-384": 384, "nistp384": 384,
	"secp521r1": 521, "p-521": 521, "nistp521": 521,

	// SEC binary curves and their NIST aliases.
	"sect163k1": 163, "b-163": 163, "k-163": 163,
	"sect163r1": 163, "sect163r2": 163,
	"sect233k1": 233, "k-233": 233,
	"sect233r1": 233, "b-233": 233,
	"sect239k1": 239,
	"sect283k1": 283, "k-283": 283,
	"sect283r1": 283, "b-283": 283,
	"sect409k1": 409, "k-409": 409,
	"sect409r1": 409, "b-409": 409,
	"sect571k1": 571, "k-571": 571,
	"sect571r1": 571, "b-571": 571,

	// Brainpool curves.
	"brainpoolp160r1": 160, "brainpoolp192r1": 192, "brainpoolp224r1": 224,
	"brainpoolp256r1": 256, "brainpoolp320r1": 320, "brainpoolp384r1": 384,
	"brainpoolp512r1": 512,
}

// unquoteLiteral strips the surrounding quotes of a source-level string
// literal. A value that is not a quoted literal is not a resolved constant.
func unquoteLiteral(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
		return "", false
	}
	return value[1 : len(value)-1], true
}
