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

// pythonKeywordArgumentPattern matches a Python keyword-argument's raw text
// (`extractPythonCallArguments` preserves it verbatim, comma-split, with no
// keyword_argument stripping — see design.md D6): `<name> = <value>`,
// e.g. "length=32" or "length=KEY_LEN". Only Python call sites ever produce
// an ArgumentExpression matching this shape (row C, python-parser-parity-2,
// step 3a) — Java/Go/Rust have no name=value argument syntax, so this
// pattern can never match their call-site text.
var pythonKeywordArgumentPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)

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
//
// Python keyword-name matching runs first because an exact role name is
// stronger evidence than a declaration-order type match when valid keyword
// arguments are reordered. Non-Python ecosystems retain the original
// positional/source resolution order.
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
	// A Python keyword names its declared role exactly and therefore outranks
	// positional/type matching, whose declaration-order indexes do not follow
	// reordered keyword slots.
	if ctx != nil && ctx.kb != nil && ctx.kb.Ecosystem == ecosystemPython {
		if resolved := resolvedKeyLengthFromKeywordName(matches, call, parameters); resolved != nil {
			return resolved
		}
	}
	for i := range matches {
		contract := &matches[i]
		role := keySizeParameterRole(contract)
		if role == nil || !contractParameterTypesMatch(contract, parameters, parameterTypes) {
			continue
		}
		return resolvedKeyLengthForRole(contract.Method, call.Line, parameters, role)
	}
	if resolved := resolvedKeyLengthFromParameterSources(ctx, parameters); resolved != nil {
		return resolved
	}
	if ctx == nil || ctx.kb == nil {
		return nil
	}
	switch ctx.kb.Ecosystem {
	case ecosystemPython, ecosystemGo, ecosystemC, ecosystemNode:
		// Step 3b (design.md §5.2) is additive ONLY for these ecosystems: it
		// resolves a purely positional constant with NO call-site declared-type
		// evidence at all, a precondition every other ecosystem's own
		// extractCallArguments can already satisfy accidentally (e.g. a
		// resolver-unresolved variable at the keySize index) — see
		// TestResolvedKeyLength_JavaUnchangedByKeywordPath (G7, PR #310
		// phase-2 review). Gating on ecosystem keeps every other
		// ecosystem's resolution byte-identical to before row C. Node joins
		// them because its contracts carry no parameter_types either: a
		// call-site literal is the only evidence of the options object.
		return resolvedKeyLengthFromPositionalConstant(matches, call, parameters, parameterTypes, ctx.kb.Ecosystem != ecosystemPython)
	default:
		return nil
	}
}

// resolvedKeyLengthFromKeywordName implements step 3a (design.md §5.2): a
// keyword argument at ANY call-site position whose text is `<name>=<value>`
// and whose <name> matches a keySize role's declared Name resolves
// directly — deliberately bypassing contractParameterTypesMatch, since a
// keyword name identifies the parameter exactly, a strictly stronger
// signal than a positional declared-type match. Once a matching keyword IS
// found, this always returns a non-nil record (constant when the value
// resolves, unknown otherwise) — exactly like resolvedKeyLengthForRole
// (steps 1-2) already does for a positional match.
func resolvedKeyLengthFromKeywordName(matches []contracts.Contract, call *callgraph.FunctionCall, parameters []callGraphParameter) *graphfrag.ResolvedKeyLength {
	for i := range matches {
		contract := &matches[i]
		role := keySizeParameterRole(contract)
		if role == nil || role.Name == "" {
			continue
		}
		for j := range parameters {
			parameter := &parameters[j]
			m := pythonKeywordArgumentPattern.FindStringSubmatch(parameter.ArgumentExpression)
			if len(m) < 3 || m[1] != role.Name {
				continue
			}
			value := parameter.ResolvedValue
			if value == "" {
				value = m[2]
			}
			resolved := &graphfrag.ResolvedKeyLength{
				Provenance: keyLengthProvenanceUnknown,
				SourceCall: graphfrag.SourceCallRef{
					FunctionName:   contract.Method,
					Line:           call.Line,
					ParameterIndex: *role.Index,
				},
			}
			if bits, ok := resolveContractKeyBits(contractArgumentValue(parameter, value, role.Contributes.Derivation), role.Contributes.Derivation); ok {
				resolved.Bits = &bits
				resolved.Provenance = keyLengthProvenanceConstant
			}
			return resolved
		}
	}
	return nil
}

// resolvedKeyLengthFromPositionalConstant implements step 3b (design.md
// §5.2): a contract that declares parameter_types (asserting one
// unambiguous signature), or, for Go and C where contracts carry no
// parameter_types and the exact arity lookup already fixes the signature, an
// untyped contract, but whose call site supplies NO declared-type
// evidence at the keySize index — neither a call-site SourceNode.DeclaredType
// nor a resolver-supplied parameterTypes[index] — still resolves when the
// raw positional argument itself is a constant. This is what makes a
// purely positional `PBKDF2(password, salt, 32)` resolve. Unlike step 3a,
// this NEVER emits an "unknown" record: reaching here means steps 1-2 and
// 3a already had their chance and found nothing, so silence on an
// unresolved value is correct — a false "unknown" record would be new
// noise, not new evidence.
func resolvedKeyLengthFromPositionalConstant(matches []contracts.Contract, call *callgraph.FunctionCall, parameters []callGraphParameter, parameterTypes []string, allowUntypedContract bool) *graphfrag.ResolvedKeyLength {
	for i := range matches {
		contract := &matches[i]
		role := keySizeParameterRole(contract)
		if role == nil || (len(contract.ParameterTypes) == 0 && !allowUntypedContract) {
			continue
		}
		if role.Contributes.ArgumentProperty != "" && len(matchingConditionalContracts([]contracts.Contract{*contract}, call)) == 0 {
			// The property a conditional contract names belongs to its own
			// key type only. exactConditionalContracts hands back every
			// contract when none matched, which for a key type held in a
			// variable would read modulusLength off a call that may be EC.
			continue
		}
		index := *role.Index
		if index >= len(parameters) {
			continue
		}
		if index < len(parameterTypes) && strings.TrimSpace(parameterTypes[index]) != "" {
			continue
		}
		if parameterHasDeclaredType(&parameters[index]) {
			continue
		}
		if pythonKeywordArgumentPattern.MatchString(parameters[index].ArgumentExpression) {
			// A keyword-shaped expression at the keySize POSITION is not
			// necessarily the keySize ARGUMENT: Python keyword arguments can
			// appear at any raw position regardless of their declared index
			// (G2, PR #310 phase-2 review — `PBKDF2(pw, salt, count=1000)`
			// previously read "count"'s value as the key length). Step 3a
			// already handles every genuine keyword match by NAME; a
			// keyword-shaped expression that reaches here matched no role
			// name and must never be reinterpreted positionally.
			continue
		}
		bits, ok := resolveContractKeyBits(roleArgumentValue(parameters, &parameters[index], parameters[index].ResolvedValue, role), role.Contributes.Derivation)
		if !ok {
			continue
		}
		return &graphfrag.ResolvedKeyLength{
			Bits:       &bits,
			Provenance: keyLengthProvenanceConstant,
			SourceCall: graphfrag.SourceCallRef{
				FunctionName:   contract.Method,
				Line:           call.Line,
				ParameterIndex: index,
			},
		}
	}
	return nil
}

// parameterHasDeclaredType reports whether any of parameter's source nodes
// carries a non-empty DeclaredType — call-site type evidence step 3b
// requires to be ABSENT before it will resolve a purely positional
// argument.
func parameterHasDeclaredType(parameter *callGraphParameter) bool {
	for i := range parameter.SourceNodes {
		if strings.TrimSpace(parameter.SourceNodes[i].DeclaredType) != "" {
			return true
		}
	}
	return false
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
		if bits, ok := resolveContractKeyBits(roleArgumentValue(parameters, parameter, parameter.ResolvedValue, role), role.Contributes.Derivation); ok {
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
	var found []*graphfrag.ResolvedKeyLength
	for i := range parameters {
		found = collectProducerKeyLengths(ctx, parameters[i].SourceNodes, 0, found)
	}
	return agreedKeyLength(found)
}

// collectProducerKeyLengths gathers every key-size producer behind an
// argument. One object can be assembled from several lookups
// (`new ECDomainParameters(a.getCurve(), b.getG(), ..)`), and the first of them
// is not evidence of the key's size.
func collectProducerKeyLengths(
	ctx *exportBuildContext,
	nodes []exportSourceNode,
	depth int,
	found []*graphfrag.ResolvedKeyLength,
) []*graphfrag.ResolvedKeyLength {
	if depth >= maxKeyLengthSourceDepth {
		return found
	}
	for i := range nodes {
		node := &nodes[i]
		if node.Type == sourceNodeTypeCallResult && node.CallTarget != "" {
			if resolved := resolvedKeyLengthFromProducer(ctx, node); resolved != nil {
				found = append(found, resolved)
				continue
			}
		}
		found = collectProducerKeyLengths(ctx, node.SourceNodes, depth+1, found)
	}
	return found
}

// agreedKeyLength returns the producers' common size. Producers that disagree,
// or any one of them that resolves to no size, leave the size unknown: a
// consumer that sees two sizes on one graph drops both.
func agreedKeyLength(found []*graphfrag.ResolvedKeyLength) *graphfrag.ResolvedKeyLength {
	if len(found) == 0 {
		return nil
	}
	first := found[0]
	for _, other := range found[1:] {
		if first.Bits == nil || other.Bits == nil || *first.Bits != *other.Bits {
			unknown := *first
			unknown.Bits = nil
			unknown.Provenance = keyLengthProvenanceUnknown
			return &unknown
		}
	}
	return first
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
	case string(contracts.DerivationArgumentParameterSetBits):
		bits, ok := dsaParameterSetBits[value]
		return bits, ok
	case string(contracts.DerivationArgumentByteLength):
		// A Python KDF's dklen/length/hash_len argument is expressed in
		// BYTES (row C, python-parser-parity-2), unlike argument_value
		// (already bits) or argument_bit_length (counts key MATERIAL
		// length, not a declared count).
		bytesCount, err := strconv.Atoi(value)
		if err != nil || bytesCount <= 0 || bytesCount > maxKeyMaterialBytes {
			return 0, false
		}
		return bytesCount * 8, true
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
// bits. The name is a quoted literal (ECGenParameterSpec("secp256r1")) or a
// curve constructor (Python ec.SECP384R1(), Go elliptic.P256()). Only names
// these tables know resolve; an unlisted or non-standard curve stays
// unresolved rather than being guessed from the digits in its name.
func ecCurveFieldBits(value string) (int, bool) {
	if name, ok := unquoteLiteral(value); ok {
		bits, ok := ecCurveBits[strings.ToLower(strings.TrimSpace(name))]
		return bits, ok
	}
	return ecCurveConstructorBits(value)
}

// ecCurveConstructorBits resolves a curve constructor expression or call
// target. The qualifier must be the curve package itself, so a user type that
// happens to share a curve's name resolves to nothing.
func ecCurveConstructorBits(value string) (int, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "()")
	dot := strings.LastIndex(value, ".")
	if dot <= 0 || strings.ContainsAny(value, "() \t\n\"") {
		return 0, false
	}
	qualifier, name := value[:dot], value[dot+1:]
	switch {
	case qualifier == "ec" || strings.HasSuffix(qualifier, ".asymmetric.ec"):
		bits, ok := ecCurveBits[strings.ToLower(name)]
		return bits, ok
	case qualifier == "elliptic" || strings.HasSuffix(qualifier, "crypto/elliptic"):
		bits, ok := goEllipticCurveBits[name]
		return bits, ok
	case qualifier == "ecdh" || strings.HasSuffix(qualifier, "crypto/ecdh"):
		bits, ok := goECDHCurveBits[name]
		return bits, ok
	default:
		return 0, false
	}
}

// goEllipticCurveBits covers the constructors crypto/elliptic exports.
var goEllipticCurveBits = map[string]int{"P224": 224, "P256": 256, "P384": 384, "P521": 521}

// goECDHCurveBits covers the NIST curves crypto/ecdh exports. X25519 is left
// out: no table here sizes a Montgomery or Edwards curve, so it stays absent
// rather than inventing a convention.
var goECDHCurveBits = map[string]int{"P256": 256, "P384": 384, "P521": 521}

// dsaParameterSetBits maps crypto/dsa's ParameterSizes constants to the
// modulus size L, the DSA key length. N is the subgroup order size and does not
// change the key length.
var dsaParameterSetBits = map[string]int{
	"dsa.L1024N160": 1024,
	"dsa.L2048N224": 2048,
	"dsa.L2048N256": 2048,
	"dsa.L3072N256": 3072,
}

// roleArgumentValue returns the text a keySize role's derivation reads. A role
// that names an argument property reads it from the object literal the call
// passes, and nothing when the argument is not an object literal that states
// the property outright (a variable, a spread, a computed key) or when Node
// would not accept the value for the call's key type. Any other role reads the
// argument itself.
func roleArgumentValue(parameters []callGraphParameter, parameter *callGraphParameter, resolved string, role *contracts.ParameterContract) string {
	property := role.Contributes.ArgumentProperty
	if property == "" {
		return contractArgumentValue(parameter, resolved, role.Contributes.Derivation)
	}
	value, ok := callgraph.NodeObjectLiteralProperty(parameter.ArgumentExpression, property)
	if !ok {
		return ""
	}
	keyType := ""
	for i := range parameters {
		if parameters[i].ParameterIndex == 0 {
			keyType, _ = unquoteLiteral(parameters[i].ArgumentExpression)
		}
	}
	if !validNodeOptionValue(keyType, property, value) {
		return ""
	}
	return value
}

// Node accepts a modulusLength or primeLength up to an unsigned 32-bit count,
// and an HMAC length up to 2^31-1 bits.
const (
	maxNodeKeyBits    = 1<<32 - 1
	maxNodeHMACLength = 1<<31 - 1
)

// validNodeOptionValue reports whether Node accepts value for property when
// generating a key of keyType, per nodejs/node doc/api/crypto.md. A value Node
// rejects or rewrites would otherwise be reported as the size of a key that was
// never generated: an AES length outside 128, 192 and 256 throws, an HMAC
// length that is not a multiple of 8 is truncated to floor(length / 8) bytes, a
// modulus above 32 bits does not fit, and a curve name must match exactly.
func validNodeOptionValue(keyType, property, value string) bool {
	switch property {
	case "modulusLength", "primeLength":
		n, err := strconv.ParseUint(value, 10, 64)
		return err == nil && n >= 1 && n <= maxNodeKeyBits
	case "length":
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return false
		}
		switch keyType {
		case "aes":
			return n == 128 || n == 192 || n == 256
		case "hmac":
			return n >= 8 && n%8 == 0 && n <= maxNodeHMACLength
		}
		return false
	case "namedCurve":
		name, ok := unquoteLiteral(value)
		return ok && isNodeCurveName(name)
	}
	return false
}

// isNodeCurveName reports whether name is spelled exactly as OpenSSL names a
// curve Node accepts: lowercase for the SEC and X9.62 names, an upper-case
// letter for the NIST aliases (P-256, B-163, K-163) and for brainpoolP...
// Surrounding whitespace or any other case makes Node throw.
func isNodeCurveName(name string) bool {
	key := strings.ToLower(name)
	if _, ok := ecCurveBits[key]; !ok || strings.HasPrefix(key, "nistp") {
		return false
	}
	switch {
	case strings.HasPrefix(key, "p-"), strings.HasPrefix(key, "b-"), strings.HasPrefix(key, "k-"):
		return name == strings.ToUpper(key[:1])+key[1:]
	case strings.HasPrefix(key, "brainpoolp"):
		return name == "brainpoolP"+key[len("brainpoolp"):]
	default:
		return name == key
	}
}

// contractArgumentValue returns the text a derivation reads from one argument.
// A curve constructor carries no resolved value, so the curve is read from the
// call that produced the argument, or from the argument expression itself when
// the graph kept no source for it. Several producers that disagree resolve to
// nothing.
func contractArgumentValue(parameter *callGraphParameter, resolved, derivation string) string {
	if derivation != string(contracts.DerivationArgumentCurveBits) || parameter == nil {
		return resolved
	}
	if _, ok := unquoteLiteral(resolved); ok {
		return resolved
	}
	candidates := curveConstructorCandidates(parameter.SourceNodes, 0)
	if len(candidates) == 0 {
		if strings.TrimSpace(resolved) != "" {
			return resolved
		}
		return strings.TrimSpace(parameter.ArgumentExpression)
	}
	for _, candidate := range candidates[1:] {
		if candidate != candidates[0] {
			return ""
		}
	}
	return candidates[0]
}

// curveConstructorCandidates collects the call targets that produce an
// argument, following variable and field hops but never descending into a
// call's own arguments.
func curveConstructorCandidates(nodes []exportSourceNode, depth int) []string {
	if depth >= maxKeyLengthSourceDepth {
		return nil
	}
	var out []string
	for i := range nodes {
		if nodes[i].Type == sourceNodeTypeCallResult {
			if nodes[i].CallTarget != "" {
				out = append(out, nodes[i].CallTarget)
			}
			continue
		}
		out = append(out, curveConstructorCandidates(nodes[i].SourceNodes, depth+1)...)
	}
	return out
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
