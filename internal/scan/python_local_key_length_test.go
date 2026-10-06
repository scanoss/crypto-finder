// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const pyaPrefix = "cryptography.hazmat.primitives.asymmetric."

// TestPythonLocalKeyLength_ExactBitsThroughSupportingCallIDs pins which local
// variables resolve as a key size. A local resolves only when every binding of
// the name in the function is the same literal or zero-argument constructor
// call; anything else is absent, never a guess.
func TestPythonLocalKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	const header = "from cryptography.hazmat.primitives.asymmetric import rsa, dsa, dh, ec\n"
	rsaAPI, dsaAPI, dhAPI, ecAPI := pyaPrefix+"rsa.generate_private_key", pyaPrefix+"dsa.generate_private_key", pyaPrefix+"dh.generate_parameters", pyaPrefix+"ec.generate_private_key"
	rsaCall := func(name string) string { return "rsa.generate_private_key(65537, " + name + ")" }

	cases := []pythonKeyLengthCase{
		{"rsa positional local", "", "def f():\n    bits = 2048\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 2048},
		{"rsa keyword local", "", "def f():\n    bits = 4096\n    return RSA\n", "rsa.generate_private_key(public_exponent=65537, key_size=bits)", rsaAPI, 1, 4096},
		{"dh positional local", "", "def f():\n    size = 3072\n    return RSA\n", "dh.generate_parameters(2, size)", dhAPI, 1, 3072},
		{"dsa positional local", "", "def f():\n    n = 1024\n    return RSA\n", "dsa.generate_private_key(n)", dsaAPI, 0, 1024},
		{"ec curve local", "", "def f():\n    c = ec.SECP521R1()\n    return RSA\n", "ec.generate_private_key(c)", ecAPI, 0, 521},
		{"ec curve local used in keyword", "", "def f():\n    c = ec.SECP384R1()\n    return RSA\n", "ec.generate_private_key(curve=c)", ecAPI, 0, 384},
		{"method local", "", "class K:\n    def f(self):\n        bits = 3072\n        return RSA\n", rsaCall("bits"), rsaAPI, 1, 3072},
		{"local declared after an if/else of the same literal", "", "def f(flag):\n    if flag:\n        bits = 2048\n    else:\n        bits = 2048\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 2048},
		{"local shadows a different module constant", "BITS = 3072\n", "def f():\n    BITS = 1024\n    return RSA\n", rsaCall("BITS"), rsaAPI, 1, 1024},
		{"closure reads the enclosing local", "", "def f():\n    bits = 2048\n    def g():\n        return RSA\n    return g\n", rsaCall("bits"), rsaAPI, 1, 2048},
		{"module constant still resolves without a local", "BITS = 3072\n", "def f():\n    return RSA\n", rsaCall("BITS"), rsaAPI, 1, 3072},

		{"reassigned to another literal", "", "def f():\n    bits = 1024\n    bits = 4096\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"conditional reassignment", "", "def f(flag):\n    bits = 2048\n    if flag:\n        bits = 1024\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"if/else different literals", "", "def f(flag):\n    if flag:\n        bits = 2048\n    else:\n        bits = 4096\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"try/except different literals", "", "def f():\n    try:\n        bits = 2048\n    except Exception:\n        bits = 1024\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"augmented assignment", "", "def f():\n    bits = 1024\n    bits += 1024\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"loop target of the same name", "", "def f(items):\n    bits = 2048\n    for bits in items:\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"tuple unpacking", "", "def f(pair):\n    first, bits = pair\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"tuple unpacking after a literal", "", "def f(pair):\n    bits = 2048\n    bits, other = pair\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"starred unpacking", "", "def f(items):\n    bits = 2048\n    *bits, last = items\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"parameter of the same name", "", "def f(bits):\n    bits = 2048\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"parameter default shadowing a module constant", "BITS = 3072\n", "def f(BITS=1024):\n    return RSA\n", rsaCall("BITS"), rsaAPI, 1, 0},
		{"global declaration", "", "def f():\n    global bits\n    bits = 2048\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"nonlocal declaration", "", "def f():\n    bits = 2048\n    def g():\n        nonlocal bits\n        bits = 1024\n        return RSA\n    return g\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"walrus rebinding", "", "def f():\n    bits = 2048\n    if (bits := 1024) > 0:\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"comprehension target", "", "def f(items):\n    bits = 2048\n    return [RSA for bits in items]\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"with target", "", "def f(ctx):\n    bits = 2048\n    with ctx as bits:\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"except target", "", "def f():\n    bits = 2048\n    try:\n        pass\n    except Exception as bits:\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"import of the same name", "", "def f():\n    bits = 2048\n    from sizes import bits\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"nested def parameter of the same name", "", "def f():\n    bits = 2048\n    def g(bits):\n        return RSA\n    return g\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"lambda parameter of the same name", "", "def f():\n    bits = 2048\n    return lambda bits: RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"nested def of the same name", "", "def f():\n    bits = 2048\n    def bits():\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"class of the same name", "", "def f():\n    bits = 2048\n    class bits:\n        pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"deleted name", "", "def f():\n    bits = 2048\n    del bits\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"match capture", "", "def f(x):\n    bits = 2048\n    match x:\n        case [bits]:\n            pass\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"annotation without a value", "", "def f():\n    bits = 2048\n    bits: int\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"computed value", "", "def f(n):\n    bits = n * 2\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"call with arguments is not a curve constructor", "", "def f():\n    c = ec.SECP521R1(1)\n    return RSA\n", "ec.generate_private_key(c)", ecAPI, 0, 0},
		{"curve reassigned in a branch", "", "def f(flag):\n    c = ec.SECP256R1()\n    if flag:\n        c = ec.SECP521R1()\n    return RSA\n", "ec.generate_private_key(c)", ecAPI, 0, 0},
		{"local computed shadows a module constant", "BITS = 3072\n", "def f(n):\n    BITS = n\n    return RSA\n", rsaCall("BITS"), rsaAPI, 1, 0},
		{"self attribute", "", "class K:\n    BITS = 2048\n    def f(self):\n        return RSA\n", rsaCall("self.BITS"), rsaAPI, 1, 0},
		{"nested def binding does not leak to the enclosing function", "bits = 4096\n", "def f():\n    def g():\n        bits = 1024\n        return RSA\n    return g\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"sibling nested def binding does not leak", "bits = 4096\n", "def f():\n    def g():\n        bits = 1024\n    def h():\n        return RSA\n    return g, h\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"nested class binding does not leak", "bits = 4096\n", "def f():\n    class A:\n        bits = 2048\n        def m(self):\n            return RSA\n    return A\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"sibling nested def curve does not leak", "", "def f():\n    def g():\n        c = ec.SECP521R1()\n    def h():\n        return RSA\n    return g, h\n", "ec.generate_private_key(c)", ecAPI, 0, 0},
		{"nested def curve binding does not leak", "", "def f():\n    def g():\n        c = ec.SECP521R1()\n        return RSA\n    return g\n", "ec.generate_private_key(c)", ecAPI, 0, 0},
		{"module lambda parameter shadows a module constant", "bits = 4096\n", "f = lambda bits: RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"lambda parameter shadows an enclosing local", "", "def f():\n    bits = 2048\n    return lambda bits: RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
		{"lambda parameter does not hide the module constant outside the lambda", "bits = 4096\n", "f = lambda bits: bits\n\ndef g():\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 4096},
		{"binding in a sibling function does not leak", "", "def g():\n    bits = 2048\n\ndef f():\n    return RSA\n", rsaCall("bits"), rsaAPI, 1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkPythonKeyLengthCase(t, header, c) })
	}
}

type pythonKeyLengthCase struct {
	name     string
	module   string
	function string
	call     string
	api      string
	index    int
	wantBits int
}

// checkPythonKeyLengthCase scans header + module + function, with the first
// RSA placeholder in function replaced by the case's call, and reads the size
// the way consumers do.
func checkPythonKeyLengthCase(t *testing.T, header string, c pythonKeyLengthCase) {
	t.Helper()
	source := header + "\n" + c.module + c.function
	source = strings.Replace(source, "RSA", c.call, 1)
	line := 0
	for i, text := range strings.Split(source, "\n") {
		if strings.Contains(text, c.call) {
			line = i + 1
		}
	}
	if line == 0 {
		t.Fatalf("call %q is not in the fixture", c.call)
	}
	exports := terminalExports(t, "python", "k.py", source, line, c.call, c.api, "")
	for name, got := range map[string]*graphfrag.ResolvedKeyLength{
		"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, c.api),
		"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, c.api),
	} {
		if c.wantBits == 0 {
			if got != nil && got.Bits != nil {
				t.Fatalf("%s: resolved_key_length bits = %d, want absent", name, *got.Bits)
			}
			continue
		}
		if got == nil || got.Bits == nil || *got.Bits != c.wantBits {
			t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, c.wantBits)
		}
		if got.Provenance != keyLengthProvenanceConstant || got.SourceCall.ParameterIndex != c.index {
			t.Fatalf("%s: provenance/source = %#v, want constant at parameter %d", name, got, c.index)
		}
	}
	for i := range exports.live.SupportingCalls {
		call := exports.live.SupportingCalls[i].SupportingCall
		if call == nil || call.ResolvedKeyLength == nil || call.ResolvedKeyLength.Bits == nil {
			continue
		}
		if *call.ResolvedKeyLength.Bits != c.wantBits {
			t.Fatalf("supporting call %s carries %d bits, want every carrier on the graph to agree on %d", call.FunctionName, *call.ResolvedKeyLength.Bits, c.wantBits)
		}
	}
}
