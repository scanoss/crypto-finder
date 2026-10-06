// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// TestPythonModuleKeyLength_ExactBitsThroughSupportingCallIDs pins when a
// module-level name resolves as a key size: only when every module-level
// binding of it, and every `global`-declared rebinding anywhere in the file,
// is the same integer literal or zero-argument constructor call.
func TestPythonModuleKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	const header = "import os\nfrom cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
	rsaAPI, ecAPI := pyaPrefix+"rsa.generate_private_key", pyaPrefix+"ec.generate_private_key"
	const (
		useRSA = "def use():\n    return RSA\n"
		rsaUse = "rsa.generate_private_key(65537, bits)"
		ecUse  = "ec.generate_private_key(c)"
	)
	const intBase, curveBase = "bits = 4096\n", "c = ec.SECP521R1()\n"

	cases := make([]pythonKeyLengthCase, 0, 64)
	cases = append(cases, []pythonKeyLengthCase{
		{"int constant", intBase, useRSA, rsaUse, rsaAPI, 1, 4096},
		{"curve constant", curveBase, useRSA, ecUse, ecAPI, 0, 521},
		{"same literal bound twice", intBase + "bits = 4096\n", useRSA, rsaUse, rsaAPI, 1, 4096},
		{"same literal in both branches", "if os.name:\n    bits = 4096\nelse:\n    bits = 4096\n", useRSA, rsaUse, rsaAPI, 1, 4096},
		{"parameter of another function does not poison", intBase + "def other(bits):\n    return bits\n", useRSA, rsaUse, rsaAPI, 1, 4096},
		{"comprehension target does not poison", intBase + "squares = [bits for bits in range(3)]\n", useRSA, rsaUse, rsaAPI, 1, 4096},
		{"lambda parameter does not poison", intBase + "ident = lambda bits: bits\n", useRSA, rsaUse, rsaAPI, 1, 4096},
		{"local of another function does not poison", intBase + "def other():\n    bits = 1\n    return bits\n", useRSA, rsaUse, rsaAPI, 1, 4096},
	}...)
	type binder struct{ name, code, curveCode string }
	for _, b := range []binder{
		{"reassignment", "bits = 1024\n", "c = ec.SECP256R1()\n"},
		{"reassignment to a computed value", "bits = int(os.name)\n", "c = os.name\n"},
		{"if-branch rebind", "if os.name:\n    bits = 1024\n", "if os.name:\n    c = ec.SECP256R1()\n"},
		{"for target", "for bits in range(3):\n    pass\n", "for c in range(3):\n    pass\n"},
		{"with target", "with open('x') as bits:\n    pass\n", "with open('x') as c:\n    pass\n"},
		{"del", "del bits\n", "del c\n"},
		{"augmented assignment", "bits += 1\n", "c += 1\n"},
		{"tuple unpacking", "bits, other = 1, 2\n", "c, other = 1, 2\n"},
		{"starred unpacking", "*bits, last = [1, 2]\n", "*c, last = [1, 2]\n"},
		{"def", "def bits():\n    pass\n", "def c():\n    pass\n"},
		{"class", "class bits:\n    pass\n", "class c:\n    pass\n"},
		{"match capture", "match os.name:\n    case bits:\n        pass\n", "match os.name:\n    case c:\n        pass\n"},
		{"import as", "import os as bits\n", "import os as c\n"},
		{"from import as", "from os import name as bits\n", "from os import name as c\n"},
		{"walrus", "if (bits := 1) > 0:\n    pass\n", "if (c := 1) > 0:\n    pass\n"},
		{"except target", "try:\n    pass\nexcept Exception as bits:\n    pass\n", "try:\n    pass\nexcept Exception as c:\n    pass\n"},
		{"annotation without a value", "bits: int\n", "c: int\n"},
		{"global rebinding in a function", "def setter():\n    global bits\n    bits = 1024\n", "def setter():\n    global c\n    c = ec.SECP256R1()\n"},
		{"global declaration in a method", "class K:\n    def setter(self):\n        global bits\n        bits = 1024\n", "class K:\n    def setter(self):\n        global c\n        c = ec.SECP256R1()\n"},
	} {
		cases = append(cases,
			pythonKeyLengthCase{"int after " + b.name, intBase + b.code, useRSA, rsaUse, rsaAPI, 1, 0},
			pythonKeyLengthCase{"curve after " + b.name, curveBase + b.curveCode, useRSA, ecUse, ecAPI, 0, 0},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkPythonKeyLengthCase(t, header, c) })
	}
}
