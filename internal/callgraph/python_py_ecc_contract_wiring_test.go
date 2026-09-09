// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// py-ecc's contract keys are the one thing in this family that CANNOT be
// reasoned about from the library's source layout: the Python call-graph key is
// the CONSUMER'S LITERAL MODULE PATH, so a symbol reachable by two import paths
// produces two different keys and neither resolves the other.
//
// WHY THIS FILE EXISTS. The contract file used to assert the opposite — that
// "the graph keys BOTH import spellings" on the shallow module — and said so was
// "asserted in the wiring test". There was no wiring test. The only test that
// looked like one, `KeysMeasuredOffTheGraph` in
// internal/callgraph/contracts/python_py_ecc_test.go, called
// `ContractsForTolerant` with a hand-typed key and touched no graph at all, so
// it was green while eleven deep-module spellings — matched by eleven rule arms
// — joined nothing. Both halves of that mistake are repaired; this file is the
// half that reads keys off a real graph, built with the full builder so that
// contract-driven propagation runs.
//
// EVERY EXPECTATION BELOW WAS READ OFF THE BUILDER, NOT WRITTEN FROM THE API.
// The reference measurement, on crypto-finder built from this worktree:
//
//	from py_ecc.secp256k1        import ecdsa_raw_sign
//	  -> py_ecc.secp256k1.ecdsa_raw_sign(builtins.bytes, builtins.bytes)
//	from py_ecc.secp256k1.secp256k1 import ecdsa_raw_sign
//	  -> py_ecc.secp256k1.secp256k1.ecdsa_raw_sign(?, ?)     <- before the fix
//
// `name(?, ?)` with empty parameter_types is the ABSENT-CONTRACT rendering.

const pyEccWiringLibrary = "py-ecc"

// pyEccTwoSpellingSurface is the part of py-ecc's contract that has a
// TWO-SPELLING story: one key for the re-export path a consumer usually writes,
// one for the defining module that also occurs in real code. It is scoped
// deliberately and the scope is the claim — this is not "every py-ecc entry".
// The exact-set closure over the whole contract lives in
// internal/callgraph/contracts/python_py_ecc_test.go against a hand-written API
// table; what THIS test owns is the keying, which only a graph can answer.
//
// role is asserted alongside the key because a key that resolves to the wrong
// role is a silent metadata defect rather than a missing finding.
var pyEccTwoSpellingSurface = map[string]string{
	// ── curve flavors: re-export path ──
	"py_ecc.bn128.pairing":                          "operation",
	"py_ecc.bn128.final_exponentiate":               "operation",
	"py_ecc.optimized_bn128.pairing":                "operation",
	"py_ecc.optimized_bn128.final_exponentiate":     "operation",
	"py_ecc.bls12_381.pairing":                      "operation",
	"py_ecc.bls12_381.final_exponentiate":           "operation",
	"py_ecc.optimized_bls12_381.pairing":            "operation",
	"py_ecc.optimized_bls12_381.final_exponentiate": "operation",

	// ── curve flavors: defining module. THE ELEVEN KEYS THAT JOINED NOTHING. ──
	"py_ecc.bn128.bn128_pairing.pairing":                              "operation",
	"py_ecc.bn128.bn128_pairing.final_exponentiate":                   "operation",
	"py_ecc.optimized_bn128.optimized_pairing.pairing":                "operation",
	"py_ecc.optimized_bn128.optimized_pairing.final_exponentiate":     "operation",
	"py_ecc.bls12_381.bls12_381_pairing.pairing":                      "operation",
	"py_ecc.bls12_381.bls12_381_pairing.final_exponentiate":           "operation",
	"py_ecc.optimized_bls12_381.optimized_pairing.pairing":            "operation",
	"py_ecc.optimized_bls12_381.optimized_pairing.final_exponentiate": "operation",

	// ── secp256k1: re-export path and defining module ──
	"py_ecc.secp256k1.ecdsa_raw_sign":              "operation",
	"py_ecc.secp256k1.ecdsa_raw_recover":           "operation",
	"py_ecc.secp256k1.privtopub":                   "factory",
	"py_ecc.secp256k1.secp256k1.ecdsa_raw_sign":    "operation",
	"py_ecc.secp256k1.secp256k1.ecdsa_raw_recover": "operation",
	"py_ecc.secp256k1.secp256k1.privtopub":         "factory",

	// ── the ciphersuite classes, the case that was already handled correctly
	//    and is kept here as the control: if the two-spelling machinery broke
	//    generally, these would move too.
	"py_ecc.bls.G2ProofOfPossession.Sign":              "operation",
	"py_ecc.bls.ciphersuites.G2ProofOfPossession.Sign": "operation",
}

// pyEccWiringSources drives every key above through the builder. The deep paths
// are imported UNALIASED, one flavor per file, so that the module path is the
// only thing under test — four flavors exporting byte-identical names cannot be
// imported unaliased into one file, and mixing in an alias here would confuse
// the keying question with the aliasing question (which has its own test below).
var pyEccWiringSources = map[string]string{
	"deep_bn128.py": `
from py_ecc.bn128.bn128_pairing import final_exponentiate, pairing


def deep_bn128(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"deep_optimized_bn128.py": `
from py_ecc.optimized_bn128.optimized_pairing import final_exponentiate, pairing


def deep_optimized_bn128(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"deep_bls12_381.py": `
from py_ecc.bls12_381.bls12_381_pairing import final_exponentiate, pairing


def deep_bls12_381(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"deep_optimized_bls12_381.py": `
from py_ecc.optimized_bls12_381.optimized_pairing import final_exponentiate, pairing


def deep_optimized_bls12_381(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"deep_secp256k1.py": `
from py_ecc.secp256k1.secp256k1 import ecdsa_raw_recover, ecdsa_raw_sign, privtopub


def deep_secp256k1(msghash, priv, vrs):
    return privtopub(priv), ecdsa_raw_sign(msghash, priv), ecdsa_raw_recover(msghash, vrs)
`,
	// ONE FILE PER FLAVOR, UNALIASED, for the shallow re-export path too. The
	// four flavors export byte-identical names, so a single file would have to
	// alias — and this test must NOT depend on how an aliased from-import is
	// keyed, because that is a different question owned by a different change.
	// Keeping every import here unaliased is what makes this test a measurement
	// of the MODULE PATH alone.
	"shallow_bn128.py": `
from py_ecc.bn128 import final_exponentiate, pairing


def shallow_bn128(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"shallow_optimized_bn128.py": `
from py_ecc.optimized_bn128 import final_exponentiate, pairing


def shallow_optimized_bn128(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"shallow_bls12_381.py": `
from py_ecc.bls12_381 import final_exponentiate, pairing


def shallow_bls12_381(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"shallow_optimized_bls12_381.py": `
from py_ecc.optimized_bls12_381 import final_exponentiate, pairing


def shallow_optimized_bls12_381(g1, g2):
    a = pairing(g2, g1)
    return a, final_exponentiate(a)
`,
	"shallow_secp256k1.py": `
from py_ecc.secp256k1 import ecdsa_raw_recover, ecdsa_raw_sign, privtopub


def shallow_secp256k1(msghash, priv, vrs):
    return privtopub(priv), ecdsa_raw_sign(msghash, priv), ecdsa_raw_recover(msghash, vrs)
`,
	"ciphersuite_shallow.py": `
from py_ecc.bls import G2ProofOfPossession


def ciphersuite_shallow(sk, message):
    return G2ProofOfPossession.Sign(sk, message)
`,
	"ciphersuite_deep.py": `
from py_ecc.bls.ciphersuites import G2ProofOfPossession


def ciphersuite_deep(sk, message):
    return G2ProofOfPossession.Sign(sk, message)
`,
}

// TestPythonPyEccGraphEmitsBothImportSpellings is the assertion the contract
// file's header used to claim existed. It builds a graph from consumer source,
// reads the callee keys OFF THE GRAPH, and requires that every key in the
// two-spelling surface both (a) is actually emitted by a real import and (b)
// resolves to a py-ecc contract with the expected role.
//
// It fails if the keys regress in either direction: a parser change that
// collapsed the deep path onto the shallow one would leave the deep keys
// unemitted (caught by the coverage loop), and a contract change that dropped
// an entry would leave an emitted key unresolved (caught by the join).
func TestPythonPyEccGraphEmitsBothImportSpellings(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	graph, err := buildPythonGraph(t, pyEccWiringSources, "consumer")
	if err != nil {
		t.Fatalf("buildPythonGraph: %v", err)
	}
	if graph == nil {
		t.Fatal("buildPythonGraph returned a nil graph")
	}

	seen := map[string]bool{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)
			wantRole, tracked := pyEccTwoSpellingSurface[method]
			if !tracked {
				continue
			}
			arity := len(fn.Calls[i].Arguments)
			got := kb.ContractsFor(method, arity)
			if len(got) == 0 {
				t.Errorf("the graph emits %q at arity %d and NO contract resolves it. "+
					"This is the exact defect this file was added for: a rule arm can "+
					"match the call site while the callgraph key joins nothing, and the "+
					"finding then carries no inferred types.", method, arity)
				continue
			}
			if got[0].SourceLibrary != pyEccWiringLibrary {
				t.Errorf("%s#%d resolved to library %q, want %q",
					method, arity, got[0].SourceLibrary, pyEccWiringLibrary)
			}
			if got[0].Role != wantRole {
				t.Errorf("%s#%d has role %q, want %q", method, arity, got[0].Role, wantRole)
			}
			seen[method] = true
		}
	}

	var missing []string
	for method := range pyEccTwoSpellingSurface {
		if !seen[method] {
			missing = append(missing, method)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the consumer sources in this file did not produce these keys: %v\n"+
			"Either the parser stopped keying that import spelling — which is the "+
			"regression this test exists to catch — or a source above was edited "+
			"without keeping the surface map in step. Add the call, do not shrink "+
			"the map.", missing)
	}
}

// TestPythonPyEccCrossVariantAliasJoinsEndToEnd is the pin the alias fix was
// missing.
//
// IT DEPENDS ON A PARSER FIX THIS BRANCH DOES NOT CONTAIN. The
// aliased-from-import keying landed on main with `pypi:eth-hash`, and this test
// is the END-TO-END half nothing else covers: main's
// `python_parser_alias_key_test.go` asserts the key the PARSER emits, while this
// asserts that the key a real graph emits is one the CONTRACT can actually join,
// with the right per-curve return type. Those are different claims, and only the
// second is a statement about this contract.
//
// py-ecc is the family that forces the case: its four curve modules export
// byte-identical names over two different curves, so a consumer using two of
// them MUST alias at least one, and the curve is carried ONLY by the module
// path. Before the parser fix each of these four calls emitted
// `py_ecc.<flavor>.<the consumer's alias>` and joined nothing, so the four
// findings carried no inferred types and the two curves were indistinguishable. With `git revert --no-commit f51a15e` applied, the only failures in
// the whole callgraph tree were the five tests in
// python_from_import_alias_test.go — every one of which asserts on the PARSER's
// callee key. The 86-entry contract test passed. So nothing connected the two:
// nothing asserted that the key the parser now emits is a key the CONTRACT can
// actually join, which is the entire justification for the fix.
//
// This is the case that makes it load-bearing rather than cosmetic. py-ecc's
// four curve flavors export BYTE-IDENTICAL names over two different curves, so
// a consumer using two flavors in one file MUST alias at least one, and the
// curve is carried ONLY by the module path. Before the fix each of these emitted
// `py_ecc.<flavor>.<the consumer's alias>` and joined nothing; the four calls
// below therefore produced four findings with no inferred types and no way to
// tell the two curves apart.
func TestPythonPyEccCrossVariantAliasJoinsEndToEnd(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	graph, err := buildPythonGraph(t, map[string]string{"app.py": `
from py_ecc.bn128 import pairing as bn_pairing
from py_ecc.bls12_381 import pairing as bls_pairing
from py_ecc.optimized_bn128 import pairing as opt_bn_pairing
from py_ecc.optimized_bls12_381 import pairing as opt_bls_pairing


def cross_variant(g1, g2):
    return (
        bn_pairing(g2, g1),
        bls_pairing(g2, g1),
        opt_bn_pairing(g2, g1),
        opt_bls_pairing(g2, g1),
    )
`}, "consumer")
	if err != nil {
		t.Fatalf("buildPythonGraph: %v", err)
	}

	// The RETURN TYPE is asserted, not just the fact of a join, because it is
	// the field that distinguishes the two curves. Two flavors joining the same
	// contract would be a wrong-curve defect that a mere "it resolved" check
	// cannot see.
	want := map[string]string{
		"py_ecc.bn128.pairing":               "py_ecc.fields.bn128_FQ12",
		"py_ecc.bls12_381.pairing":           "py_ecc.fields.bls12_381_FQ12",
		"py_ecc.optimized_bn128.pairing":     "py_ecc.fields.optimized_bn128_FQ12",
		"py_ecc.optimized_bls12_381.pairing": "py_ecc.fields.optimized_bls12_381_FQ12",
	}

	seen := map[string]bool{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)

			// The alias must not survive into the key at all. Asserting only on
			// the positive keys would stay green if the parser emitted BOTH.
			for _, alias := range []string{"bn_pairing", "bls_pairing", "opt_bn_pairing", "opt_bls_pairing"} {
				for _, mod := range []string{"py_ecc.bn128", "py_ecc.bls12_381", "py_ecc.optimized_bn128", "py_ecc.optimized_bls12_381"} {
					if method == mod+"."+alias {
						t.Errorf("callee %q is keyed on the consumer's alias; no contract "+
							"can ever join it", method)
					}
				}
			}

			wantReturn, tracked := want[method]
			if !tracked {
				continue
			}
			got := kb.ContractsFor(method, len(fn.Calls[i].Arguments))
			if len(got) == 0 {
				t.Errorf("%s emitted by the graph but joins no contract — the alias fix "+
					"is not reaching the KB", method)
				continue
			}
			if got[0].SourceLibrary != pyEccWiringLibrary {
				t.Errorf("%s resolved to %q, want %q", method, got[0].SourceLibrary, pyEccWiringLibrary)
			}
			if got[0].Return.Type != wantReturn {
				t.Errorf("%s returns %q, want %q — the curve is carried by this field",
					method, got[0].Return.Type, wantReturn)
			}
			seen[method] = true
		}
	}
	for method := range want {
		if !seen[method] {
			t.Errorf("the cross-variant consumer did not produce %q; got none. This is "+
				"the join the alias fix exists to enable.", method)
		}
	}
}

// THE TWO PARSER-BEHAVIOR PINS THAT USED TO LIVE HERE WERE MOVED OUT, and the
// reason is ownership rather than a change of mind about the measurements.
//
// This branch originally carried a fix keying an aliased Python `from X import Y
// as Z` on the exported name `Y`, and two tests pinning its edges: an
// over-propagation (a `def` or `class` statement never shadows an imported name,
// at module OR function scope, while a local assignment, a lambda binding and a
// parameter all shadow correctly) and an inert alias-case asymmetry (the
// module-side NAME is recovered in both directions, but the
// constructor-vs-function KIND still follows the alias's capitalization, so an
// upper-cased alias of a free function keeps a spurious `.<init>`).
//
// `pypi:eth-hash` fixes the SAME defect in the same two files under
// `PythonFromImportOriginals`, and its fix strictly subsumes the one that was
// here — measured in both directions on isolated worktrees. So the shared parser
// and both of those pins belong to that change, which merges first; the
// measurements were handed over to be folded in and attributed there. Pinning
// them from a py-ecc contract test would assert a second family's behavior from
// the wrong file and would have to be deleted on the rebase.
//
// WHAT STAYS HERE is what is genuinely py-ecc's: the deep-module contract keys
// and the graph-level assertion that the two import spellings are distinct keys
// (above), which is parser-independent by construction — every import in that
// fixture is unaliased — plus the cross-variant join below, which is a statement
// about THIS contract's per-curve return types.
