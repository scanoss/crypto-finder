// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// fastecdsa is ECDSA over prime-field curves with the curve and the digest
// supplied BY THE CALLER, over two C extensions. Its contract has one property
// that decides the shape of this whole file: THE ARITY SET, not the key set, is
// where a mistake hides. `fastecdsa/__init__.py` is empty in all 46 published
// sdists, so every symbol has exactly ONE module path and there is no
// two-spelling story of the kind py-ecc has; but a python keyword argument
// occupies an arity slot, so `sign(msg, d, curve=P256, hashfunc=sha256)` emits
// arity 4, and real consumers write `sign` at 2, 3 and 4 and `verify` at 3, 4
// and 5, including all-keyword calls. A missing arity does NOT fail loudly:
// `ContractsForTolerant`'s name-only fallback resolves it carrying another
// entry's parameter_types and confidence, which reads as a successful join.
//
// THIS IS AN EXACT-SET COMPARISON REPORTED AS A SYMMETRIC DIFFERENCE. A per-key
// subset assertion cannot see an entry that should not be there, an entry that
// was dropped, or a field that was corrupted. And a comparison reported as
// `len(got) != len(want)` plus an index-by-index diff turns ONE legitimate
// addition into a cascade of off-by-one errors, which is the most repeated
// defect on this campaign -- five families, four ecosystems. This one names
// what is MISSING and what is UNEXPECTED and quotes the exact literal to paste.
//
// THE EXPECTATION IS SOURCED FROM THE LIBRARY, NOT FROM THE YAML. `fastecdsaAPI`
// below is a hand-written table of fastecdsa's own declarations with a `src`
// citation per row, read from the extracted sdists; the arity expansion is
// written out per row rather than generated, because the legal arity set is a
// fact about each signature's defaults. Deriving the expectation from the
// contract file would make this assertion tautological and green on a corrupted
// contract, which is the one thing it exists to prevent.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE IS
// TRUE. Every row's `src` citation is the baseline's own evidence, and each was
// resolved against the extracted archive by a script rather than typed from
// memory -- one of them was WRONG on the first pass (`keys.py:126` pointed into
// a docstring; the declaration is at :130) and was corrected rather than
// shipped. Vacuity and truth are separate gates.

const fastecdsaLibrary = "fastecdsa"

// fastecdsaEntry is one declaration read from fastecdsa's own source.
type fastecdsaEntry struct {
	method     string
	arity      int
	role       string
	returnType string
	confidence string
	params     []string
	src        string // version file:line in the archive it was read from
}

const (
	feCurve   = "fastecdsa.curve.Curve"
	fePoint   = "fastecdsa.point.Point"
	feEncoder = "fastecdsa.encoding.KeyEncoder"
	// `SignableMessage = Union[str, bytes, bytearray]` (3.0.1 typing.py:4) is a
	// genuine union and BOTH branches occur in real consumer code -- didery
	// passes `msg.decode()`, a str. `bytes` is declared as the byte-oriented
	// branch the API is built around; the union is stated here rather than in a
	// comment nobody reads next to a confident-looking type.
	feMsg  = "builtins.bytes"
	feFunc = "builtins.function"
)

// fastecdsaAPI: every declaration this contract covers, at every arity the
// signature permits, read from the sdists.
var fastecdsaAPI = []fastecdsaEntry{
	// ── fastecdsa.ecdsa ──────────────────────────────────────────────────────
	// `sign(msg, d, curve=P256, hashfunc=sha256, prehashed=False)`.
	// `prehashed` arrives at 1.7.2, which is what makes arity 5 legal; arities
	// 2-4 are legal from 1.1.0, the first release with a module-level `sign`.
	{
		"fastecdsa.ecdsa.sign", 2, "operation", "builtins.tuple", "high",
		[]string{feMsg, "builtins.int"},
		"3.0.1 fastecdsa/ecdsa.py:16",
	},
	{
		"fastecdsa.ecdsa.sign", 3, "operation", "builtins.tuple", "high",
		[]string{feMsg, "builtins.int", feCurve},
		"3.0.1 fastecdsa/ecdsa.py:16",
	},
	{
		"fastecdsa.ecdsa.sign", 4, "operation", "builtins.tuple", "high",
		[]string{feMsg, "builtins.int", feCurve, feFunc},
		"3.0.1 fastecdsa/ecdsa.py:16",
	},
	{
		"fastecdsa.ecdsa.sign", 5, "operation", "builtins.tuple", "high",
		[]string{feMsg, "builtins.int", feCurve, feFunc, "builtins.bool"},
		"3.0.1 fastecdsa/ecdsa.py:16",
	},

	// `verify(sig, msg, Q, curve=P256, hashfunc=sha256, prehashed=False)`.
	// `prehashed` reaches `verify` only at 2.1.4 -- LATER than it reaches
	// `sign` (1.7.2) -- which is why the two functions have different top
	// arities and why they are listed separately rather than expanded from one
	// shape.
	{
		"fastecdsa.ecdsa.verify", 3, "operation", "builtins.bool", "high",
		[]string{"builtins.tuple", feMsg, fePoint},
		"3.0.1 fastecdsa/ecdsa.py:68",
	},
	{
		"fastecdsa.ecdsa.verify", 4, "operation", "builtins.bool", "high",
		[]string{"builtins.tuple", feMsg, fePoint, feCurve},
		"3.0.1 fastecdsa/ecdsa.py:68",
	},
	{
		"fastecdsa.ecdsa.verify", 5, "operation", "builtins.bool", "high",
		[]string{"builtins.tuple", feMsg, fePoint, feCurve, feFunc},
		"3.0.1 fastecdsa/ecdsa.py:68",
	},
	{
		"fastecdsa.ecdsa.verify", 6, "operation", "builtins.bool", "high",
		[]string{"builtins.tuple", feMsg, fePoint, feCurve, feFunc, "builtins.bool"},
		"3.0.1 fastecdsa/ecdsa.py:68",
	},

	// ── fastecdsa.keys ───────────────────────────────────────────────────────
	// `gen_keypair(curve) -> Tuple[int, Point]`. One arity only: the curve is
	// the sole parameter in every release 1.1.3 - 3.0.1.
	{
		"fastecdsa.keys.gen_keypair", 1, "factory", "builtins.tuple", "high",
		[]string{feCurve},
		"3.0.1 fastecdsa/keys.py:12",
	},

	// `gen_private_key(curve, randfunc=urandom) -> int`. `randfunc` arrives at
	// 1.7.0, so arity 2 is legal from there and arity 1 from 1.1.3.
	{
		"fastecdsa.keys.gen_private_key", 1, "factory", "builtins.int", "high",
		[]string{feCurve},
		"3.0.1 fastecdsa/keys.py:32",
	},
	{
		"fastecdsa.keys.gen_private_key", 2, "factory", "builtins.int", "high",
		[]string{feCurve, feFunc},
		"3.0.1 fastecdsa/keys.py:32",
	},

	// `get_public_key(d, curve) -> Point` is `return d * curve.G`
	// (3.0.1 keys.py:81) -- a derivation, so `factory` and not `operation`.
	// Both parameters are required in every release, so one arity.
	{
		"fastecdsa.keys.get_public_key", 2, "factory", fePoint, "high",
		[]string{"builtins.int", feCurve},
		"3.0.1 fastecdsa/keys.py:68",
	},

	// `get_public_keys_from_sig(sig, msg, curve, hashfunc) -> Tuple[Point, Point]`.
	// curve and hashfunc DEFAULT between 1.6.2 and 2.3.2 and become REQUIRED at
	// 3.0.0, so arities 2 and 3 are legal on the older line and 4 throughout.
	{
		"fastecdsa.keys.get_public_keys_from_sig", 2, "factory", "builtins.tuple", "high",
		[]string{"builtins.tuple", feMsg},
		"3.0.1 fastecdsa/keys.py:84",
	},
	{
		"fastecdsa.keys.get_public_keys_from_sig", 3, "factory", "builtins.tuple", "high",
		[]string{"builtins.tuple", feMsg, feCurve},
		"3.0.1 fastecdsa/keys.py:84",
	},
	{
		"fastecdsa.keys.get_public_keys_from_sig", 4, "factory", "builtins.tuple", "high",
		[]string{"builtins.tuple", feMsg, feCurve, feFunc},
		"3.0.1 fastecdsa/keys.py:84",
	},

	// `export_key(key, curve=None, filepath=None, encoder=PEMEncoder)`,
	// 1.6.2 - 2.3.2 ONLY: 3.0.0 removed it and split it in two. Returns the
	// encoded bytes when `filepath is None` and writes to disk returning None
	// otherwise (2.3.2 keys.py:143), so `bytes` is the useful half rather than
	// the whole truth -- declared `low` rather than asserted `high` or left
	// empty, since an empty canonical_return_type renders identically to no
	// contract at all.
	{
		"fastecdsa.keys.export_key", 1, "output", "builtins.bytes", "low",
		[]string{"builtins.int"},
		"2.3.2 fastecdsa/keys.py:119",
	},
	{
		"fastecdsa.keys.export_key", 2, "output", "builtins.bytes", "low",
		[]string{"builtins.int", feCurve},
		"2.3.2 fastecdsa/keys.py:119",
	},
	{
		"fastecdsa.keys.export_key", 3, "output", "builtins.bytes", "low",
		[]string{"builtins.int", feCurve, "builtins.str"},
		"2.3.2 fastecdsa/keys.py:119",
	},
	{
		"fastecdsa.keys.export_key", 4, "output", "builtins.bytes", "low",
		[]string{"builtins.int", feCurve, "builtins.str", feEncoder},
		"2.3.2 fastecdsa/keys.py:119",
	},

	// `import_key(filepath, curve=None, public=False, decoder=PEMEncoder)
	//  -> Tuple[Optional[int], Point]`, 1.6.2 - 2.3.2 ONLY. The TUPLE is
	// certain even though its first member may be None, so `high` is exact
	// here; it is the 3.0.0 split that resolves the private-versus-public
	// ambiguity, and those two entries carry concrete types.
	{
		"fastecdsa.keys.import_key", 1, "factory", "builtins.tuple", "high",
		[]string{"builtins.str"},
		"2.3.2 fastecdsa/keys.py:152",
	},
	{
		"fastecdsa.keys.import_key", 2, "factory", "builtins.tuple", "high",
		[]string{"builtins.str", feCurve},
		"2.3.2 fastecdsa/keys.py:152",
	},
	{
		"fastecdsa.keys.import_key", 3, "factory", "builtins.tuple", "high",
		[]string{"builtins.str", feCurve, "builtins.bool"},
		"2.3.2 fastecdsa/keys.py:152",
	},
	{
		"fastecdsa.keys.import_key", 4, "factory", "builtins.tuple", "high",
		[]string{"builtins.str", feCurve, "builtins.bool", feEncoder},
		"2.3.2 fastecdsa/keys.py:152",
	},

	// The 3.0.0 split. `export_*` are Optional[bytes] for the same reason as
	// `export_key`; `import_*` have concrete returns.
	{
		"fastecdsa.keys.export_private_key", 3, "output", "builtins.bytes", "low",
		[]string{"builtins.int", feCurve, feEncoder},
		"3.0.1 fastecdsa/keys.py:122",
	},
	{
		"fastecdsa.keys.export_private_key", 4, "output", "builtins.bytes", "low",
		[]string{"builtins.int", feCurve, feEncoder, "builtins.str"},
		"3.0.1 fastecdsa/keys.py:122",
	},
	{
		"fastecdsa.keys.export_public_key", 2, "output", "builtins.bytes", "low",
		[]string{fePoint, feEncoder},
		"3.0.1 fastecdsa/keys.py:156",
	},
	{
		"fastecdsa.keys.export_public_key", 3, "output", "builtins.bytes", "low",
		[]string{fePoint, feEncoder, "builtins.str"},
		"3.0.1 fastecdsa/keys.py:156",
	},
	{
		"fastecdsa.keys.import_private_key", 2, "factory", "builtins.int", "high",
		[]string{"builtins.str", feEncoder},
		"3.0.1 fastecdsa/keys.py:185",
	},
	{
		"fastecdsa.keys.import_public_key", 3, "factory", fePoint, "high",
		[]string{"builtins.str", feCurve, feEncoder},
		"3.0.1 fastecdsa/keys.py:204",
	},

	// ── fastecdsa.encoding ───────────────────────────────────────────────────
	// `SEC1Encoder.encode_public_key(point, compressed=True) -> bytes` and
	// `decode_public_key(key, curve) -> Point`. BOTH stay `@staticmethod` in all
	// 22 releases of the 1.7.0 - 3.0.1 window, which is what makes a
	// class-qualified key a valid call shape across the whole range -- the
	// PRIVATE-key methods of the same class became instance methods at 3.0.0.
	{
		"fastecdsa.encoding.sec1.SEC1Encoder.encode_public_key", 1, "output",
		"builtins.bytes", "high",
		[]string{fePoint},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.encoding.sec1.SEC1Encoder.encode_public_key", 2, "output",
		"builtins.bytes", "high",
		[]string{fePoint, "builtins.bool"},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.encoding.sec1.SEC1Encoder.decode_public_key", 2, "factory",
		fePoint, "high",
		[]string{"builtins.bytes", feCurve},
		"3.0.1 fastecdsa/encoding/sec1.py:37",
	},

	// `DEREncoder.encode_signature(r, s) -> bytes` and
	// `decode_signature(sig) -> Tuple[int, int]`. Both `@staticmethod`
	// throughout 1.7.0 - 3.0.1, both single-arity.
	{
		"fastecdsa.encoding.der.DEREncoder.encode_signature", 2, "output",
		"builtins.bytes", "high",
		[]string{"builtins.int", "builtins.int"},
		"3.0.1 fastecdsa/encoding/der.py:21",
	},
	{
		"fastecdsa.encoding.der.DEREncoder.decode_signature", 1, "factory",
		"builtins.tuple", "high",
		[]string{"builtins.bytes"},
		"3.0.1 fastecdsa/encoding/der.py:45",
	},

	// ── the two COLLAPSED spellings of each encoder method ───────────────────
	// These are not alternative names for the same key: they are DIFFERENT keys
	// the exporter actually emits, one per import spelling, measured with one
	// probe function each. `encoding` is this
	// package's only nested package and the only place the key varies.
	//
	//   from fastecdsa.encoding.sec1 import SEC1Encoder -> fastecdsa.encoding.sec1.SEC1Encoder.X
	//   from fastecdsa.encoding import sec1             -> fastecdsa.encoding.SEC1Encoder.X
	//   from fastecdsa import encoding                  -> fastecdsa.sec1.SEC1Encoder.X
	//
	// Each of the latter two rendered as `X(?)` -- the absent-contract form --
	// until it was declared, while the RULES matched all three spellings
	// perfectly well. That asymmetry is why this was found by exporting a graph
	// and could not have been found by any rules-side test.
	//
	// The src citations are the SAME declarations as the canonical spelling
	// above, because they are the same functions reached by a different import.
	{
		"fastecdsa.encoding.SEC1Encoder.encode_public_key", 1, "output",
		"builtins.bytes", "high",
		[]string{fePoint},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.encoding.SEC1Encoder.encode_public_key", 2, "output",
		"builtins.bytes", "high",
		[]string{fePoint, "builtins.bool"},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.sec1.SEC1Encoder.encode_public_key", 1, "output",
		"builtins.bytes", "high",
		[]string{fePoint},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.sec1.SEC1Encoder.encode_public_key", 2, "output",
		"builtins.bytes", "high",
		[]string{fePoint, "builtins.bool"},
		"3.0.1 fastecdsa/encoding/sec1.py:16",
	},
	{
		"fastecdsa.encoding.SEC1Encoder.decode_public_key", 2, "factory",
		fePoint, "high",
		[]string{"builtins.bytes", feCurve},
		"3.0.1 fastecdsa/encoding/sec1.py:37",
	},
	{
		"fastecdsa.sec1.SEC1Encoder.decode_public_key", 2, "factory",
		fePoint, "high",
		[]string{"builtins.bytes", feCurve},
		"3.0.1 fastecdsa/encoding/sec1.py:37",
	},
	{
		"fastecdsa.encoding.DEREncoder.encode_signature", 2, "output",
		"builtins.bytes", "high",
		[]string{"builtins.int", "builtins.int"},
		"3.0.1 fastecdsa/encoding/der.py:21",
	},
	{
		"fastecdsa.der.DEREncoder.encode_signature", 2, "output",
		"builtins.bytes", "high",
		[]string{"builtins.int", "builtins.int"},
		"3.0.1 fastecdsa/encoding/der.py:21",
	},
	{
		"fastecdsa.encoding.DEREncoder.decode_signature", 1, "factory",
		"builtins.tuple", "high",
		[]string{"builtins.bytes"},
		"3.0.1 fastecdsa/encoding/der.py:45",
	},
	{
		"fastecdsa.der.DEREncoder.decode_signature", 1, "factory",
		"builtins.tuple", "high",
		[]string{"builtins.bytes"},
		"3.0.1 fastecdsa/encoding/der.py:45",
	},
}

// render is the single documented projection of a contract into a comparable
// line. It carries parameter_types AND canonical_return_type AND role AND
// confidence, because corrupting any one of them leaves a
// method#arity-only comparison green -- measured twice on this campaign.
func renderFastecdsaContract(c contracts.Contract) string {
	return fmt.Sprintf("role=%s return=%s/%s canonical=%s params=[%s] varargs=%t",
		c.Role, c.Return.Type, c.Return.Confidence, c.CanonicalReturnType,
		strings.Join(c.ParameterTypes, ","), c.Varargs)
}

func fastecdsaKey(method string, arity int) string {
	return fmt.Sprintf("%s#%d", method, arity)
}

func fastecdsaWant() map[string]string {
	want := make(map[string]string, len(fastecdsaAPI))
	for _, e := range fastecdsaAPI {
		want[fastecdsaKey(e.method, e.arity)] = fmt.Sprintf(
			"role=%s return=%s/%s canonical=%s params=[%s] varargs=%t",
			e.role, e.returnType, e.confidence, e.returnType,
			strings.Join(e.params, ","), false)
	}
	return want
}

func loadedFastecdsaContracts(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("python", "fastecdsa.yaml"))
	if err != nil {
		t.Fatalf("read contract file: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := make(map[string]string)
	for _, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != fastecdsaLibrary {
				continue
			}
			key := fastecdsaKey(c.Method, c.Arity)
			if prev, dup := got[key]; dup && prev != renderFastecdsaContract(c) {
				t.Errorf("conflicting contract entries for %s\n  first:  %s\n  second: %s",
					key, prev, renderFastecdsaContract(c))
			}
			got[key] = renderFastecdsaContract(c)
		}
	}
	if len(got) == 0 {
		t.Fatal("no fastecdsa contracts loaded; this assertion would be vacuous")
	}
	return got
}

func TestPythonFastecdsaContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := fastecdsaWant()
	got := loadedFastecdsaContracts(t)

	var missing, unexpected, differing []string
	for key, wantLine := range want {
		gotLine, ok := got[key]
		if !ok {
			missing = append(missing, fmt.Sprintf(
				"  MISSING contract entry %s -- the API table read from fastecdsa's "+
					"own sources says it exists at that arity; if it does not, remove "+
					"its row from fastecdsaAPI and say why. Expected line:\n    %s",
				key, wantLine))
			continue
		}
		if gotLine != wantLine {
			differing = append(differing, fmt.Sprintf(
				"  DIFFERS %s\n    loaded: %s\n    wanted: %s", key, gotLine, wantLine))
		}
	}
	for key, gotLine := range got {
		if _, ok := want[key]; !ok {
			unexpected = append(unexpected, fmt.Sprintf(
				"  UNEXPECTED contract entry %s -- if the YAML change is intended, add "+
					"the corresponding row to fastecdsaAPI, sourced from fastecdsa's OWN "+
					"files with a src citation. Loaded line, for reference:\n    %s",
				key, gotLine))
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	sort.Strings(differing)

	if len(missing)+len(unexpected)+len(differing) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "fastecdsa contract set does not match the API table read "+
			"from fastecdsa's own sources (%d loaded, %d expected)\n", len(got), len(want))
		for _, l := range missing {
			b.WriteString(l + "\n")
		}
		for _, l := range unexpected {
			b.WriteString(l + "\n")
		}
		for _, l := range differing {
			b.WriteString(l + "\n")
		}
		t.Error(b.String())
	}
}

// TestPythonFastecdsaContract_LibraryBlock renders the `library:` block, which
// the exact-set test cannot see. Measured twice on this campaign: corrupting
// `version_range`, `coordinates`, `name` or `description` leaves every
// per-contract assertion green, because those fields are parsed and then never
// consulted by any other test.
func TestPythonFastecdsaContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "fastecdsa.yaml"))
	if err != nil {
		t.Fatalf("read contract file: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if kb.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want %q", kb.Ecosystem, "python")
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want %q", kb.SchemaVersion, "2")
	}
	if kb.Library == nil {
		t.Fatal("library block absent")
	}
	if kb.Library.Name != fastecdsaLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, fastecdsaLibrary)
	}
	// The import name and the distribution name coincide for this package --
	// unlike py-ecc, whose distribution is `py-ecc` and whose import is
	// `py_ecc`. The coordinate is the IMPORT name, because that is what the
	// call-graph key is built from.
	if got, want := strings.Join(kb.Library.Coordinates, ","), "fastecdsa"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// THE LOWER BOUND IS 1.1.0, NOT THE FIRST PUBLISHED RELEASE, and that is a
	// deliberate statement about coverage rather than an oversight. 1.0.0b1 -
	// 1.0.3 (7 of the 46 rows in the committed CSV) have no module-level `sign`
	// at all: the whole API is `ecdsa.KeyPair(curve)` with `sign`/`verify`
	// methods (1.0.0b1 ecdsa.py:11), and that era is python 2 only --
	// 1.0.0b1 ecdsa.py:6 is `from util import RFC6979`, an implicit relative
	// import that is a SyntaxError under python 3. No key declared here is
	// reachable in those seven releases.
	if got, want := kb.Library.VersionRange, ">=1.1.0,<4"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if !strings.Contains(kb.Library.Description, "prime-field") {
		t.Errorf("library.description does not describe the curve family: %q",
			kb.Library.Description)
	}
}

// TestPythonFastecdsaContract_ArithmeticAndCExtensionAreNotContracted pins the
// NEGATIVE surface. The rules and the contract have to agree about what is not
// crypto, and nothing else checks that they do: the rule files state these as
// skipped-non-crypto and this asserts the contract makes the same choice.
func TestPythonFastecdsaContract_ArithmeticAndCExtensionAreNotContracted(t *testing.T) {
	t.Parallel()

	got := loadedFastecdsaContracts(t)
	declared := make(map[string]bool, len(got))
	for key := range got {
		declared[strings.SplitN(key, "#", 2)[0]] = true
	}

	// Each of these is real, present and reachable in the published releases,
	// and each is deliberately NOT contracted. The reason is in the rule
	// headers; the point of asserting it here is that a later edit cannot
	// quietly add one and leave the two documents disagreeing.
	forbidden := map[string]string{
		"fastecdsa._ecdsa.sign":                "C extension primitive; ecdsa.sign calls it itself (3.0.1 ecdsa.py:54)",
		"fastecdsa._ecdsa.verify":              "C extension primitive",
		"fastecdsa.curvemath.mul":              "C extension group arithmetic",
		"fastecdsa.curvemath.add":              "C extension group arithmetic",
		"fastecdsa.point.Point":                "point construction; the class has no public named method",
		"fastecdsa.util.RFC6979":               "nonce derivation inside sign (3.0.1 ecdsa.py:39)",
		"fastecdsa.util.mod_sqrt":              "field arithmetic",
		"fastecdsa.curve.Curve":                "fixed public curve parameters",
		"fastecdsa.ecdsa.KeyPair":              "the python-2-only 1.0.x era, 7 of 46 rows",
		"fastecdsa.keys.encode_keypair":        "1.4.3 - 1.6.1 predecessor of export_key, 4 of 46 rows",
		"fastecdsa.keys.encode_public_key":     "1.4.3 - 1.6.1 predecessor of export_key, 4 of 46 rows",
		"fastecdsa.encoding.util.bytes_to_int": "byte plumbing",
	}
	for method, why := range forbidden {
		if declared[method] {
			t.Errorf("%s is contracted, but the rule headers state it as a "+
				"non-claim (%s). Either contract it AND claim it in the rules, or "+
				"neither.", method, why)
		}
	}
}

// TestPythonFastecdsaContract_EveryDeclaredArityIsLegal cross-checks the arity
// sets against each signature's parameter count, which is the field this
// family's contract is most likely to get wrong.
//
// The bound per method is (required + optional) parameters, and the floor is
// the required count. A declared arity outside that window would match a call
// that cannot be written.
func TestPythonFastecdsaContract_EveryDeclaredArityIsLegal(t *testing.T) {
	t.Parallel()

	// method -> {min legal arity, max legal arity}, from the signatures at the
	// version each was read at. Cited in fastecdsaAPI above.
	window := map[string][2]int{
		"fastecdsa.ecdsa.sign":                                  {2, 5},
		"fastecdsa.ecdsa.verify":                                {3, 6},
		"fastecdsa.keys.gen_keypair":                            {1, 1},
		"fastecdsa.keys.gen_private_key":                        {1, 2},
		"fastecdsa.keys.get_public_key":                         {2, 2},
		"fastecdsa.keys.get_public_keys_from_sig":               {2, 4},
		"fastecdsa.keys.export_key":                             {1, 4},
		"fastecdsa.keys.import_key":                             {1, 4},
		"fastecdsa.keys.export_private_key":                     {3, 4},
		"fastecdsa.keys.export_public_key":                      {2, 3},
		"fastecdsa.keys.import_private_key":                     {2, 2},
		"fastecdsa.keys.import_public_key":                      {3, 3},
		"fastecdsa.encoding.sec1.SEC1Encoder.encode_public_key": {1, 2},
		"fastecdsa.encoding.sec1.SEC1Encoder.decode_public_key": {2, 2},
		"fastecdsa.encoding.der.DEREncoder.encode_signature":    {2, 2},
		"fastecdsa.encoding.der.DEREncoder.decode_signature":    {1, 1},
		// the collapsed spellings, same signatures
		"fastecdsa.encoding.SEC1Encoder.encode_public_key": {1, 2},
		"fastecdsa.sec1.SEC1Encoder.encode_public_key":     {1, 2},
		"fastecdsa.encoding.SEC1Encoder.decode_public_key": {2, 2},
		"fastecdsa.sec1.SEC1Encoder.decode_public_key":     {2, 2},
		"fastecdsa.encoding.DEREncoder.encode_signature":   {2, 2},
		"fastecdsa.der.DEREncoder.encode_signature":        {2, 2},
		"fastecdsa.encoding.DEREncoder.decode_signature":   {1, 1},
		"fastecdsa.der.DEREncoder.decode_signature":        {1, 1},
	}

	data, err := os.ReadFile(filepath.Join("python", "fastecdsa.yaml"))
	if err != nil {
		t.Fatalf("read contract file: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	seen := map[string]map[int]bool{}
	for _, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != fastecdsaLibrary {
				continue
			}
			w, ok := window[c.Method]
			if !ok {
				t.Errorf("%s is contracted but has no arity window in this test; add "+
					"one from its signature", c.Method)
				continue
			}
			if c.Arity < w[0] || c.Arity > w[1] {
				t.Errorf("%s arity %d is outside the legal window [%d,%d] for its "+
					"signature -- it would match a call that cannot be written",
					c.Method, c.Arity, w[0], w[1])
			}
			if seen[c.Method] == nil {
				seen[c.Method] = map[int]bool{}
			}
			seen[c.Method][c.Arity] = true
			if len(c.ParameterTypes) != c.Arity {
				t.Errorf("%s#%d declares %d parameter_types", c.Method, c.Arity,
					len(c.ParameterTypes))
			}
		}
	}

	// EVERY legal arity must be declared, not merely the ones the corpus
	// happens to contain: a missing arity resolves through the name-only
	// fallback with another entry's parameter_types, which reads as a join.
	for method, w := range window {
		for arity := w[0]; arity <= w[1]; arity++ {
			if !seen[method][arity] {
				t.Errorf("%s has no entry at arity %d, which its signature permits; "+
					"a call at that arity resolves through ContractsForTolerant with "+
					"another entry's parameter_types", method, arity)
			}
		}
	}
}
