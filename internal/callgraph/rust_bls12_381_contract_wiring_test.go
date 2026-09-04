package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bls12_381 IS the BLS12-381 curve rather than a protocol built on it, and its
// keys are not guessable from the API. Three facts were read off an exported
// call graph rather than written from the source layout, and each one would
// silently resolve to nothing if it were assumed instead:
//
//   - the types are re-exported from the crate root, so their keys carry NO
//     module segment: `bls12_381.Scalar.random`, not `bls12_381::scalar.Scalar.random`;
//   - the crate-root free functions carry no owning type at all:
//     `bls12_381.pairing`, `bls12_381.multi_miller_loop`;
//   - HASH-TO-CURVE KEYS ON THE CONCRETE TYPE, NOT THE TRAIT THAT DEFINES IT.
//     A consumer writes `<G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(m, d)`
//     and the graph emits `bls12_381.G2Projective.hash_to_curve`. Declaring it
//     under `bls12_381::hash_to_curve::HashToCurve` resolves to nothing.
//
// WHAT THE CONTRACT FIXES: `multi_miller_loop(..).final_exponentiation()` had
// the chained call land in the CONSUMER's own package, because the free
// function's return was undeclared. That is the defect this test pins first.
func TestBls12381ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The FULL BUILDER, not the parser alone: contract-driven chain propagation
	// runs after the KB is loaded.
	dir := t.TempDir()
	src := `use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, pairing, Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};

fn app(rng: &mut R, prep: &G2Prepared, cb1: &[u8; 48], cb2: &[u8; 96], sb: &[u8; 32]) {
    let sk = Scalar::random(rng);
    let p = G1Projective::random(rng);
    let q = G2Projective::random(rng);

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let pg1 = G1Projective::generator();
    let pg2 = G2Projective::generator();

    let gt = pairing(&g1, &g2);
    let gt_engine = Bls12::pairing(&g1, &g2);
    let ml_engine = Bls12::multi_miller_loop(&[(&g1, prep)]);
    let gt_rand = Gt::random(rng);
    // CHAINED DIRECTLY, and that is not a stylistic choice. Measured on this
    // binary with the contract loaded: a free function's declared return
    // propagates through a direct chain but NOT into a local binding --
    // a local binding does not: binding it first still comes out as the
    // consumer's own final_exponentiation. Method returns DO flow into locals,
    // so the asymmetry is specific to crate-root free functions.
    let gt2 = multi_miller_loop(&[(&g1, prep)]).final_exponentiation();

    let h1 = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"m", b"d");
    let h2 = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"m", b"d");
    let e1 = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::encode_to_curve(b"m", b"d");
    let e2 = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::encode_to_curve(b"m", b"d");

    let c1 = g1.to_compressed();
    let c2 = g2.to_compressed();
    let d1 = G1Affine::from_compressed(cb1);
    let d2 = G2Affine::from_compressed(cb2);
    let raw = sk.to_bytes();
    let back = Scalar::from_bytes(sb);

    let _ = (sk, p, q, pg1, pg2, gt, gt2, h1, h2, e1, e2, c1, c2, d1, d2, raw, back);
    let _ = (gt_engine, ml_engine, gt_rand);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string]string{
		"bls12_381.pairing":                               "operation",
		"bls12_381.multi_miller_loop":                     "operation",
		"bls12_381.Bls12.pairing":                         "operation",
		"bls12_381.Bls12.multi_miller_loop":               "operation",
		"bls12_381.Gt.random":                             "factory",
		"bls12_381.MillerLoopResult.final_exponentiation": "operation",
		"bls12_381.Scalar.random":                         "factory",
		"bls12_381.G1Projective.random":                   "factory",
		"bls12_381.G2Projective.random":                   "factory",
		"bls12_381.G1Projective.hash_to_curve":            "operation",
		"bls12_381.G2Projective.hash_to_curve":            "operation",
		"bls12_381.G1Projective.encode_to_curve":          "operation",
		"bls12_381.G2Projective.encode_to_curve":          "operation",
		"bls12_381.G1Affine.generator":                    "factory",
		"bls12_381.G2Affine.generator":                    "factory",
		"bls12_381.G1Projective.generator":                "factory",
		"bls12_381.G2Projective.generator":                "factory",
		"bls12_381.G1Affine.to_compressed":                "output",
		"bls12_381.G2Affine.to_compressed":                "output",
		"bls12_381.G1Affine.from_compressed":              "factory",
		"bls12_381.G2Affine.from_compressed":              "factory",
		"bls12_381.Scalar.to_bytes":                       "output",
		"bls12_381.Scalar.from_bytes":                     "factory",
	}
	seen := map[string]bool{}

	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)
			role, ok := want[method]
			if !ok {
				continue
			}
			got := kb.ContractsFor(method, len(fn.Calls[i].Arguments))
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
					method, len(fn.Calls[i].Arguments), len(got))
			}
			if got[0].Role != role || got[0].SourceLibrary != "bls12_381" {
				t.Fatalf("contract for %q = %#v, want bls12_381 %s", method, got[0], role)
			}
			seen[method] = true
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}

	// EVERY declared entry has to be driven through the builder, not just the
	// interesting ones. A fixture that exercises a subset and leaves the rest to
	// the static check is how a missing entry stays invisible in both.
	declared := 0
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary == "bls12_381" {
				declared++
			}
		}
	}
	if declared != len(want) {
		t.Fatalf("the contract declares %d entries and this fixture drives %d; "+
			"add the call to the source above rather than shrinking the check",
			declared, len(want))
	}
}

// TestBls12381ContractIsTheSourcesSurface names every owner and every method
// with its arity, and CLOSES both sets in both directions.
//
// WHAT THIS MAP IS, precisely, because an imprecise claim here is how the
// previous family's version of this test went wrong: it is the crate's
// CRYPTO-RELEVANT SURFACE PLUS THE CHAIN LINKS NEEDED TO REACH IT, read from
// the sources and cited below to the file and line it was read from. It is NOT
// the crate's entire public API -- bls12_381 exposes hundreds of arithmetic and
// trait methods that no contract should type -- so the closing direction means
// "the contract declares nothing outside that scope", not "the crate does not
// have this method". `Gt::identity` is real (src/pairings.rs:250) and correctly
// absent from both.
//
// THIS MAP IS READ FROM THE SOURCES AND NOT MIRRORED FROM THE CONTRACT. That
// distinction is the whole point: a previous family in this campaign shipped a
// map copied from its own YAML, which was green AND rejected the repair when a
// real missing method was added. Every entry below is cited to the file it was
// read from at 0.8.0, so a future edit has somewhere to check.
//
//	src/pairings.rs:607  pub fn pairing(p: &G1Affine, q: &G2Affine) -> Gt
//	src/pairings.rs:554  pub fn multi_miller_loop(terms: &[(&G1Affine, &G2Prepared)]) -> MillerLoopResult
//	src/pairings.rs:48   pub fn final_exponentiation(&self) -> Gt
//	src/scalar.rs:646    fn random(mut rng: impl RngCore) -> Self        (ff::Field)
//	src/g1.rs:948        fn random(mut rng: impl RngCore) -> Self        (group::Group)
//	src/g2.rs:1093       fn random(mut rng: impl RngCore) -> Self        (group::Group)
//	src/pairings.rs:342  fn random(mut rng: impl RngCore) -> Self        (group::Group, Gt)
//	src/g2.rs:210,666    pub fn generator()                              (affine, projective)
//	src/g1.rs:197,615    pub fn generator()                              (affine, projective)
//	src/g1.rs:221,326    pub fn to_compressed(&self) -> [u8; 48] / from_compressed(&[u8; 48])
//	src/g2.rs:254,390    pub fn to_compressed(&self) -> [u8; 96] / from_compressed(&[u8; 96])
//	src/scalar.rs:284,256 pub fn to_bytes(&self) -> [u8; 32] / from_bytes(&[u8; 32])
//	src/hash_to_curve/mod.rs:75,92  fn hash_to_curve / encode_to_curve (message, dst)
func TestBls12381ContractIsTheSourcesSurface(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	want := map[string]map[string]int{
		// The crate-root free functions carry no owning type.
		"bls12_381": {
			"pairing": 2, "multi_miller_loop": 1,
		},
		// `pub struct Bls12;` at src/pairings.rs:793, with `impl Engine for
		// Bls12` at :795 and `impl MultiMillerLoop for Bls12` at :817. A first
		// draft of THIS MAP omitted the owner entirely -- copied from the
		// contract rather than read from the sources -- so the test was green
		// while a whole route into the pairing was undeclared, AND it rejected
		// the repair with "which is not a type the crate has". That is the
		// exact failure a previous family in this campaign shipped; if an owner
		// or method is added below it must be because it was read in the file
		// cited beside it.
		"bls12_381::Bls12":            {"pairing": 2, "multi_miller_loop": 1},
		"bls12_381::MillerLoopResult": {"final_exponentiation": 0},
		// `impl Group for Gt` at src/pairings.rs:339.
		"bls12_381::Gt": {"random": 1},
		"bls12_381::Scalar": {
			"random": 1, "to_bytes": 0, "from_bytes": 1,
		},
		"bls12_381::G1Affine": {
			"generator": 0, "to_compressed": 0, "from_compressed": 1,
		},
		"bls12_381::G2Affine": {
			"generator": 0, "to_compressed": 0, "from_compressed": 1,
		},
		"bls12_381::G1Projective": {
			"random": 1, "generator": 0, "hash_to_curve": 2, "encode_to_curve": 2,
		},
		"bls12_381::G2Projective": {
			"random": 1, "generator": 0, "hash_to_curve": 2, "encode_to_curve": 2,
		},
	}

	declared := map[string]map[string]int{}
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary != "bls12_381" {
				continue
			}
			dot := strings.LastIndex(entry.Method, ".")
			if dot < 0 {
				t.Errorf("entry %q has no owner separator", entry.Method)
				continue
			}
			owner, method := entry.Method[:dot], entry.Method[dot+1:]
			if declared[owner] == nil {
				declared[owner] = map[string]int{}
			}
			declared[owner][method] = entry.Arity
		}
	}

	for owner, methods := range want {
		got := declared[owner]
		if got == nil {
			t.Errorf("%s: no entries declared", owner)
			continue
		}
		for m, arity := range methods {
			gotArity, ok := got[m]
			if !ok {
				t.Errorf("%s: this crate's declared scope includes %q and the contract does not declare it", owner, m)
				continue
			}
			if gotArity != arity {
				t.Errorf("%s.%s declared at arity %d, the sources have %d", owner, m, gotArity, arity)
			}
		}
		for m := range got {
			if _, ok := methods[m]; !ok {
				t.Errorf("%s: the contract declares %q, which is outside the scope this map defines; "+
					"if it is a real method that belongs here, ADD IT TO THE MAP with its src file:line, "+
					"do not delete the entry", owner, m)
			}
		}
	}
	for owner := range declared {
		if _, ok := want[owner]; !ok {
			t.Errorf("the contract declares entries for %q, which is outside the scope this map defines; "+
				"add the owner above with its src file:line if the crate really has it", owner)
		}
	}
}

// TestBls12381ContractExactSet IS THE EXACT-SET COMPARISON, and it is the test
// the mutation battery is run against. The two tests above close the key set
// (owner, method, arity) and prove every entry is reachable through the full
// builder; neither of them reads a RETURN TYPE, a PARAMETER TYPE LIST, a
// CONFIDENCE or a per-parameter property, so a corrupted field loads cleanly
// and passes both. Measured on this family: with only those two tests in place,
// corrupting `canonical_return_type`, corrupting `parameter_types` and
// downgrading `confidence` all SURVIVED.
//
// So this renders every loaded bls12_381 contract in full -- method, arity,
// role, both return fields, confidence, parameter types, the `parameters:`
// property block and its derivations, varargs and any `when:` condition -- and
// compares the whole set against a literal. `props=[]` on every line is a
// declaration, not an omission: no argument of this crate's crypto surface
// determines an operation or contributes a CBOM property (there is no key size,
// no algorithm selector and no mode argument anywhere in it), so the block is
// rendered so that ADDING one cannot pass unnoticed.
func TestBls12381ContractExactSet(t *testing.T) {
	t.Parallel()

	// R8: THE `library:` BLOCK IS PARSED AND OTHERWISE NEVER CONSULTED, so
	// nothing else in this repository notices if it is wrong. `version_range`
	// in particular is read at load and never used for resolution
	// (contracts.go:471), and it is the field this file's header reasons hardest
	// about -- measured: rewriting it to ">=0.1.0,<0.9.0", renaming the
	// coordinate and wiping the description all left every other assertion in
	// this package green. `rust_balloon_test.go:176` and
	// `rust_biscuit_test.go:217` pin it for the same reason; this family cites
	// balloon as its authority for the bound, so it carries balloon's guard too.
	//
	// The range is >=0.5.0,<0.9.0 because `version_range` is per library and may
	// only claim versions for which EVERY entry below is true. `hash_to_curve`
	// arrives at 0.5.0 (0.5.0 src/hash_to_curve/mod.rs:70) and the four sampling
	// entries take `&mut R` rather than `impl RngCore` at 0.2.0
	// (0.2.0 src/scalar.rs:654), so 0.1.0-0.4.0 are excluded on both counts.
	// 0.9.0 does not exist; 0.8.0 is the newest published release.
	singleData, err := os.ReadFile("contracts/rust/bls12_381.yaml")
	if err != nil {
		t.Fatalf("read bls12_381.yaml: %v", err)
	}
	single, err := contracts.Load(singleData)
	if err != nil {
		t.Fatalf("Load(bls12_381.yaml): %v", err)
	}
	if single.Library == nil {
		t.Fatal("bls12_381.yaml declares no library: block")
	}
	if single.Library.Name != "bls12_381" {
		t.Errorf("library.name = %q, want %q", single.Library.Name, "bls12_381")
	}
	if got, want := strings.Join(single.Library.Coordinates, ","), "bls12_381"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	if got, want := single.Library.VersionRange, ">=0.5.0,<0.9.0"; got != want {
		t.Errorf("version_range = %q, want %q -- the range may claim only versions "+
			"for which every declared signature below is true", got, want)
	}
	if single.Library.Description == "" {
		t.Error("library.description is empty")
	}

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	want := []string{
		"bls12_381.multi_miller_loop#1 role=operation canonret=bls12_381::MillerLoopResult rettype=bls12_381::MillerLoopResult conf=high params=[&[(&bls12_381::G1Affine, &bls12_381::G2Prepared)]] props=[] varargs=false when=-",
		"bls12_381.pairing#2 role=operation canonret=bls12_381::Gt rettype=bls12_381::Gt conf=high params=[&bls12_381::G1Affine,&bls12_381::G2Affine] props=[] varargs=false when=-",
		"bls12_381::Bls12.multi_miller_loop#1 role=operation canonret=bls12_381::MillerLoopResult rettype=bls12_381::MillerLoopResult conf=high params=[&[(&bls12_381::G1Affine, &bls12_381::G2Prepared)]] props=[] varargs=false when=-",
		"bls12_381::Bls12.pairing#2 role=operation canonret=bls12_381::Gt rettype=bls12_381::Gt conf=high params=[&bls12_381::G1Affine,&bls12_381::G2Affine] props=[] varargs=false when=-",
		"bls12_381::G1Affine.from_compressed#1 role=factory canonret=subtle::CtOption<bls12_381::G1Affine> rettype=bls12_381::G1Affine conf=high params=[&[u8; 48]] props=[] varargs=false when=-",
		"bls12_381::G1Affine.generator#0 role=factory canonret=bls12_381::G1Affine rettype=bls12_381::G1Affine conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G1Affine.to_compressed#0 role=output canonret=[u8; 48] rettype=[u8; 48] conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G1Projective.encode_to_curve#2 role=operation canonret=bls12_381::G1Projective rettype=bls12_381::G1Projective conf=high params=[impl AsRef<[u8]>,&[u8]] props=[] varargs=false when=-",
		"bls12_381::G1Projective.generator#0 role=factory canonret=bls12_381::G1Projective rettype=bls12_381::G1Projective conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G1Projective.hash_to_curve#2 role=operation canonret=bls12_381::G1Projective rettype=bls12_381::G1Projective conf=high params=[impl AsRef<[u8]>,&[u8]] props=[] varargs=false when=-",
		"bls12_381::G1Projective.random#1 role=factory canonret=bls12_381::G1Projective rettype=bls12_381::G1Projective conf=high params=[impl rand_core::RngCore] props=[] varargs=false when=-",
		"bls12_381::G2Affine.from_compressed#1 role=factory canonret=subtle::CtOption<bls12_381::G2Affine> rettype=bls12_381::G2Affine conf=high params=[&[u8; 96]] props=[] varargs=false when=-",
		"bls12_381::G2Affine.generator#0 role=factory canonret=bls12_381::G2Affine rettype=bls12_381::G2Affine conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G2Affine.to_compressed#0 role=output canonret=[u8; 96] rettype=[u8; 96] conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G2Projective.encode_to_curve#2 role=operation canonret=bls12_381::G2Projective rettype=bls12_381::G2Projective conf=high params=[impl AsRef<[u8]>,&[u8]] props=[] varargs=false when=-",
		"bls12_381::G2Projective.generator#0 role=factory canonret=bls12_381::G2Projective rettype=bls12_381::G2Projective conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::G2Projective.hash_to_curve#2 role=operation canonret=bls12_381::G2Projective rettype=bls12_381::G2Projective conf=high params=[impl AsRef<[u8]>,&[u8]] props=[] varargs=false when=-",
		"bls12_381::G2Projective.random#1 role=factory canonret=bls12_381::G2Projective rettype=bls12_381::G2Projective conf=high params=[impl rand_core::RngCore] props=[] varargs=false when=-",
		"bls12_381::Gt.random#1 role=factory canonret=bls12_381::Gt rettype=bls12_381::Gt conf=high params=[impl rand_core::RngCore] props=[] varargs=false when=-",
		"bls12_381::MillerLoopResult.final_exponentiation#0 role=operation canonret=bls12_381::Gt rettype=bls12_381::Gt conf=high params=[] props=[] varargs=false when=-",
		"bls12_381::Scalar.from_bytes#1 role=factory canonret=subtle::CtOption<bls12_381::Scalar> rettype=bls12_381::Scalar conf=high params=[&[u8; 32]] props=[] varargs=false when=-",
		"bls12_381::Scalar.random#1 role=factory canonret=bls12_381::Scalar rettype=bls12_381::Scalar conf=high params=[impl rand_core::RngCore] props=[] varargs=false when=-",
		"bls12_381::Scalar.to_bytes#0 role=output canonret=[u8; 32] rettype=[u8; 32] conf=high params=[] props=[] varargs=false when=-",
	}

	var got []string
	for _, bucket := range kb.Contracts {
		for _, e := range bucket {
			if e.SourceLibrary != "bls12_381" {
				continue
			}
			props := make([]string, 0, len(e.Parameters))
			for _, p := range e.Parameters {
				idx := "-"
				if p.Index != nil {
					idx = strconv.Itoa(*p.Index)
				}
				contributes := "-"
				if p.Contributes != nil {
					contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
				}
				props = append(props, fmt.Sprintf("%s/%s/%s/%s", idx, p.Name, p.Role, contributes))
			}
			when := "-"
			if e.When != nil {
				when = fmt.Sprintf("%d in %s", e.When.ArgIndex, strings.Join(e.When.ArgValueIn, "|"))
			}
			got = append(got, fmt.Sprintf(
				"%s#%d role=%s canonret=%s rettype=%s conf=%s params=[%s] props=[%s] varargs=%t when=%s",
				e.Method, e.Arity, e.Role, e.CanonicalReturnType, e.Return.Type, e.Return.Confidence,
				strings.Join(e.ParameterTypes, ","), strings.Join(props, ";"), e.Varargs, when))
		}
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("the KB loads %d bls12_381 entries and this test declares %d;\ngot:\n%s",
			len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d differs:\n  want %s\n  got  %s", i, want[i], got[i])
		}
	}
}
