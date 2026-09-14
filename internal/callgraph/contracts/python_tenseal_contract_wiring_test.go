// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TenSEAL is homomorphic encryption on tensors, a pybind11 wrapper over
// Microsoft SEAL. Its contract is keyed in several module spellings on purpose:
// the Python call-graph key follows the CONSUMER'S IMPORT, and the written-out
// module-attribute call emits no `.<init>` segment while an imported-name call
// does. Measured on a probe consumer with crypto-finder built from this
// worktree, and reproduced as a fixed point (two consecutive exports identical,
// 37 keys):
//
//	import tenseal as ts; ts.Context(..)              -> tenseal.Context
//	from tenseal.enc_context import Context; C(..)    -> tenseal.enc_context.Context.<init>
//	from tenseal.tensors.ckksvector import CKKSVector -> tenseal.tensors.ckksvector.CKKSVector.<init>
//
// THE EXPECTATION BELOW IS HAND-WRITTEN FROM THE LIBRARY'S OWN SOURCES, NOT
// DERIVED FROM THE YAML. That distinction is the whole point of this file: a
// `want` map copied from the contract is green on a corrupted contract and
// rejects a correct repair, which is the single most repeated defect in this
// campaign. Every symbol below carries the file and line it was read at, in the
// 0.3.16 wheel's own Python sources and the 0.3.18 sdist's C++, and the module
// spellings are expanded mechanically from that hand-written table so that
// adding a real method stays a ONE-LINE edit.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE
// IS TRUE. Vacuity and truth are separate gates. The baseline's truth rests on
// the per-symbol source citations here and in the contract header; this file
// only guarantees that nothing drifts away from it silently.

const tensealLibrary = "tenseal"

// renderTensealContract renders one loaded contract as a single line holding
// every field Load() populates. A field omitted here is a field no mutation of
// which this test can detect — `varargs` in particular, which is inert for
// Python but is rendered anyway so that declaring it would fail loudly.
func renderTensealContract(key string, c contracts.Contract) string {
	params := "-"
	if len(c.ParameterTypes) > 0 {
		params = strings.Join(c.ParameterTypes, "|")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	canonical := c.CanonicalReturnType
	if canonical == "" {
		canonical = "-"
	}
	paramRoles := "-"
	if len(c.Parameters) > 0 {
		rendered := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			rendered = append(rendered, fmt.Sprintf("%d:%s:%s:%s:%s",
				p.Index, p.Name, p.Role, p.Contributes.Property, p.Contributes.Derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, canonical, paramRoles, c.Varargs, when, c.SourceLibrary)
}

func loadedTensealContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != tensealLibrary {
				continue
			}
			lines = append(lines, renderTensealContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no tenseal contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

// ── THE HAND-WRITTEN SOURCE TABLE ───────────────────────────────────────────
//
// One row per SYMBOL as the library declares it. Arity is the REQUIRED-argument
// count: `ContractsForTolerant` falls back to a name-only match for a Python KB
// (contracts.go:292-303), so one entry per method is right and the optional
// trailing arguments every one of these takes are covered by that fallback.

type tensealSymbol struct {
	name   string // the method name as it hangs off its owning type or module
	arity  int
	role   string
	ret    string
	source string // where it was read
}

// Context methods. `tenseal/enc_context.py` in the 0.3.16 wheel; the C++ bodies
// in `tenseal/cpp/context/tensealcontext.cpp` of the 0.3.18 sdist.
var tensealContextMethods = []tensealSymbol{
	{"generate_galois_keys", 0, "operation", "builtins.NoneType", "enc_context.py:236 -> tensealcontext.cpp:280-285 keygen.create_galois_keys(gk)"},
	{"generate_relin_keys", 0, "operation", "builtins.NoneType", "enc_context.py:250 -> tensealcontext.cpp:300-305 keygen.create_relin_keys(rk)"},
	{"make_context_public", 0, "operation", "builtins.NoneType", "enc_context.py:285 -> tensealcontext.cpp:326-328 _secret_key = nullptr"},
	{"serialize", 0, "operation", "builtins.bytes", "enc_context.py:181-192, defaults save_public_key/galois/relin True"},
	{"secret_key", 0, "operation", "tenseal.enc_context.SecretKey", "enc_context.py:261-262 -> SecretKey(self.data.secret_key())"},
	{"public_key", 0, "operation", "tenseal.enc_context.PublicKey", "enc_context.py:267-268"},
	{"galois_keys", 0, "operation", "tenseal.enc_context.GaloisKeys", "enc_context.py:233"},
	{"relin_keys", 0, "operation", "tenseal.enc_context.RelinKeys", "enc_context.py:247"},
}

// The module spellings a consumer's import can produce for the Context type.
var tensealContextSpellings = []string{"tenseal.Context", "tenseal.enc_context.Context"}

// Encrypted-tensor types. Class sources in `tenseal/tensors/`; the free
// functions in `tenseal/__init__.py`.
type tensealTensor struct {
	class     string // CKKSVector
	module    string // ckksvector
	fn        string // ckks_vector
	decryptRT string
	source    string
}

var tensealTensors = []tensealTensor{
	{"CKKSVector", "ckksvector", "ckks_vector", "builtins.list", "__init__.py:100 -> tensors/ckksvector.py:9-43, decrypt :49 -> List[float]"},
	{"BFVVector", "bfvvector", "bfv_vector", "builtins.list", "__init__.py:84 -> tensors/bfvvector.py:9-35, decrypt :38 -> List[int]"},
	{"CKKSTensor", "ckkstensor", "ckks_tensor", "tenseal.tensors.PlainTensor", "__init__.py:116 -> tensors/ckkstensor.py:10, decrypt :54 -> ts.PlainTensor"},
	{"BFVTensor", "bfvtensor", "bfv_tensor", "tenseal.tensors.PlainTensor", "__init__.py:132 -> tensors/bfvtensor.py:10, decrypt :46 -> ts.PlainTensor"},
}

// Free functions that return a Context.
var tensealContextFactories = []tensealSymbol{
	{"tenseal.context", 1, "factory", "tenseal.Context", "__init__.py:63 (0.1.0a0 :16); keygen at tensealcontext.cpp:51-57"},
	{"tenseal.context_from", 1, "factory", "tenseal.Context", "__init__.py:68-71 -> Context.load"},
}

// Free functions that return a CKKSVector but are not named for a tensor type.
var tensealEncodingFactories = []tensealSymbol{
	{"tenseal.im2col_encoding", 5, "factory", "tenseal.tensors.CKKSVector", "__init__.py:14-39, declared -> CKKSVector at :14"},
	{"tenseal.enc_matmul_encoding", 2, "factory", "tenseal.tensors.CKKSVector", "__init__.py:43-60, declared -> CKKSVector at :43"},
}

func line(key, method, role, ret string) string {
	return fmt.Sprintf("%s %s/%s/%s/high/-/-/params=-/varargs=false/when=-/lib=tenseal",
		key, method, role, ret)
}

// wantTensealContracts expands the hand-written table above into the rendered
// set. The EXPANSION is mechanical; the TABLE is the hand-written part.
func wantTensealContracts() []string {
	var want []string
	add := func(method string, arity int, role, ret string) {
		want = append(want, line(fmt.Sprintf("%s#%d", method, arity), method, role, ret))
	}

	for _, f := range tensealContextFactories {
		add(f.name, f.arity, f.role, f.ret)
	}
	for _, spell := range tensealContextSpellings {
		add(spell, 1, "factory", spell)
		add(spell+".<init>", 1, "factory", spell)
		add(spell+".load", 1, "factory", spell)
		for _, m := range tensealContextMethods {
			add(spell+"."+m.name, m.arity, m.role, m.ret)
		}
	}
	for _, tt := range tensealTensors {
		ret := "tenseal.tensors." + tt.class
		add("tenseal."+tt.fn, 2, "factory", ret)
		add("tenseal."+tt.fn+"_from", 2, "factory", ret)
		add("tenseal.lazy_"+tt.fn+"_from", 1, "factory", ret)
		for _, spell := range []string{
			"tenseal." + tt.class,
			"tenseal.tensors." + tt.class,
			"tenseal.tensors." + tt.module + "." + tt.class,
		} {
			add(spell, 2, "factory", ret)
			add(spell+".<init>", 2, "factory", ret)
			add(spell+".decrypt", 0, "operation", tt.decryptRT)
		}
	}
	for _, f := range tensealEncodingFactories {
		add(f.name, f.arity, f.role, f.ret)
	}
	sort.Strings(want)
	return want
}

// TestPythonTensealContract_ExactSet asserts the SYMMETRIC DIFFERENCE and names
// what is missing and what is unexpected, quoting the exact literal to paste,
// so a failure says which line to change rather than that a count moved.
func TestPythonTensealContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantTensealContracts()
	got := loadedTensealContracts(t)

	inWant := make(map[string]bool, len(want))
	for _, w := range want {
		inWant[w] = true
	}
	inGot := make(map[string]bool, len(got))
	for _, g := range got {
		inGot[g] = true
	}

	var missing, unexpected []string
	for _, w := range want {
		if !inGot[w] {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !inWant[g] {
			unexpected = append(unexpected, g)
		}
	}

	for _, m := range missing {
		t.Errorf("contract entry MISSING — the sources declare it and the YAML does not:\n    %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("unexpected contract entry — if the YAML change is intended, add this one line to the table in this file:\n    %q", u)
	}
	if len(missing) == 0 && len(unexpected) == 0 && len(got) != len(want) {
		t.Errorf("duplicate entries: loaded %d lines for %d distinct expectations", len(got), len(want))
	}
}

// TestPythonTensealContract_RolesAreInTheAllowedVocabulary checks roles against
// the vocabulary the loader accepts, NOT against a tally. A tally duplicates the
// exact-set assertion with no independent source and turns one legitimate
// addition into an off-by-one cascade.
func TestPythonTensealContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	allowed := map[string]bool{"factory": true, "config": true, "output": true, "operation": true}
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	seen := 0
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != tensealLibrary {
				continue
			}
			seen++
			if !allowed[list[i].Role] {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, list[i].Role)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no tenseal contracts loaded; every assertion above passed vacuously")
	}
}

// TestPythonTensealContract_EveryFactoryDeclaresAReturnType is the assertion
// that actually makes this family work, so it is stated separately rather than
// left implicit in the exact set.
//
// Before this contract existed, a probe consumer's context operations keyed on
// the CONSUMER'S OWN VARIABLE PATH — `cg.src.cgprobe.ctx.generate_galois_keys()`
// and twelve more — which no contract can ever join and which is
// indistinguishable from having no contract at all. A factory whose return type
// is empty renders identically to no contract, so this is the field the whole
// KB rests on.
func TestPythonTensealContract_EveryFactoryDeclaresAReturnType(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	factories := 0
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != tensealLibrary || list[i].Role != "factory" {
				continue
			}
			factories++
			if strings.TrimSpace(list[i].Return.Type) == "" {
				t.Errorf("%s: factory with an empty return.type; receiver methods on its result can never resolve", key)
			}
		}
	}
	if factories == 0 {
		t.Fatal("no tenseal factories loaded; the assertion above passed vacuously")
	}
}

// TestPythonTensealContract_LibraryBlockIsPinned closes a gap the mutation
// battery for this file FOUND rather than assumed.
//
// Running the eleven mutation classes against the exact-set test above killed
// nine of them and left TWO ALIVE: corrupting `coordinates` and corrupting
// `version_range` changed nothing any assertion could see, because
// `LoadEmbedded` MERGES every python contract and sets `KnowledgeBase.Library`
// to nil whenever more than one library is loaded (contracts.go:65-70), so the
// merged view cannot carry either field. `name` was already covered, but only
// incidentally, through `Contract.SourceLibrary`.
//
// Both fields are load-bearing. `coordinates` is what ties this KB to the PURL
// the rules publish, and `version_range` is the family's coverage claim: the
// 30 committed CSV rows run 0.1.0a0 to 0.3.16, and a range that drifted off
// them would assert coverage the family does not have while every other test
// stayed green.
//
// So this test parses the single file directly rather than the merged KB.
func TestPythonTensealContract_LibraryBlockIsPinned(t *testing.T) {
	t.Parallel()

	data, err := embeddedPythonContract("tenseal.yaml")
	if err != nil {
		t.Fatalf("reading the embedded tenseal contract: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(tenseal.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("tenseal.yaml declares no library block; every assertion below would pass vacuously")
	}
	if got, want := kb.Library.Name, "tenseal"; got != want {
		t.Errorf("library.name = %q, want %q", got, want)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "tenseal"; got != want {
		t.Errorf("library.coordinates = %q, want %q — this is what ties the KB to pkg:pypi/tenseal", got, want)
	}
	// The 30 committed CSV rows for pkg:pypi/tenseal run 0.1.0a0 .. 0.3.16.
	// 0.3.17 and 0.3.18 exist on PyPI and are NOT in the CSV, so the upper
	// bound is deliberate rather than stale.
	if got, want := kb.Library.VersionRange, ">=0.1.0a0,<=0.3.16"; got != want {
		t.Errorf("library.version_range = %q, want %q — this is the family's coverage claim", got, want)
	}
	if got, want := kb.Ecosystem, "python"; got != want {
		t.Errorf("ecosystem = %q, want %q", got, want)
	}
}
