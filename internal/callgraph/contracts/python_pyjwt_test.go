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

const pyjwtLibrary = "pyjwt"

// renderPyjwtContract renders one loaded contract as a single comparable line.
//
// Every field the loader parses is rendered, including the `parameters:` block
// and `varargs`: a mutation to a field no assertion renders survives the whole
// battery. `Index` is a *int and `Contributes` is nil for a `role: none`
// parameter, so both are nil-guarded — rendering `%d` on the pointer prints an
// address and dereferencing the other panics.
func renderPyjwtContract(key string, c contracts.Contract) string {
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
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprintf("%d", *p.Index)
			}
			property, derivation := "-", "-"
			if p.Contributes != nil {
				property = p.Contributes.Property
				derivation = p.Contributes.Derivation
			}
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s",
				idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, canonical, paramRoles, c.Varargs, when, c.SourceLibrary)
}

func loadedPyjwtContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != pyjwtLibrary {
				continue
			}
			lines = append(lines, renderPyjwtContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no pyjwt contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

// wantPyjwtContracts is written BY HAND from the PyJWT sources, not from the
// YAML. Deriving it from the YAML would make the comparison tautological and
// green on a corrupted contract, which is the one thing this test exists to
// prevent. Each entry carries the file:line it was read at, in PyJWT 2.13.0
// (the newest release in this family's matrix range), so a later reader can
// audit the map itself rather than only the diff.
func wantPyjwtContracts() []string {
	return []string{
		// ── module-level JWT API. `import jwt; jwt.encode(...)` and
		// `from jwt import encode; encode(...)` both emit `jwt.encode`,
		// measured off an exported call graph, so ONE entry serves both.
		// jwt/api_jwt.py:591-593 bind these from a PyJWT singleton.
		"jwt.decode#1 jwt.decode/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.decode#3 jwt.decode/operation/builtins.dict/high/-/builtins.dict/params=2:algorithms:operation-determining:-:-/varargs=false/when=-/lib=pyjwt",
		"jwt.decode_complete#1 jwt.decode_complete/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.encode#2 jwt.encode/operation/builtins.str/high/-/builtins.str/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.encode#3 jwt.encode/operation/builtins.str/high/builtins.dict|builtins.str|builtins.str/builtins.str/params=2:algorithm:operation-determining:-:-/varargs=false/when=-/lib=pyjwt",

		// ── the PyJWT object. jwt/api_jwt.py:42 (class), :90 encode,
		// :303 decode, :174 decode_complete. Two constructor spellings:
		// `jwt.PyJWT()` emits the attribute path, `from jwt import PyJWT;
		// PyJWT()` emits the `.<init>` form.
		"jwt.PyJWT#0 jwt.PyJWT/factory/jwt.api_jwt.PyJWT/high/-/jwt.api_jwt.PyJWT/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.PyJWT.<init>#0 jwt.PyJWT.<init>/factory/jwt.api_jwt.PyJWT/high/-/jwt.api_jwt.PyJWT/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jwt.PyJWT#0 jwt.api_jwt.PyJWT/factory/jwt.api_jwt.PyJWT/high/-/jwt.api_jwt.PyJWT/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jwt.PyJWT.<init>#0 jwt.api_jwt.PyJWT.<init>/factory/jwt.api_jwt.PyJWT/high/-/jwt.api_jwt.PyJWT/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jwt.PyJWT.decode#1 jwt.api_jwt.PyJWT.decode/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jwt.PyJWT.decode_complete#1 jwt.api_jwt.PyJWT.decode_complete/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jwt.PyJWT.encode#2 jwt.api_jwt.PyJWT.encode/operation/builtins.str/high/-/builtins.str/params=-/varargs=false/when=-/lib=pyjwt",

		// ── the JWS layer. jwt/api_jws.py:33 (class), :120 encode,
		// :285 decode, :219 decode_complete, :449-455 the singleton bindings.
		// Present since 1.5.0, when api_jws.py split out of api.py.
		"jwt.PyJWS#0 jwt.PyJWS/factory/jwt.api_jws.PyJWS/high/-/jwt.api_jws.PyJWS/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.PyJWS.<init>#0 jwt.PyJWS.<init>/factory/jwt.api_jws.PyJWS/high/-/jwt.api_jws.PyJWS/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.PyJWS#0 jwt.api_jws.PyJWS/factory/jwt.api_jws.PyJWS/high/-/jwt.api_jws.PyJWS/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.PyJWS.<init>#0 jwt.api_jws.PyJWS.<init>/factory/jwt.api_jws.PyJWS/high/-/jwt.api_jws.PyJWS/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.PyJWS.decode#1 jwt.api_jws.PyJWS.decode/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.PyJWS.encode#2 jwt.api_jws.PyJWS.encode/operation/builtins.str/high/-/builtins.str/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.decode#1 jwt.api_jws.decode/operation/builtins.dict/high/-/builtins.dict/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.api_jws.encode#2 jwt.api_jws.encode/operation/builtins.str/high/-/builtins.str/params=-/varargs=false/when=-/lib=pyjwt",

		// ── algorithm registry. jwt/api_jws.py:59 register_algorithm,
		// :76 unregister_algorithm, :99 get_algorithm_by_name.
		// These CONFIGURE which algorithms are accepted; they perform no
		// cryptography, so they are `config` rather than `operation`.
		// `get_algorithm_by_name` returns an Algorithm (jwt/algorithms.py:174)
		// and is therefore a `factory`.
		"jwt.get_algorithm_by_name#1 jwt.get_algorithm_by_name/factory/jwt.algorithms.Algorithm/high/-/jwt.algorithms.Algorithm/params=0:alg_name:operation-determining:-:-/varargs=false/when=-/lib=pyjwt",
		"jwt.register_algorithm#2 jwt.register_algorithm/config/builtins.NoneType/high/-/builtins.NoneType/params=-/varargs=false/when=-/lib=pyjwt",
		"jwt.unregister_algorithm#1 jwt.unregister_algorithm/config/builtins.NoneType/high/-/builtins.NoneType/params=-/varargs=false/when=-/lib=pyjwt",
	}
}

func TestPythonPyjwtContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantPyjwtContracts()
	sort.Strings(want)
	got := loadedPyjwtContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		wantSet[line] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, line := range got {
		gotSet[line] = struct{}{}
	}

	var missing, unexpected []string
	for _, line := range want {
		if _, ok := gotSet[line]; !ok {
			missing = append(missing, line)
		}
	}
	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			unexpected = append(unexpected, line)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	for _, line := range missing {
		t.Errorf("contract entry declared in the expectation but NOT loaded from the YAML:\n\t%q,", line)
	}
	for _, line := range unexpected {
		t.Errorf("unexpected contract entry — if the YAML change is intended, add this one line to wantPyjwtContracts():\n\t\t%q,", line)
	}
}

func TestPythonPyjwtContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	allowed := map[string]struct{}{
		"factory":   {},
		"config":    {},
		"output":    {},
		"operation": {},
	}
	seen := 0
	for key, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != pyjwtLibrary {
				continue
			}
			seen++
			if _, ok := allowed[c.Role]; !ok {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, c.Role)
			}
			if c.Role == "factory" && c.Return.Type == "" {
				t.Errorf("%s: role=factory with no return type — a factory that types nothing cannot rekey a receiver", key)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no pyjwt contracts loaded — every assertion above passed vacuously")
	}
}

func TestPythonPyjwtContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "pyjwt.yaml"))
	if err != nil {
		t.Fatalf("read pyjwt.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pyjwt.yaml): %v", err)
	}
	if kb.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want python", kb.Ecosystem)
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", kb.SchemaVersion)
	}
	if kb.Library == nil {
		t.Fatal("library block absent")
	}
	if kb.Library.Name != pyjwtLibrary {
		t.Errorf("library.name = %q, want pyjwt", kb.Library.Name)
	}
	// Both spellings: PEP 503 normalizes `PyJWT` and `pyjwt` to one package,
	// and the distribution is published as `PyJWT` while the rule directory and
	// the PURL are lowercase.
	if got, want := strings.Join(kb.Library.Coordinates, ","), "PyJWT,pyjwt"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// The range is bound by the RETURN TYPE, not by how far back the rules
	// match: encode returns bytes in 1.x and str from 2.0.0.
	if got, want := kb.Library.VersionRange, ">=2.0,<3.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
}

// TestPythonPyjwtContract_ForeignJoseNamespacesAreNotClaimed pins the namespace
// split that authlib.yaml states from the other side. python-jose is reached as
// `from jose import jwt` and Authlib as `from authlib.jose import jwt`; neither
// may resolve to a pyjwt contract, and the bare `jwt.*` spelling must resolve to
// pyjwt and to nothing else. A wrong answer here is a wrong PURL on real code,
// and python has no receiver filter beneath the rule layer to catch it.
func TestPythonPyjwtContract_ForeignJoseNamespacesAreNotClaimed(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}

	// The positive control comes FIRST: without it the sweep below proves
	// nothing, because an empty KB satisfies every negative.
	if got := kb.ContractsFor("jwt.encode", 2); len(got) == 0 {
		t.Fatal("positive control failed: jwt.encode#2 does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, foreign := range []string{
		"jose.jwt.encode",
		"jose.jwt.decode",
		"jose.jws.sign",
		"authlib.jose.jwt.encode",
		"authlib.jose.jwt.decode",
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(foreign, arity) {
				if c.SourceLibrary == pyjwtLibrary {
					t.Errorf("%s#%d resolves to a PYJWT contract; that spelling belongs to another distribution",
						foreign, arity)
				}
			}
		}
	}

	for _, own := range []string{"jwt.encode", "jwt.decode"} {
		for _, c := range kb.ContractsForTolerant(own, 3) {
			if c.SourceLibrary != pyjwtLibrary {
				t.Errorf("%s resolves to %q; the bare jwt.* namespace belongs to pyjwt",
					own, c.SourceLibrary)
			}
		}
	}
}

// TestPythonPyjwtContract_UncontractedAPIsAreAbsent pins the surface this family
// deliberately does NOT contract, each with the reason. Without this, adding one
// of them later looks like an omission being corrected rather than a scope
// decision being reversed.
func TestPythonPyjwtContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if got := kb.ContractsFor("jwt.decode", 1); len(got) == 0 {
		t.Fatal("positive control failed: jwt.decode#1 does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, absent := range []struct{ key, reason string }{
		{"jwt.get_unverified_header", "reads the header without verifying it — no cryptographic operation is performed"},
		{"jwt.PyJWKClient", "fetches a JWKS over HTTP; the call site states no algorithm and no key type"},
		{"jwt.PyJWKClient.get_signing_key", "returns a key whose algorithm is not knowable at the call site"},
		{"jwt.algorithms.NoneAlgorithm", "the registry classes are matched by rules, not contracted as call targets"},
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(absent.key, arity) {
				if c.SourceLibrary == pyjwtLibrary {
					t.Errorf("%s resolves to a pyjwt contract, but it is deliberately not contracted: %s",
						absent.key, absent.reason)
				}
			}
		}
	}
}
