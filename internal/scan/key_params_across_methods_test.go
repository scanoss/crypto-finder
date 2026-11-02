// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	jcaInitialize  = "java.security.KeyPairGenerator.initialize"
	jcaGetInstance = "java.security.KeyPairGenerator.getInstance"
)

// keyParamsAcrossMethodsSource creates each KeyPairGenerator in one method and
// fixes its size or curve in another. The finding is the getInstance call, the
// only call a detection rule sees.
const keyParamsAcrossMethodsSource = `package demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

class Keys {
    private static final int CONSTANT_BITS = 3072;

    static KeyPair literalSize(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }

    static KeyPair sizeParameter(String alg, int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    static KeyPairGenerator returned() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }

    static KeyPair disagreeingCallers(int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    static KeyPair constantParameter(int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    static KeyPair curveParameter(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    void callers() throws Exception {
        literalSize("RSA");
        sizeParameter("RSA", 4096);
        sizeParameter("RSA", 4096);

        KeyPairGenerator kpg = returned();
        kpg.initialize(2048);
        kpg.generateKeyPair();

        disagreeingCallers(2048);
        disagreeingCallers(4096);
        constantParameter(CONSTANT_BITS);
        curveParameter("secp384r1");
    }
}
`

// TestKeyParamsAcrossMethods_ResolveFromCallersAndReturns pins that a key size
// or curve fixed in another method than the generator's creation still reaches
// the getInstance finding, live and stitched: through a parameter every caller
// fills with the same constant, and through a generator the method returns to
// a caller that configures it. Callers that disagree publish no size.
func TestKeyParamsAcrossMethods_ResolveFromCallersAndReturns(t *testing.T) {
	for _, tc := range []struct {
		name     string
		method   string // the getInstance call is the line after its declaration
		match    string
		wantBits int // 0: a supporting call carries evidence but no bits
	}{
		{name: "A literal next to getInstance", method: "literalSize(", match: "KeyPairGenerator.getInstance(alg)", wantBits: 3072},
		{name: "B size parameter, both callers pass 4096", method: "sizeParameter(", match: "KeyPairGenerator.getInstance(alg)", wantBits: 4096},
		{name: "C generator returned, caller initializes it", method: "returned(", match: `KeyPairGenerator.getInstance("RSA")`, wantBits: 2048},
		{name: "callers pass 2048 and 4096", method: "disagreeingCallers(", match: `KeyPairGenerator.getInstance("RSA")`},
		{name: "static final constant through a parameter", method: "constantParameter(", match: `KeyPairGenerator.getInstance("RSA")`, wantBits: 3072},
		{name: "EC curve name through a parameter", method: "curveParameter(", match: `KeyPairGenerator.getInstance("EC")`, wantBits: 384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := lineAfter(t, keyParamsAcrossMethodsSource, "static KeyPair "+tc.method, "static KeyPairGenerator "+tc.method)
			exports := terminalExports(t, "java", "Keys.java", keyParamsAcrossMethodsSource, line, tc.match, jcaGetInstance, "")
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, jcaInitialize),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, jcaInitialize),
				"annotate": fragmentKeyLength(&exports.annotate, exports.findingID, jcaInitialize),
			} {
				if got == nil {
					t.Fatalf("%s: no initialize supporting call carries resolved_key_length", name)
				}
				if tc.wantBits == 0 {
					if got.Bits != nil || got.Provenance != keyLengthProvenanceUnknown {
						t.Fatalf("%s: resolved_key_length = %#v, want unknown with no bits", name, got)
					}
					continue
				}
				if got.Bits == nil || *got.Bits != tc.wantBits || got.Provenance != keyLengthProvenanceConstant {
					t.Fatalf("%s: resolved_key_length = %#v, want %d constant", name, got, tc.wantBits)
				}
			}
		})
	}
}

// TestKeyParamsAcrossMethods_ReturnedGeneratorPerCaller pins that each caller
// configuring a returned generator contributes its own supporting call with
// its own size, so two callers that size it differently publish both sizes on
// separate supporting calls rather than one invented size.
func TestKeyParamsAcrossMethods_ReturnedGeneratorPerCaller(t *testing.T) {
	const source = `package demo;

import java.security.KeyPairGenerator;

class Keys {
    static KeyPairGenerator returned() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }

    void small() throws Exception {
        KeyPairGenerator kpg = returned();
        kpg.initialize(2048);
    }

    void large(Factory factory) throws Exception {
        KeyPairGenerator kpg = returned();
        factory.configure();
        kpg.initialize(4096);
    }
}
`
	exports := terminalExports(t, "java", "Keys.java", source, 7, `KeyPairGenerator.getInstance("RSA")`, jcaGetInstance, "")
	got := supportingBitsByLine(exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID)
	if want := "12:2048,18:4096"; got != want {
		t.Fatalf("supporting key bits by line = %q, want %q", got, want)
	}
	if annotated := fragmentBitsByLine(&exports.annotate, exports.findingID); annotated != got {
		t.Fatalf("annotate supporting key bits by line = %q, want the live %q", annotated, got)
	}
}

// TestKeyParamsAcrossMethods_AnnotateMatchesFullFragment pins that `annotate`,
// re-deriving supporting calls from the cached fragment, gives each finding of
// the across-methods cases the same supporting calls as the full scan's
// fragment, the caller-side calls on a returned generator included.
func TestKeyParamsAcrossMethods_AnnotateMatchesFullFragment(t *testing.T) {
	for _, method := range []string{"literalSize(", "sizeParameter(", "returned(", "disagreeingCallers(", "constantParameter(", "curveParameter("} {
		t.Run(method, func(t *testing.T) {
			line := lineAfter(t, keyParamsAcrossMethodsSource, "static KeyPair "+method, "static KeyPairGenerator "+method)
			match := strings.TrimSpace(strings.Split(keyParamsAcrossMethodsSource, "\n")[line-1])
			match = match[strings.Index(match, "KeyPairGenerator.getInstance"):strings.LastIndex(match, ";")]
			exports := terminalExports(t, "java", "Keys.java", keyParamsAcrossMethodsSource, line, match, jcaGetInstance, "")
			full, annotated := fragmentSupportingIDs(&exports.fragment, exports.findingID), fragmentSupportingIDs(&exports.annotate, exports.findingID)
			if full == "" || full != annotated {
				t.Fatalf("annotate supporting ids = %q, full fragment = %q", annotated, full)
			}
			if full, annotated := fragmentBitsByLine(&exports.fragment, exports.findingID), fragmentBitsByLine(&exports.annotate, exports.findingID); full != annotated {
				t.Fatalf("annotate key bits by line = %q, full fragment = %q", annotated, full)
			}
		})
	}
}

// TestKeyParamsAcrossMethods_DepthBounds pins both bounds: a size passed
// through more parameter hops than maxExportSourceResolutionDepth allows, and
// a generator returned through more methods than maxReturnedObjectDepth, stay
// unresolved instead of being chased without limit.
func TestKeyParamsAcrossMethods_DepthBounds(t *testing.T) {
	t.Run("parameter hops", func(t *testing.T) {
		// Each call site a parameter is resolved through costs two levels of
		// the source resolution depth: the parameter, then the caller's
		// argument.
		const maxParameterHops = maxExportSourceResolutionDepth / 2
		for _, tc := range []struct {
			hops     int
			wantBits bool
		}{{hops: 1, wantBits: true}, {hops: maxParameterHops, wantBits: true}, {hops: maxParameterHops + 1, wantBits: false}} {
			source, line := parameterHopsSource(tc.hops)
			exports := terminalExports(t, "java", "Keys.java", source, line, `KeyPairGenerator.getInstance("RSA")`, jcaGetInstance, "")
			got := keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, jcaInitialize)
			if resolved := got != nil && got.Bits != nil; resolved != tc.wantBits {
				t.Errorf("%d hops: resolved = %v (%#v), want %v", tc.hops, resolved, got, tc.wantBits)
			}
		}
	})
	t.Run("returned through helpers", func(t *testing.T) {
		for _, tc := range []struct {
			helpers  int
			wantBits bool
		}{{helpers: 1, wantBits: true}, {helpers: maxReturnedObjectDepth, wantBits: true}, {helpers: maxReturnedObjectDepth + 1, wantBits: false}} {
			source, line := returnHopsSource(tc.helpers)
			exports := terminalExports(t, "java", "Keys.java", source, line, `KeyPairGenerator.getInstance("RSA")`, jcaGetInstance, "")
			got := keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, jcaInitialize)
			if resolved := got != nil && got.Bits != nil; resolved != tc.wantBits {
				t.Errorf("%d helpers: resolved = %v (%#v), want %v", tc.helpers, resolved, got, tc.wantBits)
			}
			annotated := fragmentKeyLength(&exports.annotate, exports.findingID, jcaInitialize)
			if resolved := annotated != nil && annotated.Bits != nil; resolved != tc.wantBits {
				t.Errorf("%d helpers: annotate resolved = %v (%#v), want %v", tc.helpers, resolved, annotated, tc.wantBits)
			}
		}
	})
}

// TestKeyParamsAcrossMethods_GoReturnedObjectLifecycle pins that following a
// returned object is not Java-specific: a Go helper returning a hash keeps the
// caller's Write as the finding's supporting call.
func TestKeyParamsAcrossMethods_GoReturnedObjectLifecycle(t *testing.T) {
	const source = `package main

import (
	"crypto/sha256"
	"hash"
)

func newHash() hash.Hash {
	return sha256.New()
}

func main() {
	h := newHash()
	h.Write([]byte("data"))
}
`
	exports := terminalExports(t, "go", "main.go", source, 9, "sha256.New()", "crypto/sha256.New", "")
	var functions []string
	for i := range exports.live.FindingGraphs {
		if exports.live.FindingGraphs[i].FindingID != exports.findingID {
			continue
		}
		for _, id := range exports.live.FindingGraphs[i].SupportingCallIDs {
			for j := range exports.live.SupportingCalls {
				if exports.live.SupportingCalls[j].SupportingID == id && exports.live.SupportingCalls[j].StartLine == 14 {
					functions = append(functions, exports.live.SupportingCalls[j].SupportingCall.FunctionName)
				}
			}
		}
	}
	if len(functions) != 1 || !strings.HasSuffix(functions[0], ".Write") {
		t.Fatalf("supporting calls on main.go:14 = %q, want the caller's h.Write", functions)
	}
}

// parameterHopsSource passes a literal size through hops methods before it
// reaches initialize. It returns the source and the getInstance line.
func parameterHopsSource(hops int) (string, int) {
	var b strings.Builder
	b.WriteString("package demo;\n\nimport java.security.KeyPairGenerator;\n\nclass Keys {\n")
	b.WriteString("    static void gen(int size) throws Exception {\n")
	b.WriteString("        KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n")
	b.WriteString("        kpg.initialize(size);\n    }\n")
	callee := "gen"
	for i := 1; i < hops; i++ {
		name := fmt.Sprintf("hop%d", i)
		fmt.Fprintf(&b, "    static void %s(int size) throws Exception { %s(size); }\n", name, callee)
		callee = name
	}
	fmt.Fprintf(&b, "    void root() throws Exception { %s(2048); }\n}\n", callee)
	return b.String(), 7
}

// returnHopsSource returns the generator through helpers methods before a
// caller initializes it. It returns the source and the getInstance line.
func returnHopsSource(helpers int) (string, int) {
	var b strings.Builder
	b.WriteString("package demo;\n\nimport java.security.KeyPairGenerator;\n\nclass Keys {\n")
	b.WriteString("    static KeyPairGenerator helper1() throws Exception {\n")
	b.WriteString("        return KeyPairGenerator.getInstance(\"RSA\");\n    }\n")
	for i := 2; i <= helpers; i++ {
		fmt.Fprintf(&b, "    static KeyPairGenerator helper%d() throws Exception { return helper%d(); }\n", i, i-1)
	}
	fmt.Fprintf(&b, "    void root() throws Exception {\n        KeyPairGenerator kpg = helper%d();\n        kpg.initialize(2048);\n    }\n}\n", helpers)
	return b.String(), 7
}

// supportingBitsByLine renders a finding's resolved supporting-call sizes as
// sorted "line:bits" pairs.
func supportingBitsByLine(graphs []callGraphExportFinding, supporting []callGraphSupportingCall, findingID string) string {
	var pairs []string
	for i := range graphs {
		if graphs[i].FindingID != findingID {
			continue
		}
		for _, id := range graphs[i].SupportingCallIDs {
			for j := range supporting {
				call := supporting[j].SupportingCall
				if supporting[j].SupportingID == id && call != nil && call.ResolvedKeyLength != nil && call.ResolvedKeyLength.Bits != nil {
					pairs = append(pairs, fmt.Sprintf("%d:%d", supporting[j].StartLine, *call.ResolvedKeyLength.Bits))
				}
			}
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// TestKeyParamsAcrossMethods_AnnotateOldFragmentFollowsNoReturn pins that a
// fragment exported before graph-fragment-1.15, which has no returns_calls,
// still loads, and that annotate then derives what it did before: the
// generator's own-method lifecycle only, without the caller-side calls.
func TestKeyParamsAcrossMethods_AnnotateOldFragmentFollowsNoReturn(t *testing.T) {
	line := lineAfter(t, keyParamsAcrossMethodsSource, "static KeyPairGenerator returned(")
	exports := terminalExports(t, "java", "Keys.java", keyParamsAcrossMethodsSource, line, `KeyPairGenerator.getInstance("RSA")`, jcaGetInstance, "")
	if got := fragmentSupportingIDs(&exports.annotate, exports.findingID); got == "" {
		t.Fatal("annotate on a 1.15 fragment joined no supporting call to the returned generator")
	}

	old := exports.fragment
	old.SchemaVersion = "graph-fragment-1.14"
	old.Functions = append([]graphfrag.GraphFragmentFunction(nil), old.Functions...)
	recorded := false
	for i := range old.Functions {
		recorded = recorded || len(old.Functions[i].ReturnsCalls) > 0
		old.Functions[i].ReturnsCalls = nil
	}
	if !recorded {
		t.Fatal("the full fragment records no returns_calls")
	}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "returns_calls") {
		t.Fatal("the trimmed fragment still carries returns_calls")
	}
	fragment, err := graphfrag.DecodeFragment(graphfrag.ComponentKey{}, data)
	if err != nil {
		t.Fatalf("a graph-fragment-1.14 fragment must still decode: %v", err)
	}
	annotate := buildAnnotateExport(exports.report, fragment)
	if got := fragmentSupportingIDs(&annotate, exports.findingID); got != "" {
		t.Fatalf("annotate on a 1.14 fragment joined supporting calls %q, want none: `returned` makes no call on the generator", got)
	}
}

// fragmentSupportingIDs renders the supporting_call_ids of a graph fragment's
// finding, sorted and comma-joined.
func fragmentSupportingIDs(export *graphfrag.GraphFragmentExport, findingID string) string {
	var ids []string
	for i := range export.CryptoAnnotations {
		if export.CryptoAnnotations[i].FindingID == findingID {
			ids = append(ids, export.CryptoAnnotations[i].SupportingCallIDs...)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// fragmentSupportingCalls returns the supporting calls a graph fragment joins
// to a finding.
func fragmentSupportingCalls(export *graphfrag.GraphFragmentExport, findingID string) []*graphfrag.GraphFragmentSupporting {
	var out []*graphfrag.GraphFragmentSupporting
	for _, id := range strings.Split(fragmentSupportingIDs(export, findingID), ",") {
		for i := range export.SupportingCalls {
			if export.SupportingCalls[i].SupportingID == id && export.SupportingCalls[i].SupportingCall != nil {
				out = append(out, &export.SupportingCalls[i])
			}
		}
	}
	return out
}

// fragmentKeyLength returns the key-length evidence of the first supporting
// call to function that a graph fragment joins to a finding.
func fragmentKeyLength(export *graphfrag.GraphFragmentExport, findingID, function string) *graphfrag.ResolvedKeyLength {
	for _, call := range fragmentSupportingCalls(export, findingID) {
		if call.SupportingCall.FunctionName == function && call.SupportingCall.ResolvedKeyLength != nil {
			return call.SupportingCall.ResolvedKeyLength
		}
	}
	return nil
}

// fragmentBitsByLine is supportingBitsByLine for a graph fragment.
func fragmentBitsByLine(export *graphfrag.GraphFragmentExport, findingID string) string {
	var pairs []string
	for _, call := range fragmentSupportingCalls(export, findingID) {
		if keyLength := call.SupportingCall.ResolvedKeyLength; keyLength != nil && keyLength.Bits != nil {
			pairs = append(pairs, fmt.Sprintf("%d:%d", call.StartLine, *keyLength.Bits))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// lineAfter returns the line after the first line containing any of markers:
// the first statement of the method a marker declares.
func lineAfter(t *testing.T, source string, markers ...string) int {
	t.Helper()
	for i, line := range strings.Split(source, "\n") {
		for _, marker := range markers {
			if strings.Contains(line, marker) {
				return i + 2
			}
		}
	}
	t.Fatalf("no line contains %q", markers)
	return 0
}
