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

// coincurve is the Python CFFI binding to libsecp256k1. Its contract is keyed
// in TWO module spellings on purpose: the Python call-graph key follows the
// CONSUMER'S IMPORT, so `from coincurve import PrivateKey` emits
// `coincurve.PrivateKey.<init>` while `from coincurve.keys import PrivateKey`
// emits `coincurve.keys.PrivateKey.<init>`, and neither key resolves the other.
//
// THIS IS AN EXACT-SET COMPARISON, NOT A PER-KEY SUBSET ASSERTION. A per-key
// test cannot see an entry that should not be there, an entry that was dropped,
// or a field that was corrupted — it only sees the keys it thought to ask
// about. The literal below therefore renders every field the loader populates
// for this library, including `varargs`, `parameter_types` and the `library:`
// block, because a field no test renders is a field every mutation of it
// survives.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE
// IS TRUE. The baseline itself is traced to the package's own source, per
// symbol, in the contract file's header — the version windows there
// (`combine_keys` >= 5.1.0, `sign_schnorr` and `PublicKeyXOnly` >= 18.0.0) were
// read from the archive of the version named AND from the version on the other
// side of it. Vacuity and truth are separate gates.

const coincurveLibrary = "coincurve"

// renderCoincurveContract renders one loaded contract as a single line holding
// every field Load() populates. Anything omitted here is a field no mutation of
// which this test can detect.
func renderCoincurveContract(key string, c contracts.Contract) string {
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

// loadedCoincurveContracts returns every rendered line for the coincurve
// library, sorted. It fails the test if nothing was loaded at all: a
// zero-length set would make every "not present" assertion below pass
// vacuously, which is the failure mode this whole file exists to prevent.
func loadedCoincurveContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != coincurveLibrary {
				continue
			}
			lines = append(lines, renderCoincurveContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no coincurve contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

func TestPythonCoincurveContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := []string{
		"coincurve.PrivateKey.<init>#0 coincurve.PrivateKey.<init>/factory/coincurve.PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.ecdh#1 coincurve.PrivateKey.ecdh/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.from_der#1 coincurve.PrivateKey.from_der/factory/coincurve.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.from_hex#1 coincurve.PrivateKey.from_hex/factory/coincurve.PrivateKey/high/builtins.str/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.from_int#1 coincurve.PrivateKey.from_int/factory/coincurve.PrivateKey/high/builtins.int/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.from_pem#1 coincurve.PrivateKey.from_pem/factory/coincurve.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.sign#1 coincurve.PrivateKey.sign/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.sign_recoverable#1 coincurve.PrivateKey.sign_recoverable/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.sign_schnorr#1 coincurve.PrivateKey.sign_schnorr/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.to_der#0 coincurve.PrivateKey.to_der/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey.to_pem#0 coincurve.PrivateKey.to_pem/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PrivateKey#0 coincurve.PrivateKey/factory/coincurve.PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.<init>#1 coincurve.PublicKey.<init>/factory/coincurve.PublicKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.combine_keys#1 coincurve.PublicKey.combine_keys/factory/coincurve.PublicKey/high/builtins.list/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.format#0 coincurve.PublicKey.format/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.from_point#2 coincurve.PublicKey.from_point/factory/coincurve.PublicKey/high/builtins.int|builtins.int/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.from_secret#1 coincurve.PublicKey.from_secret/factory/coincurve.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.from_signature_and_message#2 coincurve.PublicKey.from_signature_and_message/factory/coincurve.PublicKey/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.from_valid_secret#1 coincurve.PublicKey.from_valid_secret/factory/coincurve.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey.verify#2 coincurve.PublicKey.verify/operation/builtins.bool/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKey#1 coincurve.PublicKey/factory/coincurve.PublicKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly.<init>#1 coincurve.PublicKeyXOnly.<init>/factory/coincurve.PublicKeyXOnly/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly.format#0 coincurve.PublicKeyXOnly.format/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly.from_secret#1 coincurve.PublicKeyXOnly.from_secret/factory/coincurve.PublicKeyXOnly/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly.from_valid_secret#1 coincurve.PublicKeyXOnly.from_valid_secret/factory/coincurve.PublicKeyXOnly/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly.verify#2 coincurve.PublicKeyXOnly.verify/operation/builtins.bool/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.PublicKeyXOnly#1 coincurve.PublicKeyXOnly/factory/coincurve.PublicKeyXOnly/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.ecdsa.deserialize_recoverable#1 coincurve.ecdsa.deserialize_recoverable/operation/builtins.object/low/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.ecdsa.recover#2 coincurve.ecdsa.recover/operation/builtins.object/low/builtins.bytes|builtins.object/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.<init>#0 coincurve.keys.PrivateKey.<init>/factory/coincurve.keys.PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.ecdh#1 coincurve.keys.PrivateKey.ecdh/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.from_der#1 coincurve.keys.PrivateKey.from_der/factory/coincurve.keys.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.from_hex#1 coincurve.keys.PrivateKey.from_hex/factory/coincurve.keys.PrivateKey/high/builtins.str/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.from_int#1 coincurve.keys.PrivateKey.from_int/factory/coincurve.keys.PrivateKey/high/builtins.int/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.from_pem#1 coincurve.keys.PrivateKey.from_pem/factory/coincurve.keys.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.sign#1 coincurve.keys.PrivateKey.sign/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.sign_recoverable#1 coincurve.keys.PrivateKey.sign_recoverable/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.sign_schnorr#1 coincurve.keys.PrivateKey.sign_schnorr/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.to_der#0 coincurve.keys.PrivateKey.to_der/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey.to_pem#0 coincurve.keys.PrivateKey.to_pem/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PrivateKey#0 coincurve.keys.PrivateKey/factory/coincurve.keys.PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.<init>#1 coincurve.keys.PublicKey.<init>/factory/coincurve.keys.PublicKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.combine_keys#1 coincurve.keys.PublicKey.combine_keys/factory/coincurve.keys.PublicKey/high/builtins.list/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.format#0 coincurve.keys.PublicKey.format/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.from_point#2 coincurve.keys.PublicKey.from_point/factory/coincurve.keys.PublicKey/high/builtins.int|builtins.int/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.from_secret#1 coincurve.keys.PublicKey.from_secret/factory/coincurve.keys.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.from_signature_and_message#2 coincurve.keys.PublicKey.from_signature_and_message/factory/coincurve.keys.PublicKey/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.from_valid_secret#1 coincurve.keys.PublicKey.from_valid_secret/factory/coincurve.keys.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey.verify#2 coincurve.keys.PublicKey.verify/operation/builtins.bool/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKey#1 coincurve.keys.PublicKey/factory/coincurve.keys.PublicKey/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly.<init>#1 coincurve.keys.PublicKeyXOnly.<init>/factory/coincurve.keys.PublicKeyXOnly/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly.format#0 coincurve.keys.PublicKeyXOnly.format/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly.from_secret#1 coincurve.keys.PublicKeyXOnly.from_secret/factory/coincurve.keys.PublicKeyXOnly/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly.from_valid_secret#1 coincurve.keys.PublicKeyXOnly.from_valid_secret/factory/coincurve.keys.PublicKeyXOnly/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly.verify#2 coincurve.keys.PublicKeyXOnly.verify/operation/builtins.bool/high/builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.keys.PublicKeyXOnly#1 coincurve.keys.PublicKeyXOnly/factory/coincurve.keys.PublicKeyXOnly/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.utils.sha256#1 coincurve.utils.sha256/operation/builtins.bytes/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.utils.get_valid_secret#0 coincurve.utils.get_valid_secret/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.utils.verify_signature#3 coincurve.utils.verify_signature/operation/builtins.bool/high/builtins.bytes|builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
		"coincurve.verify_signature#3 coincurve.verify_signature/operation/builtins.bool/high/builtins.bytes|builtins.bytes|builtins.bytes/-/params=-/varargs=false/when=-/lib=coincurve",
	}
	sort.Strings(want)

	got := loadedCoincurveContracts(t)
	if len(got) != len(want) {
		t.Errorf("contract count = %d, want %d", len(got), len(want))
	}
	longest := len(got)
	if len(want) > longest {
		longest = len(want)
	}
	for i := 0; i < longest; i++ {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			t.Errorf("line %d:\n  got  %s\n  want %s", i, g, w)
		}
	}
}

// TestPythonCoincurveContract_LibraryBlock renders the `library:` block, which
// the exact-set test above cannot see. Measured twice on this campaign:
// corrupting `version_range`, `coordinates`, `name` or `description` leaves
// every per-contract assertion green because those fields are parsed and then
// never consulted by any other test.
func TestPythonCoincurveContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "coincurve.yaml"))
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
	if kb.Library.Name != coincurveLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, coincurveLibrary)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "coincurve"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// The committed CSV range is 4.1.3 - 21.0.0. The lower bound is 4.1.3 and
	// not 4.4.0 even though 4.1.3 publishes no sdist: the API was read from the
	// 4.1.3 wheel, where every symbol this contract declares except
	// combine_keys, sign_schnorr and PublicKeyXOnly is already present.
	if got, want := kb.Library.VersionRange, ">=4.1.3,<22"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if !strings.Contains(kb.Library.Description, "libsecp256k1") {
		t.Errorf("library.description does not name the bound C library: %q", kb.Library.Description)
	}
}

// TestPythonCoincurveContract_KeysMeasuredOffTheGraph pins the exact keys an
// exported call graph emits for a consumer of this package, in both module
// spellings, read off `crypto-finder scan --export-callgraph` rather than
// written from the API. A key that is merely plausible loads without error and
// joins nothing, which looks identical to having no contract at all.
func TestPythonCoincurveContract_KeysMeasuredOffTheGraph(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	// Every key here was observed in an exported call graph, with the call
	// shape that produced it named beside it.
	cases := []struct {
		method string
		arity  int
		shape  string
	}{
		{"coincurve.PrivateKey.<init>", 1, "from coincurve import PrivateKey; PrivateKey(secret)"},
		{"coincurve.PrivateKey.sign", 1, "key.sign(message) after the above"},
		{"coincurve.PrivateKey.sign_schnorr", 1, "key.sign_schnorr(message)"},
		{"coincurve.PrivateKey.ecdh", 1, "key.ecdh(peer.format())"},
		{"coincurve.PublicKey.from_secret", 1, "PublicKey.from_secret(secret)"},
		{"coincurve.PublicKey.verify", 2, "pub.verify(signature, message)"},
		{"coincurve.PublicKeyXOnly.from_secret", 1, "PublicKeyXOnly.from_secret(secret)"},
		{"coincurve.PublicKeyXOnly.verify", 2, "xonly.verify(signature, message)"},
		{"coincurve.keys.PrivateKey", 1, "import coincurve.keys; coincurve.keys.PrivateKey(secret)"},
		{"coincurve.keys.PrivateKey.sign", 1, "the deep-module receiver, after the above"},
		{"coincurve.keys.PublicKey.from_secret", 1, "coincurve.keys.PublicKey.from_secret(secret)"},
		{"coincurve.keys.PublicKey.verify", 2, "the deep-module verify receiver"},
		{"coincurve.keys.PublicKeyXOnly.verify", 2, "the deep-module x-only verify receiver"},
		{"coincurve.utils.verify_signature", 3, "from coincurve.utils import verify_signature"},
		{"coincurve.verify_signature", 3, "from coincurve import verify_signature (root re-export)"},
		{"coincurve.utils.get_valid_secret", 0, "from coincurve.utils import get_valid_secret"},
		{"coincurve.ecdsa.recover", 2, "from coincurve.ecdsa import recover"},
	}

	for _, tc := range cases {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d does not resolve (call shape: %s)", tc.method, tc.arity, tc.shape)
			continue
		}
		if got[0].SourceLibrary != coincurveLibrary {
			t.Errorf("%s#%d resolved to library %q, want %q",
				tc.method, tc.arity, got[0].SourceLibrary, coincurveLibrary)
		}
	}
}

// TestPythonCoincurveContract_RootReExportIsNotInvented asserts the keys this
// contract deliberately does NOT declare, because declaring them would ship an
// entry matching code that cannot run.
//
// `coincurve/__init__.py` re-exports GLOBAL_CONTEXT, Context, PrivateKey,
// PublicKey, PublicKeyXOnly and verify_signature and nothing else, in all 29
// archives inspected (4.4.0 - 21.0.0 plus the 4.1.3 wheel). So
// `coincurve.get_valid_secret` and `coincurve.recover` resolve in no published
// release.
//
// The positive control matters here: `coincurve.utils.get_valid_secret` MUST
// resolve, or this test would pass just as well against an empty KB.
func TestPythonCoincurveContract_RootReExportIsNotInvented(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	if got := kb.ContractsForTolerant("coincurve.utils.get_valid_secret", 0); len(got) == 0 {
		t.Fatal("positive control failed: coincurve.utils.get_valid_secret does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, absent := range []string{
		"coincurve.get_valid_secret",
		"coincurve.recover",
		"coincurve.deserialize_recoverable",
	} {
		for _, c := range kb.ContractsForTolerant(absent, 0) {
			if c.SourceLibrary == coincurveLibrary {
				t.Errorf("%s resolves to a coincurve contract, but that name is not "+
					"re-exported from the package root in any published release", absent)
			}
		}
	}
}
