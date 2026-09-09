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

// eth-keys is the common API for Ethereum secp256k1 key operations, and a thin
// layer over a pluggable ECC backend. Its contract is keyed in FIVE module
// spellings for the constructors because the Python call-graph key follows the
// CONSUMER'S IMPORT and the package exposes its types five documented ways:
//
//	from eth_keys.datatypes import PrivateKey   -> eth_keys.datatypes.PrivateKey.<init>
//	import eth_keys                             -> eth_keys.datatypes.PrivateKey
//	from eth_keys import keys                   -> eth_keys.keys.PrivateKey
//	from eth_keys import KeyAPI                 -> eth_keys.KeyAPI.PrivateKey
//	from eth_keys.main import KeyAPI            -> eth_keys.main.KeyAPI.PrivateKey
//
// and none resolves any other. Every key below was read off an exported call
// graph from a probe consumer built with THIS worktree's binary and re-exported
// until nothing moved; before the file existed the same probe emitted
// `consumer.pk.sign_msg(?)` and `consumer.api.ecdsa_sign(?, ?)` — keyed on the
// consumer's variable path, which no contract can join.
//
// THE RETURN TYPES ARE UNIFIED ONTO THE `eth_keys.datatypes.*` SPELLING, which
// is why each OPERATION appears once rather than once per constructor spelling.
// Verified by re-export: with every factory returning
// `eth_keys.datatypes.PrivateKey`, all five spellings above produce the single
// receiver key `eth_keys.datatypes.PrivateKey.sign_msg`.
//
// THIS IS A SYMMETRIC-DIFFERENCE COMPARISON, NOT A COUNT PLUS AN INDEX WALK.
// The campaign has shipped the mirror-test defect five times in four
// ecosystems: an exact-set test that compares lengths and then positions
// reports a one-line addition as a cascade of "wrong line N" errors and tells
// the reader nothing about which line to add. This one names what is MISSING
// and what is UNEXPECTED, and for an unexpected entry it prints the exact
// literal to paste, so a legitimate contract addition is a one-line edit here.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE
// IS TRUE. The baseline is traced to the package's own sources, per symbol, in
// the contract file's header: every method name here was resolved against the
// sdists of 0.1.0b1, 0.2.2, 0.2.3 and 0.8.0b1, and the seven symbols marked
// `>= 0.2.3` are exactly the seven that are absent at 0.2.2 and present at
// 0.2.3. Vacuity and truth are separate gates and this file is the first one.

const ethKeysLibrary = "eth-keys"

// renderEthKeysContract renders one loaded contract as a single line holding
// every field Load() populates. Anything omitted here is a field no mutation of
// which this test can detect — including `Varargs`, which no other rust or
// python exact-set test in this directory renders at all.
func renderEthKeysContract(key string, c contracts.Contract) string {
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

// loadedEthKeysContracts returns every rendered line for the eth-keys library,
// sorted. It fails if nothing was loaded at all: a zero-length set would make
// the "no unexpected entry" half of the comparison below pass vacuously, which
// is the failure mode this whole file exists to prevent.
func loadedEthKeysContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != ethKeysLibrary {
				continue
			}
			lines = append(lines, renderEthKeysContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no eth-keys contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

func TestPythonEthKeysContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := []string{
		"eth_keys.KeyAPI#0 eth_keys.KeyAPI/factory/eth_keys.main.KeyAPI/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.KeyAPI.<init>#0 eth_keys.KeyAPI.<init>/factory/eth_keys.main.KeyAPI/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.KeyAPI.NonRecoverableSignature#1 eth_keys.KeyAPI.NonRecoverableSignature/factory/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.KeyAPI.PrivateKey#1 eth_keys.KeyAPI.PrivateKey/factory/eth_keys.datatypes.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.KeyAPI.PublicKey#1 eth_keys.KeyAPI.PublicKey/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.KeyAPI.Signature#1 eth_keys.KeyAPI.Signature/factory/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.PublicKey.from_compressed_bytes#1 eth_keys.PublicKey.from_compressed_bytes/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.PublicKey.from_private#1 eth_keys.PublicKey.from_private/factory/eth_keys.datatypes.PublicKey/high/eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.PublicKey.recover_from_msg#2 eth_keys.PublicKey.recover_from_msg/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.PublicKey.recover_from_msg_hash#2 eth_keys.PublicKey.recover_from_msg_hash/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature#1 eth_keys.datatypes.NonRecoverableSignature/factory/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature.<init>#1 eth_keys.datatypes.NonRecoverableSignature.<init>/factory/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature.to_bytes#0 eth_keys.datatypes.NonRecoverableSignature.to_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature.to_hex#0 eth_keys.datatypes.NonRecoverableSignature.to_hex/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature.verify_msg#2 eth_keys.datatypes.NonRecoverableSignature.verify_msg/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.NonRecoverableSignature.verify_msg_hash#2 eth_keys.datatypes.NonRecoverableSignature.verify_msg_hash/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey#1 eth_keys.datatypes.PrivateKey/factory/eth_keys.datatypes.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.<init>#1 eth_keys.datatypes.PrivateKey.<init>/factory/eth_keys.datatypes.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.sign_msg#1 eth_keys.datatypes.PrivateKey.sign_msg/operation/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.sign_msg_hash#1 eth_keys.datatypes.PrivateKey.sign_msg_hash/operation/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.sign_msg_hash_non_recoverable#1 eth_keys.datatypes.PrivateKey.sign_msg_hash_non_recoverable/operation/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.sign_msg_non_recoverable#1 eth_keys.datatypes.PrivateKey.sign_msg_non_recoverable/operation/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.to_bytes#0 eth_keys.datatypes.PrivateKey.to_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PrivateKey.to_hex#0 eth_keys.datatypes.PrivateKey.to_hex/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey#1 eth_keys.datatypes.PublicKey/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.<init>#1 eth_keys.datatypes.PublicKey.<init>/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.from_compressed_bytes#1 eth_keys.datatypes.PublicKey.from_compressed_bytes/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.from_private#1 eth_keys.datatypes.PublicKey.from_private/factory/eth_keys.datatypes.PublicKey/high/eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.recover_from_msg#2 eth_keys.datatypes.PublicKey.recover_from_msg/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.recover_from_msg_hash#2 eth_keys.datatypes.PublicKey.recover_from_msg_hash/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_address#0 eth_keys.datatypes.PublicKey.to_address/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_bytes#0 eth_keys.datatypes.PublicKey.to_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_canonical_address#0 eth_keys.datatypes.PublicKey.to_canonical_address/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_checksum_address#0 eth_keys.datatypes.PublicKey.to_checksum_address/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_compressed_bytes#0 eth_keys.datatypes.PublicKey.to_compressed_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.to_hex#0 eth_keys.datatypes.PublicKey.to_hex/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.verify_msg#2 eth_keys.datatypes.PublicKey.verify_msg/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.PublicKey.verify_msg_hash#2 eth_keys.datatypes.PublicKey.verify_msg_hash/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature#1 eth_keys.datatypes.Signature/factory/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.<init>#1 eth_keys.datatypes.Signature.<init>/factory/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.recover_public_key_from_msg#1 eth_keys.datatypes.Signature.recover_public_key_from_msg/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.recover_public_key_from_msg_hash#1 eth_keys.datatypes.Signature.recover_public_key_from_msg_hash/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.to_bytes#0 eth_keys.datatypes.Signature.to_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.to_hex#0 eth_keys.datatypes.Signature.to_hex/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.to_non_recoverable_signature#0 eth_keys.datatypes.Signature.to_non_recoverable_signature/factory/eth_keys.datatypes.NonRecoverableSignature/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.verify_msg#2 eth_keys.datatypes.Signature.verify_msg/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.datatypes.Signature.verify_msg_hash#2 eth_keys.datatypes.Signature.verify_msg_hash/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.NonRecoverableSignature#1 eth_keys.keys.NonRecoverableSignature/factory/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.PrivateKey#1 eth_keys.keys.PrivateKey/factory/eth_keys.datatypes.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.PublicKey#1 eth_keys.keys.PublicKey/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.Signature#1 eth_keys.keys.Signature/factory/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.ecdsa_recover#2 eth_keys.keys.ecdsa_recover/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.ecdsa_sign#2 eth_keys.keys.ecdsa_sign/operation/eth_keys.datatypes.Signature/high/builtins.bytes|eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.ecdsa_sign_non_recoverable#2 eth_keys.keys.ecdsa_sign_non_recoverable/operation/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes|eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.ecdsa_verify#3 eth_keys.keys.ecdsa_verify/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.BaseSignature|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.keys.private_key_to_public_key#1 eth_keys.keys.private_key_to_public_key/factory/eth_keys.datatypes.PublicKey/high/eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI#0 eth_keys.main.KeyAPI/factory/eth_keys.main.KeyAPI/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.<init>#0 eth_keys.main.KeyAPI.<init>/factory/eth_keys.main.KeyAPI/high/-/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.NonRecoverableSignature#1 eth_keys.main.KeyAPI.NonRecoverableSignature/factory/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.PrivateKey#1 eth_keys.main.KeyAPI.PrivateKey/factory/eth_keys.datatypes.PrivateKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.PublicKey#1 eth_keys.main.KeyAPI.PublicKey/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.Signature#1 eth_keys.main.KeyAPI.Signature/factory/eth_keys.datatypes.Signature/high/builtins.bytes/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.ecdsa_recover#2 eth_keys.main.KeyAPI.ecdsa_recover/factory/eth_keys.datatypes.PublicKey/high/builtins.bytes|eth_keys.datatypes.Signature/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.ecdsa_sign#2 eth_keys.main.KeyAPI.ecdsa_sign/operation/eth_keys.datatypes.Signature/high/builtins.bytes|eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.ecdsa_sign_non_recoverable#2 eth_keys.main.KeyAPI.ecdsa_sign_non_recoverable/operation/eth_keys.datatypes.NonRecoverableSignature/high/builtins.bytes|eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.ecdsa_verify#3 eth_keys.main.KeyAPI.ecdsa_verify/operation/builtins.bool/high/builtins.bytes|eth_keys.datatypes.BaseSignature|eth_keys.datatypes.PublicKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.KeyAPI.private_key_to_public_key#1 eth_keys.main.KeyAPI.private_key_to_public_key/factory/eth_keys.datatypes.PublicKey/high/eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
		"eth_keys.main.PublicKey.from_private#1 eth_keys.main.PublicKey.from_private/factory/eth_keys.datatypes.PublicKey/high/eth_keys.datatypes.PrivateKey/-/params=-/varargs=false/when=-/lib=eth-keys",
	}

	got := loadedEthKeysContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, w := range want {
		wantSet[w] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, g := range got {
		gotSet[g] = struct{}{}
	}

	var missing, unexpected []string
	for _, w := range want {
		if _, ok := gotSet[w]; !ok {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if _, ok := wantSet[g]; !ok {
			unexpected = append(unexpected, g)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	for _, m := range missing {
		t.Errorf("contract entry MISSING from the loaded KB — the YAML no longer declares it:\n  %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("unexpected contract entry — if the YAML change is intended, add this one line to want:\n\t\t%q,", u)
	}
}

// TestPythonEthKeysContract_LibraryBlock renders the `library:` block, which
// the exact-set test above cannot see. Measured twice on this campaign:
// corrupting `version_range`, `coordinates`, `name` or `description` leaves
// every per-contract assertion green, because those fields are parsed and then
// never consulted by any other test.
func TestPythonEthKeysContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "eth-keys.yaml"))
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
	if kb.Library.Name != ethKeysLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, ethKeysLibrary)
	}
	// Both PEP 503 spellings: the distribution name and the import name. The
	// two differ for this package and a consumer PURL carries the first while
	// every key in this file carries the second.
	if got, want := strings.Join(kb.Library.Coordinates, ","), "eth-keys,eth_keys"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// The committed CSV range is 0.1.0b1 - 0.8.0b1, 23 rows. The upper bound is
	// open to 0.9 rather than pinned at 0.8.0b1 because 0.8.0 final adds and
	// removes no public symbol relative to 0.7.0 — read from both archives.
	if got, want := kb.Library.VersionRange, ">=0.1.0b1,<0.9"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if !strings.Contains(kb.Library.Description, "secp256k1") {
		t.Errorf("library.description does not name the curve: %q", kb.Library.Description)
	}
	if !strings.Contains(kb.Library.Description, "backend") {
		t.Errorf("library.description does not say this is a layer over a pluggable backend: %q", kb.Library.Description)
	}
}

// TestPythonEthKeysContract_KeysMeasuredOffTheGraph pins the exact keys an
// exported call graph emits for a consumer of this package, in every module
// spelling, read off `crypto-finder scan --export-callgraph` rather than
// written from the API. A key that is merely plausible loads without error and
// joins nothing, which looks identical to having no contract at all.
//
// The `eth_keys.PublicKey.from_private` row is the one worth reading twice: the
// `keys.PublicKey.from_private(pk)` and `KeyAPI.PublicKey.from_private(pk)`
// spellings both COLLAPSE one interior segment, and the segment they collapse
// to comes from the IMPORTING module rather than the defining one — so the same
// source line emits `eth_keys.PublicKey.from_private` under a root import and
// `eth_keys.main.PublicKey.from_private` under `from eth_keys.main import
// KeyAPI`. Both were measured and both are declared; reasoning would have
// produced one of them.
func TestPythonEthKeysContract_KeysMeasuredOffTheGraph(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	cases := []struct {
		method string
		arity  int
		shape  string
	}{
		{"eth_keys.datatypes.PrivateKey.<init>", 1, "from eth_keys.datatypes import PrivateKey; PrivateKey(secret)"},
		{"eth_keys.datatypes.PrivateKey", 1, "import eth_keys; eth_keys.datatypes.PrivateKey(secret)"},
		{"eth_keys.keys.PrivateKey", 1, "from eth_keys import keys; keys.PrivateKey(secret)"},
		{"eth_keys.KeyAPI.PrivateKey", 1, "from eth_keys import KeyAPI; KeyAPI.PrivateKey(secret)"},
		{"eth_keys.main.KeyAPI.PrivateKey", 1, "from eth_keys.main import KeyAPI; KeyAPI.PrivateKey(secret)"},
		{"eth_keys.datatypes.PrivateKey.sign_msg", 1, "the receiver, typed by any of the five factories above"},
		{"eth_keys.datatypes.PrivateKey.sign_msg_hash", 1, "key.sign_msg_hash(message_hash)"},
		{"eth_keys.datatypes.PublicKey.verify_msg", 2, "pub.verify_msg(message, signature)"},
		{"eth_keys.datatypes.Signature.verify_msg", 2, "sig.verify_msg(message, public_key)"},
		{"eth_keys.datatypes.NonRecoverableSignature.verify_msg", 2, "nrs.verify_msg(message, public_key)"},
		{"eth_keys.datatypes.Signature.recover_public_key_from_msg", 1, "sig.recover_public_key_from_msg(message)"},
		{"eth_keys.datatypes.PublicKey.recover_from_msg", 2, "PublicKey.recover_from_msg(message, sig)"},
		{"eth_keys.PublicKey.from_private", 1, "keys.PublicKey.from_private(pk) — one segment collapsed, root import"},
		{"eth_keys.main.PublicKey.from_private", 1, "KeyAPI.PublicKey.from_private(pk) under `from eth_keys.main import KeyAPI`"},
		{"eth_keys.keys.ecdsa_sign", 2, "keys.ecdsa_sign(message_hash, pk) — the lazy_key_api instance"},
		{"eth_keys.main.KeyAPI.ecdsa_sign", 2, "api = KeyAPI(); api.ecdsa_sign(message_hash, pk)"},
		{"eth_keys.KeyAPI.<init>", 0, "from eth_keys import KeyAPI; KeyAPI()"},
		{"eth_keys.main.KeyAPI", 0, "import eth_keys.main; eth_keys.main.KeyAPI()"},
	}

	for _, c := range cases {
		list := kb.ContractsFor(c.method, c.arity)
		if len(list) == 0 {
			t.Errorf("no contract for %s#%d — the call shape %q would resolve nothing",
				c.method, c.arity, c.shape)
		}
	}
}

// TestPythonEthKeysContract_NoBackendMethodIsClaimed is the wrong-package
// assertion, and it is the one this family most needs.
//
// eth-keys is a thin API over a pluggable backend. Its default backend is
// coincurve, whose contract is ALREADY in this same embedded KB, and
// `eth_keys/backends/coincurve.py` calls `sign`, `sign_recoverable`, `verify`
// and `from_signature_and_message` through a `self.keys = coincurve.keys`
// attribute (0.7.0 line 48). Declaring any of those under `lib=eth-keys` would
// attribute libsecp256k1's operations to the wrong distribution — the defect
// class this campaign punishes hardest — and no exact-set comparison states it
// as an intention, only as a list.
//
// The `BaseECCBackend` protocol names are checked in the same sweep: a consumer
// never calls a backend directly, because `KeyAPI` proxies every operation, so
// a backend method keyed under eth-keys would be an entry point nothing can
// reach.
func TestPythonEthKeysContract_NoBackendMethodIsClaimed(t *testing.T) {
	t.Parallel()

	// coincurve's own key/signature surface, and the backend protocol.
	forbidden := []string{
		"sign_recoverable",
		"sign_schnorr",
		"from_signature_and_message",
		"from_secret",
		"from_valid_secret",
		"combine_keys",
		"ecdh",
		"decompress_public_key_bytes",
		"compress_public_key_bytes",
		"get_backend",
		"get_backend_class",
		"get_default_backend_class",
		"is_coincurve_available",
	}

	got := loadedEthKeysContracts(t)
	var offenders []string
	for _, line := range got {
		key := strings.Fields(line)[0]
		method := key
		if i := strings.LastIndex(key, "#"); i >= 0 {
			method = key[:i]
		}
		last := method
		if i := strings.LastIndex(method, "."); i >= 0 {
			last = method[i+1:]
		}
		for _, f := range forbidden {
			if last == f {
				offenders = append(offenders, key)
			}
		}
	}
	if len(offenders) > 0 {
		t.Errorf("eth-keys contract claims a backend or coincurve method: %v", offenders)
	}

	// The positive control: a bare `verify` would be coincurve's spelling and
	// this package's is `verify_msg`. If the sweep above ever stopped seeing
	// method names at all, it would report clean, so assert that the eth-keys
	// spelling IS present.
	found := false
	for _, line := range got {
		if strings.HasPrefix(line, "eth_keys.datatypes.PublicKey.verify_msg#2 ") {
			found = true
		}
		if strings.Contains(line, ".verify#") {
			t.Errorf("eth-keys contract declares a bare `verify`, which is coincurve's spelling: %s", line)
		}
	}
	if !found {
		t.Error("eth_keys.datatypes.PublicKey.verify_msg#2 is not in the loaded set — the sweep above proves nothing")
	}
}
