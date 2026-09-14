// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// renderEthAccountInventory renders every loaded eth-account contract as one
// line so the test below can compare the WHOLE SET against a literal rather
// than probing key by key.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. The rendering
// deliberately includes every field the loader populates -- role, return type,
// return confidence, canonical_return_type, parameter_types, varargs, and each
// parameter's index/name/role plus its contributed property and derivation --
// because a mutation to any one of them is a change to what this family
// CLAIMS. Varargs is rendered even though no entry sets it: a family measured
// that `Contract.Varargs` was rendered by no other test in this directory, so a
// `varargs: true` mutation survived every one of them.
func renderEthAccountInventory(kb *contracts.KnowledgeBase) []string {
	var inventory []string
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			contract := &candidates[i]
			if contract.SourceLibrary != "eth-account" {
				continue
			}
			line := fmt.Sprintf("%s#%d|%s|%s|%s|%s|%v|%v",
				contract.Method, contract.Arity, contract.Role,
				contract.Return.Type, contract.Return.Confidence,
				contract.CanonicalReturnType, contract.ParameterTypes, contract.Varargs)
			for j := range contract.Parameters {
				parameter := &contract.Parameters[j]
				index := -1
				if parameter.Index != nil {
					index = *parameter.Index
				}
				if parameter.Contributes == nil {
					line += fmt.Sprintf("|%d:%s:%s", index, parameter.Name, parameter.Role)
					continue
				}
				line += fmt.Sprintf("|%d:%s:%s:%s:%s", index, parameter.Name, parameter.Role,
					parameter.Contributes.Property, parameter.Contributes.Derivation)
			}
			inventory = append(inventory, line)
		}
	}
	sort.Strings(inventory)
	return inventory
}

// TestLoadEmbeddedPython_EthAccount_ExactSet pins the eth-account contract KB
// as an EXACT SET.
//
// WHAT THIS TEST DOES AND DOES NOT PROVE. It proves the loaded set is exactly
// what was authored, so any later edit that adds, drops or corrupts an entry
// fails here. It does NOT prove the authored values are TRUE: a mutation
// battery can only find drift away from a baseline, never an error inside it.
// The baseline's truth rests on a separate check -- every method and arity
// below was traced to eth-account's own source, and every version window was
// measured by parsing `Account`, `LocalAccount`, `messages` and `hdaccount` out
// of all 43 sdists the Tier 0 python CSV lists for this package. See the
// contract file's header for the citations.
func TestLoadEmbeddedPython_EthAccount_ExactSet(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	got := renderEthAccountInventory(kb)

	want := []string{
		"eth_account.Account.create#0|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[]|false",
		"eth_account.Account.create#1|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[typing.Union[str, bytes, int]]|false",
		"eth_account.Account.create_with_mnemonic#0|factory|builtins.tuple|high|typing.Tuple[eth_account.signers.LocalAccount, builtins.str]|[]|false",
		"eth_account.Account.create_with_mnemonic#1|factory|builtins.tuple|high|typing.Tuple[eth_account.signers.LocalAccount, builtins.str]|[]|false",
		"eth_account.Account.decrypt#2|operation|builtins.bytes|high|hexbytes.main.HexBytes|[typing.Union[builtins.str, typing.Dict[builtins.str, typing.Any]] builtins.str]|false",
		"eth_account.Account.encrypt#2|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[eth_account.types.PrivateKeyType builtins.str]|false",
		"eth_account.Account.encrypt#3|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[]|false|2:kdf:operation-determining",
		"eth_account.Account.encrypt#4|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[]|false|2:kdf:operation-determining|3:iterations:metadata-contributing:iterations:argument_value",
		"eth_account.Account.from_key#1|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[eth_account.types.PrivateKeyType]|false",
		"eth_account.Account.from_mnemonic#1|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[]|false",
		"eth_account.Account.from_mnemonic#2|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[]|false",
		"eth_account.Account.from_mnemonic#3|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[builtins.str builtins.str builtins.str]|false",
		"eth_account.Account.privateKeyToAccount#1|factory|eth_account.signers.LocalAccount|high|eth_account.signers.LocalAccount|[]|false",
		"eth_account.Account.recoverHash#2|output|builtins.str|high|eth_typing.evm.ChecksumAddress|[]|false",
		"eth_account.Account.recoverTransaction#1|output|builtins.str|high|eth_typing.evm.ChecksumAddress|[]|false",
		"eth_account.Account.recover_message#1|output|builtins.str|high|eth_typing.evm.ChecksumAddress|[]|false",
		"eth_account.Account.recover_message#2|output|builtins.str|high|eth_typing.evm.ChecksumAddress|[]|false",
		"eth_account.Account.recover_transaction#1|output|builtins.str|high|eth_typing.evm.ChecksumAddress|[]|false",
		"eth_account.Account.signHash#2|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.Account.signTransaction#2|operation|eth_account.datastructures.AttributeDict|low||[]|false",
		"eth_account.Account.sign_authorization#2|operation|eth_account.datastructures.SignedSetCodeAuthorization|low||[]|false",
		"eth_account.Account.sign_message#2|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.Account.sign_transaction#2|operation|eth_account.datastructures.SignedTransaction|low||[]|false",
		"eth_account.Account.sign_transaction#3|operation|eth_account.datastructures.SignedTransaction|low||[]|false",
		"eth_account.Account.sign_typed_data#2|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.Account.sign_typed_data#4|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.Account.unsafe_sign_hash#2|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.hdaccount.generate_mnemonic#2|factory|builtins.str|high|builtins.str|[builtins.int builtins.str]|false",
		"eth_account.hdaccount.key_from_seed#2|factory|builtins.bytes|high|builtins.bytes|[builtins.bytes builtins.str]|false",
		"eth_account.hdaccount.seed_from_mnemonic#2|factory|builtins.bytes|high|builtins.bytes|[builtins.str builtins.str]|false",
		"eth_account.messages.defunct_hash_message#1|output|builtins.bytes|high|hexbytes.main.HexBytes|[]|false",
		"eth_account.messages.encode_defunct#0|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_defunct#1|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_intended_validator#1|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_intended_validator#2|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_structured_data#1|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_typed_data#1|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.messages.encode_typed_data#3|factory|eth_account.messages.SignableMessage|high|eth_account.messages.SignableMessage|[]|false",
		"eth_account.signers.LocalAccount.encrypt#1|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[]|false",
		"eth_account.signers.LocalAccount.encrypt#2|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[]|false|1:kdf:operation-determining",
		"eth_account.signers.LocalAccount.encrypt#3|operation|builtins.dict|high|typing.Dict[builtins.str, typing.Any]|[]|false|1:kdf:operation-determining|2:iterations:metadata-contributing:iterations:argument_value",
		"eth_account.signers.LocalAccount.signHash#1|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.signers.LocalAccount.signTransaction#1|operation|eth_account.datastructures.AttributeDict|low||[]|false",
		"eth_account.signers.LocalAccount.sign_authorization#1|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.signers.LocalAccount.sign_message#1|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.signers.LocalAccount.sign_transaction#1|operation|eth_account.datastructures.SignedTransaction|low||[]|false",
		"eth_account.signers.LocalAccount.sign_transaction#2|operation|eth_account.datastructures.SignedTransaction|low||[]|false",
		"eth_account.signers.LocalAccount.sign_typed_data#1|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.signers.LocalAccount.sign_typed_data#3|operation|eth_account.datastructures.SignedMessage|low||[]|false",
		"eth_account.signers.LocalAccount.unsafe_sign_hash#1|operation|eth_account.datastructures.SignedMessage|low||[]|false",
	}

	// ONE assertion, reported as a symmetric difference. An earlier version of
	// this test mirrored the literal in TWO more places -- a separate length
	// check and a hardcoded role tally (factory=19, operation=25, output=6) --
	// so ADDING a real, present, crypto-relevant entry failed three times and
	// was indistinguishable from a regression. That is a test that rejects a
	// correct repair. The literal below is now the single place to edit, and
	// the message says which direction the difference is in.
	inWant := make(map[string]bool, len(want))
	for _, line := range want {
		inWant[line] = true
	}
	inGot := make(map[string]bool, len(got))
	for _, line := range got {
		inGot[line] = true
	}
	var unexpected, missing []string
	for _, line := range got {
		if !inWant[line] {
			unexpected = append(unexpected, line)
		}
	}
	for _, line := range want {
		if !inGot[line] {
			missing = append(missing, line)
		}
	}
	if len(unexpected) > 0 || len(missing) > 0 {
		t.Errorf("eth-account contract set differs (%d loaded, %d expected).\n"+
			"  loaded but not expected (%d):\n    %s\n"+
			"  expected but not loaded (%d):\n    %s\n"+
			"If you deliberately added or removed an entry, update the `want` "+
			"literal above -- it is the only place that needs changing.",
			len(got), len(want),
			len(unexpected), strings.Join(unexpected, "\n    "),
			len(missing), strings.Join(missing, "\n    "))
	}

	// Roles are checked against the VOCABULARY, not against a count. A tally
	// would be a third mirror of the same literal, and the set comparison
	// above already fails on any role change because role is a rendered field.
	valid := map[string]bool{"factory": true, "config": true, "operation": true, "output": true}
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary == "eth-account" && !valid[c.Role] {
				t.Errorf("%s#%d carries role %q, which is outside the whitelist",
					c.Method, c.Arity, c.Role)
			}
		}
	}
}

// TestLoadEmbeddedPython_EthAccount_LibraryBlock pins the library block, which
// the exact-set rendering above does not cover. version_range, coordinates,
// name and description are parsed and then never consulted by any other
// assertion, so corrupting one of them left every other test in this directory
// green on another family. LoadEmbedded merges every python KB and leaves
// kb.Library nil, so the block is read by loading this one file on its own.
func TestLoadEmbeddedPython_EthAccount_LibraryBlock(t *testing.T) {
	t.Parallel()

	// The library.name field is what populates SourceLibrary on every entry;
	// corrupting it empties the exact-set test as well as this one.
	kb := loadPythonKB(t)
	found := false
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "eth-account" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no contract carries SourceLibrary \"eth-account\"; the library.name field did not load")
	}

	data, err := os.ReadFile(filepath.Join("python", "eth-account.yaml"))
	if err != nil {
		t.Fatalf("read eth-account.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(eth-account.yaml): %v", err)
	}
	if single.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want \"2\"", single.SchemaVersion)
	}
	if single.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want \"python\"", single.Ecosystem)
	}
	if single.Library == nil {
		t.Fatal("library block did not load")
	}
	if single.Library.Name != "eth-account" {
		t.Errorf("library.name = %q, want \"eth-account\"", single.Library.Name)
	}
	// The range starts at 0.4.0 because that is the release where the
	// snake_case API, eth_account.messages and Account.encrypt's kdf argument
	// all arrive; every contracted symbol exists somewhere at or above it.
	if single.Library.VersionRange != ">=0.4.0,<1.0" {
		t.Errorf("library.version_range = %q, want \">=0.4.0,<1.0\"", single.Library.VersionRange)
	}
	wantCoordinates := []string{"eth-account", "eth_account"}
	if !slices.Equal(single.Library.Coordinates, wantCoordinates) {
		t.Errorf("library.coordinates = %#v, want %#v", single.Library.Coordinates, wantCoordinates)
	}
	if !strings.Contains(single.Library.Description, "EIP-191/EIP-712") {
		t.Errorf("library.description does not describe the covered surface: %q", single.Library.Description)
	}
}

// TestLoadEmbeddedPython_EthAccount_LocalAccountKeySpelling pins the module
// spelling that the FIRST authoring of this contract got wrong.
//
// `LocalAccount` is defined in eth_account/signers/local.py, so a consumer
// writes `from eth_account.signers.local import LocalAccount` -- but the Python
// parser keys a definition on its containing DIRECTORY and emits
// `eth_account.signers.LocalAccount.sign_message`, with the `local` FILE
// segment dropped. Authored with the import-path spelling, the entries loaded
// WITHOUT ERROR and joined nothing, which is indistinguishable from having no
// contract at all. The wrong spelling is asserted NOT to resolve so a future
// edit cannot quietly reintroduce it.
//
// `Account` lives in eth_account/account.py, a file directly under
// eth_account/, so for it the directory path and the import path coincide. The
// two spellings diverge only for a type nested one directory deeper, which is
// why this needed measuring rather than reasoning.
func TestLoadEmbeddedPython_EthAccount_LocalAccountKeySpelling(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	resolves := []struct {
		method string
		arity  int
	}{
		{"eth_account.signers.LocalAccount.sign_message", 1},
		{"eth_account.signers.LocalAccount.sign_transaction", 1},
		{"eth_account.signers.LocalAccount.sign_typed_data", 1},
		{"eth_account.signers.LocalAccount.unsafe_sign_hash", 1},
		{"eth_account.signers.LocalAccount.sign_authorization", 1},
		{"eth_account.signers.LocalAccount.signHash", 1},
		{"eth_account.signers.LocalAccount.signTransaction", 1},
		{"eth_account.signers.LocalAccount.encrypt", 1},
	}
	for _, tt := range resolves {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
		}
	}

	// The import-path spelling must NOT resolve.
	if got := kb.ContractsFor("eth_account.signers.local.LocalAccount.sign_message", 1); len(got) != 0 {
		t.Errorf("the import-path spelling resolved (%d contracts); the parser emits the "+
			"directory-path spelling and the two must not both be present", len(got))
	}

	// Every factory's declared return type must be the same spelling the
	// LocalAccount keys use, or the chain cannot walk from one to the other.
	for _, tt := range []struct {
		method string
		arity  int
	}{
		{"eth_account.Account.create", 0},
		{"eth_account.Account.create", 1},
		{"eth_account.Account.from_key", 1},
		{"eth_account.Account.from_mnemonic", 1},
		{"eth_account.Account.from_mnemonic", 2},
		{"eth_account.Account.from_mnemonic", 3},
		{"eth_account.Account.privateKeyToAccount", 1},
	} {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
		}
		if got[0].Return.Type != "eth_account.signers.LocalAccount" {
			t.Errorf("%s#%d returns %q, want eth_account.signers.LocalAccount",
				tt.method, tt.arity, got[0].Return.Type)
		}
	}
}

// TestLoadEmbeddedPython_EthAccount_UncontractedAPIsAreAbsent asserts that
// methods this family deliberately did NOT contract resolve to nothing. A
// contract for a symbol that does not exist in the declared version range, or
// for a non-crypto method, is a false declaration that nothing else here would
// catch: the exact-set test above would happily pin it.
func TestLoadEmbeddedPython_EthAccount_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	absent := []struct {
		method string
		arity  int
		why    string
	}{
		// Account.hashMessage exists ONLY in 0.1.0a1 and 0.1.0a2, both below
		// this contract's declared version_range of >=0.4.0.
		{"eth_account.Account.hashMessage", 1, "0.1.0a1-0.1.0a2 only, below the declared range"},
		// Configuration, not cryptography: returns None and flips a flag.
		{"eth_account.Account.enable_unaudited_hdwallet_features", 0, "non-crypto"},
		// Selects the eth-keys backend; that is eth-keys' surface, not this
		// family's.
		{"eth_account.Account.set_key_backend", 1, "belongs to eth-keys"},
		// Private, and never a consumer call site.
		{"eth_account.Account._sign_hash", 2, "private"},
		{"eth_account.Account._recover_hash", 2, "private"},
		// Properties, not calls.
		{"eth_account.signers.LocalAccount.address", 0, "a property"},
		{"eth_account.signers.LocalAccount.key", 0, "a property"},
	}
	for _, tt := range absent {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want 0 (%s)",
				tt.method, tt.arity, len(got), tt.why)
		}
	}
}

// TestLoadEmbeddedPython_EthAccount_ArityTolerance pins the Python name-only
// fallback for this family. Python keyword and default arguments mean the same
// call appears at several arities: Account.encrypt is contracted at 2, 3 and 4
// because the graph emitted all three, and a call at an arity no entry declares
// must still resolve by name to the LOWEST declared arity rather than to
// nothing.
func TestLoadEmbeddedPython_EthAccount_ArityTolerance(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	// Exact match wins.
	exact := kb.ContractsForTolerant("eth_account.Account.encrypt", 3)
	if len(exact) != 1 || exact[0].Arity != 3 {
		t.Fatalf("ContractsForTolerant(encrypt, 3) = %#v, want the arity-3 entry", exact)
	}
	// An undeclared arity falls back by name to the lowest declared one.
	fallback := kb.ContractsForTolerant("eth_account.Account.encrypt", 9)
	if len(fallback) != 1 || fallback[0].Arity != 2 {
		t.Fatalf("ContractsForTolerant(encrypt, 9) = %#v, want the arity-2 entry by name fallback", fallback)
	}
	// A method that is not in the KB at all must stay absent under the
	// fallback too -- the fallback widens arity, never the symbol set.
	if got := kb.ContractsForTolerant("eth_account.Account.hashMessage", 9); len(got) != 0 {
		t.Fatalf("ContractsForTolerant(hashMessage, 9) = %#v, want none", got)
	}
}
