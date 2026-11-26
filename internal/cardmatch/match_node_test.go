// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// The entries and calls below are invented: "acme-crypto" is not a real
// library and none of them comes from a ruleset.

// nodeAssets loads index entries given as JSON objects, as an exported index
// carries them (rule_id and metadata included).
func nodeAssets(t *testing.T, entries ...string) *Assets {
	t.Helper()
	var ix Index
	if err := json.Unmarshal([]byte(`{"entries": [`+strings.Join(entries, ",")+`]}`), &ix); err != nil {
		t.Fatal(err)
	}
	if err := ix.validateNode(); err != nil {
		t.Fatal(err)
	}
	ix.prepare()
	return &Assets{index: &ix, cards: &CardSet{RuleIDs: map[string]bool{}}}
}

// call is one external call of the test fragment, in the caller
// "src/app.<module>" of file src/app.js unless caller is set.
type call struct {
	line, col, endCol     int
	key, method, raw      string
	recv, assigned, chain string
	caller                string
	args                  []string
	resolved              map[int]string
	noArgs                bool
}

func nodeFragment(calls ...call) *FragmentJSON {
	f := &FragmentJSON{}
	f.ScanMetadata.Ecosystem = ecosystemNode
	f.Functions = []FunctionJSON{
		{Key: "src/app.<module>", Package: "src/app", FilePath: "src/app.js"},
		{Key: "src/app.run", Package: "src/app", FilePath: "src/app.js"},
	}
	for _, c := range calls {
		line, col := c.line, c.col
		endCol := c.endCol
		if endCol == 0 {
			endCol = col + 40
		}
		e := ExternalJSON{
			CallerKey: "src/app.<module>", TargetKey: c.key, MethodName: c.method, Raw: c.raw, Line: &line,
			StartCol: &col, EndCol: &endCol, ReceiverVar: c.recv, AssignedVar: c.assigned, ChainID: c.chain, Resolution: "exact",
		}
		if c.caller != "" {
			e.CallerKey = c.caller
		}
		if !c.noArgs {
			e.EntryCall = &CallSiteJSON{Parameters: []Param{}}
			for i, a := range c.args {
				e.EntryCall.Parameters = append(e.EntryCall.Parameters, Param{ParameterIndex: i, ArgumentExpression: a, ResolvedValue: c.resolved[i]})
			}
		}
		f.ExternalCalls = append(f.ExternalCalls, e)
	}
	return f
}

// nodeLines are findings as rule@line, the focus argument and the filled
// metadata.
func nodeLines(found []*Finding) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		s := fmt.Sprintf("%s@%d %s", f.RuleID, f.Line, jsonValue(f.Metadata))
		if f.FocusArg != nil {
			s += fmt.Sprintf(" focus=%d:%s", *f.FocusArg, f.FocusText)
		}
		out = append(out, s)
	}
	return out
}

func checkNode(t *testing.T, a *Assets, frag *FragmentJSON, want ...string) {
	t.Helper()
	found, _ := a.mustMatch(t, frag)
	got := nodeLines(found)
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
}

const encryptEntry = `{"rule_id": "enc", "metadata": {"algorithmName": "$algo", "mode": "$MODE"},
	"callee": {"bind": "import", "modules": ["acme-crypto", "node:acme-crypto"], "path": "cipher.encrypt"},
	"method": "encrypt", "min_arity": 2, "max_arity": 2, "arg_pattern": "$DATA, {..., alg: $ALG, mode: $MODE, ...}",
	"constraints": [{"metavar": "$ALG", "regex": "^\"(?P<algo>AES|DES)\"$"}]}`

// An import callee: the full key of any of its modules, the arguments
// unified, the constraint read on the bound text and its groups filled in.
func TestNodeImportCallee(t *testing.T) {
	a := nodeAssets(t, encryptEntry)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "AES", mode: CBC }`}},
		call{line: 2, col: 1, key: "node:acme-crypto.cipher.encrypt", method: "encrypt", raw: "(0, A.encrypt)", args: []string{"data", `{mode: "GCM", alg: "DES", iv}`}},
		// Wrong algorithm, missing key, wrong arity, other module.
		call{line: 3, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "RC4", mode: CBC }`}},
		call{line: 4, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "AES" }`}},
		call{line: 5, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data"}},
		call{line: 6, col: 1, key: "other.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "AES", mode: CBC }`}},
		// A spread may hold the key: Unknown is no match.
		call{line: 7, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ ...opts, mode: CBC }`}},
		// The arguments are not listed: no match for a pattern that reads them.
		call{line: 8, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", noArgs: true},
	),
		`enc@1 {"algorithmName": "AES", "mode": "CBC"}`,
		`enc@2 {"algorithmName": "DES", "mode": "GCM"}`,
	)
}

// A constraint falls back on the literal reach resolved the bound name to,
// and a string pattern matches a name that resolves to that string.
func TestNodeResolvedLiterals(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "hash", "metadata": {"algorithmName": "$H"}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "hash"},
		"method": "hash", "min_arity": 1, "max_arity": 1, "arg_pattern": "$H", "constraints": [{"metavar": "$H", "regex": "^\"sha"}]}`,
		`{"rule_id": "md5", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "hash"},
		"method": "hash", "min_arity": 1, "max_arity": 1, "arg_pattern": "\"md5\""}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{"ALG"}, resolved: map[int]string{0: `"sha256"`}},
		call{line: 2, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{"weak"}, resolved: map[int]string{0: `"md5"`}},
		call{line: 3, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{"other"}},
	),
		`hash@1 {"algorithmName": "sha256"}`,
		`md5@2 {}`,
	)
}

// A constraint on a bound literal reads the literal as written, quotes and
// all, as OpenGrep does: the value reach resolved it to (unquoted) is not
// tried, or a regex that excludes the quoted names would accept it.
func TestNodeLiteralConstraintReadsTheText(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "dynamic", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "hash"},
		"method": "hash", "min_arity": 1, "max_arity": 1, "arg_pattern": "$H",
		"constraints": [{"metavar": "$H", "regex": "^(?!(?i:[\"'](?:md5|sha256)[\"'])$).+"}]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{`'sha256'`}, resolved: map[int]string{0: "sha256"}},
		call{line: 2, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{`"MD5"`}, resolved: map[int]string{0: "MD5"}},
		call{line: 3, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{`'sm3'`}, resolved: map[int]string{0: "sm3"}},
		call{line: 4, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{"algo"}},
	),
		`dynamic@3 {}`,
		`dynamic@4 {}`,
	)
	// The quote the source uses is the one the regex sees.
	b := nodeAssets(t,
		`{"rule_id": "single", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "hash"},
		"method": "hash", "min_arity": 1, "max_arity": 1, "arg_pattern": "$H", "constraints": [{"metavar": "$H", "regex": "^'sha256'$"}]}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{`'sha256'`}},
		call{line: 2, col: 1, key: "acme-crypto.hash", method: "hash", raw: "h.hash", args: []string{`"sha256"`}},
	),
		`single@1 {}`,
	)
}

// A path regex binds its groups under one of the modules; a local regex
// reads the name the call is written with.
func TestNodePathAndLocalRegex(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "rx", "metadata": {"family": "$FAM"}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P<FAM>[^.()]+)\\.sign$"},
		"method": "sign", "min_arity": 0, "max_arity": null, "constraints": [{"metavar": "$FAM", "regex": "^(ed|ec)"}]}`,
		`{"rule_id": "local", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(default).<init>", "new": true, "local_regex": "^Acme"},
		"method": "<init>", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.ed25519.sign", method: "sign", raw: "acme.ed25519.sign"},
		call{line: 2, col: 1, key: "acme-crypto.rsa.sign", method: "sign", raw: "acme.rsa.sign"},
		call{line: 3, col: 1, key: "acme-crypto.a.ec.sign", method: "sign", raw: "acme.a.ec.sign"},
		call{line: 4, col: 1, key: "acme-crypto.(default).<init>", method: "<init>", raw: "new AcmeCipher"},
		call{line: 5, col: 1, key: "acme-crypto.(default).<init>", method: "<init>", raw: "new Other"},
	),
		`rx@1 {"family": "ed25519"}`,
		`local@4 {}`,
	)
	// local_first: the call is written with the local name the destructured
	// binding gave the export it names (`const { $NS } = require(m); $NS.f()`),
	// not through a namespace binding of the module.
	b := nodeAssets(t,
		`{"rule_id": "first", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P<NS>[^.()]+)\\.create$", "local_first": true},
		"method": "create", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.hmac.create", method: "create", raw: "hmac.create"},
		call{line: 2, col: 1, key: "acme-crypto.pss.create", method: "create", raw: "acme.pss.create"},
	),
		`first@1 {}`,
	)
}

// A global callee is reach's own interface key; a written callee is an
// unbound call written as the rule writes it.
func TestNodeGlobalAndWritten(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "digest", "metadata": {}, "callee": {"bind": "global", "path": "(SubtleCrypto).digest"},
		"method": "digest", "min_arity": 1, "max_arity": null, "arg_pattern": "\"SHA-1\", ..."}`,
		`{"rule_id": "written", "metadata": {}, "callee": {"bind": "written", "path": "acme.createCipher"},
		"method": "createCipher", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "written-new", "metadata": {}, "callee": {"bind": "written", "path": "acme.Cipher", "new": true},
		"method": "Cipher", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "(SubtleCrypto).digest", method: "digest", raw: "crypto.subtle.digest", args: []string{`"SHA-1"`, "data"}},
		call{line: 2, col: 1, key: "(SubtleCrypto).digest", method: "digest", raw: "crypto.subtle.digest", args: []string{`"SHA-256"`, "data"}},
		// Unbound: the caller's own module path and the name.
		call{line: 3, col: 1, key: "src/app.createCipher", method: "createCipher", raw: "acme . createCipher"},
		call{line: 4, col: 1, key: "src/app.Cipher", method: "Cipher", raw: "new acme.Cipher"},
		// Bound to an import: still the written spelling, which OpenGrep reads
		// on the text.
		call{line: 5, col: 1, key: "other.createCipher", method: "createCipher", raw: "acme.createCipher"},
		// Unbound but written otherwise.
		call{line: 6, col: 1, key: "src/app.createCipher", method: "createCipher", raw: "x.createCipher"},
		call{line: 7, col: 1, key: "src/app.Cipher", method: "Cipher", raw: "acme.Cipher"},
	),
		`digest@1 {}`,
		`written@3 {}`,
		`written-new@4 {}`,
		`written@5 {}`,
	)
	// A written spelling under a branch's import guard needs the import.
	c := nodeAssets(t,
		`{"rule_id": "guarded", "metadata": {}, "callee": {"bind": "written", "path": "Signer", "new": true, "modules": ["acme-sig"]},
		"method": "Signer", "min_arity": 0, "max_arity": null}`,
	)
	fr := nodeFragment(call{line: 2, col: 1, key: "other-sig.(Signer).<init>", method: "<init>", raw: "new Signer"})
	checkNode(t, c, fr)
	fr.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {{Line: 1, Module: "acme-sig", Alias: "ns"}}}
	checkNode(t, c, fr, `guarded@2 {}`)
	// A global callee the rule writes out is matched only as written: reach
	// gives every spelling of the global crypto object the same key.
	b := nodeAssets(t,
		`{"rule_id": "uuid", "metadata": {}, "callee": {"bind": "global", "path": "(Crypto).randomUUID", "written": "crypto.randomUUID"},
		"method": "randomUUID", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "uuid-any", "metadata": {}, "callee": {"bind": "global", "path": "(Crypto).randomUUID", "written": "$W.crypto.randomUUID"},
		"method": "randomUUID", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "(Crypto).randomUUID", method: "randomUUID", raw: "crypto.randomUUID"},
		call{line: 2, col: 1, key: "(Crypto).randomUUID", method: "randomUUID", raw: "window.crypto.randomUUID"},
	),
		`uuid@1 {}`,
		`uuid-any@2 {}`,
	)
}

const objectEntry = `{"rule_id": "update", "metadata": {"algorithmName": "$ALG"},
	"callee": {"bind": "object", "path": "update", "via": ["chain", "var"], "from": [
		{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "createHash"}, "method": "createHash",
		 "min_arity": 1, "max_arity": 1, "arg_pattern": "$ALG", "constraints": [{"metavar": "$ALG", "regex": "^\"sha"}]}]},
	"method": "update", "min_arity": 0, "max_arity": null}`

// An object callee: an unbound call of the method on what a matching
// producer made, through a variable or a chain.
func TestNodeObjectCallee(t *testing.T) {
	a := nodeAssets(t, objectEntry)
	checkNode(t, a, nodeFragment(
		// Through a variable: h is what createHash made.
		call{line: 1, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "h", args: []string{`"sha256"`}},
		call{line: 2, col: 1, key: "src/app.update", method: "update", raw: "h.update", recv: "h", args: []string{"x"}},
		// Through a chain: update called on createHash's result.
		call{line: 3, col: 1, endCol: 25, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", chain: "7", args: []string{`"sha1"`}},
		call{line: 3, col: 1, endCol: 35, key: "src/app.update", method: "update", raw: `acme.createHash("sha1").update`, chain: "7", args: []string{"x"}},
		// The producer's argument fails its constraint.
		call{line: 4, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "m", args: []string{`"md5"`}},
		call{line: 5, col: 1, key: "src/app.update", method: "update", raw: "m.update", recv: "m", args: []string{"x"}},
		// h is assigned again before the call: the last assignment counts.
		call{line: 6, col: 11, key: "other.make", method: "make", raw: "other.make", assigned: "h"},
		call{line: 7, col: 1, key: "src/app.update", method: "update", raw: "h.update", recv: "h", args: []string{"x"}},
		// Another function's variable is not this one's.
		call{line: 8, col: 1, key: "src/app.update", method: "update", raw: "m2.update", recv: "h", caller: "src/app.run", args: []string{"x"}},
	),
		`update@2 {"algorithmName": "sha256"}`,
		`update@3 {"algorithmName": "sha1"}`,
	)
}

// not_calls negate the site when their argument pattern unifies; an Unknown
// verdict is no hit. not_imports suppress a file that imports a module
// before the site; a fragment without imports never does.
func TestNodeNots(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "gen", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "generate"},
		"method": "generate", "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., size: $N, ...}",
		"not_calls": [{"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., size: 4096, ...}"},
		              {"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., ...$REST, ...}"}],
		"not_imports": ["acme-legacy"]}`,
	)
	frag := nodeFragment(
		call{line: 3, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: 1024 }"}},
		call{line: 4, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: 4096 }"}},
		call{line: 5, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: 2048, ...defaults }"}},
		call{line: 9, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: 1024 }"}},
	)
	checkNode(t, a, frag, `gen@3 {}`, `gen@9 {}`)
	frag.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {{Line: 8, Module: "acme-legacy"}}}
	checkNode(t, a, frag, `gen@3 {}`)
}

// A not_calls entry with exceptions negates the calls its pattern matches
// and none of its exceptions does: a pattern-not written as a formula.
func TestNodeNotsWithExceptions(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "gen", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "generate"},
		"method": "generate", "min_arity": 0, "max_arity": null,
		"not_calls": [{"min_arity": 2, "max_arity": null, "arg_pattern": "$ATTRS, {...}, ...",
		               "not_calls": [{"min_arity": 2, "max_arity": null, "arg_pattern": "$ATTRS, {..., algorithm: $ALG, ...}, ..."}]}]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"attrs", "{ days: 365 }"}},
		call{line: 2, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"attrs", `{ algorithm: "sha256" }`}},
		call{line: 3, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"attrs"}},
	),
		`gen@2 {}`,
		`gen@3 {}`,
	)
	// A not_calls entry's constraints must hold for it to negate.
	b := nodeAssets(t,
		`{"rule_id": "size", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "generate"},
		"method": "generate", "min_arity": 0, "max_arity": null,
		"not_calls": [{"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., size: $BITS, ...}", "constraints": [{"metavar": "$BITS", "regex": "^\\d+$"}]}]}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: 2048 }"}},
		call{line: 2, col: 1, key: "acme-crypto.generate", method: "generate", raw: "g.generate", args: []string{"{ size: bits }"}},
	),
		`size@2 {}`,
	)
	// A negation reads the arguments as written: a name reach resolves to a
	// number is not a number there, nor a string pattern's string.
	c := nodeAssets(t,
		`{"rule_id": "kdf", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "derive"},
		"method": "derive", "min_arity": 0, "max_arity": null,
		"not_calls": [{"min_arity": 2, "max_arity": 2, "arg_pattern": "$PW, $N", "constraints": [{"metavar": "$N", "regex": "^[0-9]+$"}]},
		              {"min_arity": 1, "max_arity": 1, "arg_pattern": "\"weak\""}]}`,
	)
	checkNode(t, c, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.derive", method: "derive", raw: "k.derive", args: []string{"pw", "1024"}},
		call{line: 2, col: 1, key: "acme-crypto.derive", method: "derive", raw: "k.derive", args: []string{"pw", "N"}, resolved: map[int]string{1: "1024"}},
		call{line: 3, col: 1, key: "acme-crypto.derive", method: "derive", raw: "k.derive", args: []string{`"weak"`}},
		call{line: 4, col: 1, key: "acme-crypto.derive", method: "derive", raw: "k.derive", args: []string{"W"}, resolved: map[int]string{0: `"weak"`}},
	),
		`kdf@2 {}`,
		`kdf@4 {}`,
	)
}

// A consumer: the draw counts only where a call of the named callee takes
// it at the argument index, inline or through the variable it is assigned to.
func TestNodeConsumers(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "iv", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "random"},
		"method": "random", "min_arity": 0, "max_arity": null,
		"consumers": [{"via": "var", "callee_regex": "^(?:[\\w$]+\\.)?seal$", "arg_pattern": "$A, $K, $MAT, ...", "use": "$MAT"},
		              {"via": "inline", "callee_regex": "^(?:[\\w$]+\\.)?seal$", "arg_pattern": "$A, $K, $DRAW, ...", "use": "$DRAW"},
		              {"via": "var", "method_regex": "^(?:encrypt)$", "arg_pattern": "{..., iv: $MAT, ...}, ...", "use": "$MAT"}]}`,
	)
	checkNode(t, a, nodeFragment(
		// Through a variable: iv at index 2 of a later seal call.
		call{line: 1, col: 1, key: "acme-crypto.random", method: "random", raw: "acme.random", assigned: "iv", args: []string{"16"}},
		call{line: 2, col: 1, key: "acme-crypto.seal", method: "seal", raw: "acme.seal", args: []string{`"aes"`, "key", "iv"}},
		// Assigned to the key, not the iv: no finding.
		call{line: 3, col: 1, key: "acme-crypto.random", method: "random", raw: "acme.random", assigned: "key", args: []string{"32"}},
		// Inline at index 2.
		call{line: 5, col: 1, key: "acme-crypto.random", method: "random", raw: "acme.random", args: []string{"12"}},
		call{line: 5, col: 1, key: "acme-crypto.seal", method: "seal", raw: "seal", args: []string{`"aes"`, "k", "acme.random(12)"}},
		// Used by another callee: no finding.
		call{line: 7, col: 1, key: "acme-crypto.random", method: "random", raw: "acme.random", assigned: "salt", args: []string{"16"}},
		call{line: 8, col: 1, key: "acme-crypto.derive", method: "derive", raw: "acme.derive", args: []string{"pw", "x", "salt"}},
		// A property of an object argument of a method the regex names.
		call{line: 9, col: 1, key: "acme-crypto.random", method: "random", raw: "acme.random", assigned: "nonce", args: []string{"12"}},
		call{line: 10, col: 1, key: "(SubtleCrypto).encrypt", method: "encrypt", raw: "crypto.subtle.encrypt", args: []string{"{ name: 'AES-GCM', iv: nonce }", "k", "d"}},
	),
		`iv@1 {}`,
		`iv@5 {}`,
		`iv@9 {}`,
	)
	// A receiver consumer: the site's result receives the consumer's call,
	// through a variable or a chain, with the consumer's own constraints.
	b := nodeAssets(t,
		`{"rule_id": "pss", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "createSign"},
		"method": "createSign", "min_arity": 0, "max_arity": null,
		"consumers": [{"via": "receiver", "method_regex": "^sign$", "arg_pattern": "{..., padding: $PAD, ...}, ...",
		               "constraints": [{"metavar": "$PAD", "regex": ".*PSS"}]}]}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.createSign", method: "createSign", raw: "acme.createSign", assigned: "s", args: []string{"'sha256'"}},
		call{line: 2, col: 1, key: "acme-crypto.(Sign).sign", method: "sign", raw: "s.sign", recv: "s", args: []string{"{ key, padding: acme.PSS }"}},
		call{line: 3, col: 1, key: "acme-crypto.createSign", method: "createSign", raw: "acme.createSign", assigned: "t", args: []string{"'sha256'"}},
		call{line: 4, col: 1, key: "acme-crypto.(Sign).sign", method: "sign", raw: "t.sign", recv: "t", args: []string{"{ key, padding: acme.PKCS1 }"}},
		// A chain with a link between: createSign(..).update(..).sign(..).
		call{line: 5, col: 1, key: "acme-crypto.createSign", method: "createSign", raw: "acme.createSign", chain: "c1", args: []string{"'sha256'"}, endCol: 30},
		call{line: 5, col: 1, key: "acme-crypto.(Sign).update", method: "update", raw: "acme.createSign('sha256').update", chain: "c1", args: []string{"d"}, endCol: 40},
		call{line: 5, col: 1, key: "acme-crypto.(Sign).sign", method: "sign", raw: "acme.createSign('sha256').update(d).sign", chain: "c1", args: []string{"{ padding: acme.PSS }"}, endCol: 60},
	),
		`pss@1 {}`,
		`pss@5 {}`,
	)
}

// pattern-not-regex: no finding where the regex is found in the call's
// text, callee and arguments as written.
func TestNodeNotRegexes(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "kdf", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "derive"},
		"method": "derive", "min_arity": 0, "max_arity": null, "not_regexes": ["\\bc\\s*:\\s*\\d"]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.derive", method: "derive", raw: "derive", args: []string{"pw", "{ c: 600000 }"}},
		call{line: 2, col: 1, key: "acme-crypto.derive", method: "derive", raw: "derive", args: []string{"pw", "{ c: rounds }"}},
	),
		`kdf@2 {}`,
	)
}

// A focus metavariable bound to a whole argument reports that argument.
func TestNodeFocus(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "key", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "importKey"},
		"method": "importKey", "min_arity": 2, "max_arity": null, "arg_pattern": "$FMT, $KEY, ...", "focus_metavar": "$KEY"}`,
		`{"rule_id": "inner", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "importKey"},
		"method": "importKey", "min_arity": 2, "max_arity": null, "arg_pattern": "$FMT, {..., k: $K, ...}, ...", "focus_metavar": "$K"}`,
	)
	found, _ := a.mustMatch(t, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.importKey", method: "importKey", raw: "a.importKey", args: []string{`"raw"`, "secret"}},
		call{line: 2, col: 1, key: "acme-crypto.importKey", method: "importKey", raw: "a.importKey", args: []string{`"raw"`, "{k: secret}"}},
	))
	got := nodeLines(found)
	want := []string{`key@1 {} focus=1:secret`, `key@2 {} focus=1:{k: secret}`, `inner@2 {}`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if found[2].FocusText != "secret" {
		t.Errorf("inner focus text = %q", found[2].FocusText)
	}
}

// reach v0.1.1 lists the arguments after a shift as one text: the list is
// read whole.
func TestNodeJoinedArguments(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "kdf", "metadata": {"len": "$LEN"}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "kdf"},
		"method": "kdf", "min_arity": 4, "max_arity": 4, "arg_pattern": "$PW, $SALT, $N, $LEN"}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.kdf", method: "kdf", raw: "a.kdf", args: []string{"pw", "salt", "1 << 14, 32"}},
	), `kdf@1 {"len": "32"}`)
}

// A node fragment is matched by node entries only, and a Java fragment never
// by node entries.
func TestNodeEntriesStayInTheirFront(t *testing.T) {
	a := nodeAssets(t, `{"rule_id": "java", "receiver": "none", "method": "encrypt", "min_arity": 0, "max_arity": null, "metadata": {}}`, encryptEntry)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "AES", mode: CBC }`}},
	), `enc@1 {"algorithmName": "AES", "mode": "CBC"}`)
	java := nodeFragment(call{line: 1, col: 1, key: "acme.Cipher.encrypt#1", method: "encrypt", raw: "encrypt", args: []string{"data", "opts"}})
	java.ScanMetadata.Ecosystem = "java"
	found, _ := a.mustMatch(t, java)
	if got := nodeLines(found); len(got) != 1 || !strings.HasPrefix(got[0], "java@1") {
		t.Errorf("java findings = %q", got)
	}
}

// Matching is deterministic: the same fragment gives the same findings in
// the same order, sites in fragment order and entries in index order.
func TestNodeDeterministic(t *testing.T) {
	a := nodeAssets(t, objectEntry, encryptEntry,
		`{"rule_id": "any", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P<P>.+)$"},
		"method": null, "min_arity": 0, "max_arity": null}`)
	frag := nodeFragment(
		call{line: 1, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "h", args: []string{`"sha256"`}},
		call{line: 2, col: 1, key: "src/app.update", method: "update", raw: "h.update", recv: "h", args: []string{"x"}},
		call{line: 3, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "A.cipher.encrypt", args: []string{"data", `{ alg: "AES", mode: CBC }`}},
	)
	first, _ := a.mustMatch(t, frag)
	want := []string{`any@1 {}`, `update@2 {"algorithmName": "sha256"}`, `enc@3 {"algorithmName": "AES", "mode": "CBC"}`, `any@3 {}`}
	for i := 0; i < 5; i++ {
		got, _ := a.mustMatch(t, frag)
		if !reflect.DeepEqual(nodeLines(got), want) || !reflect.DeepEqual(nodeLines(got), nodeLines(first)) {
			t.Fatalf("run %d: %q, want %q", i, nodeLines(got), want)
		}
	}
}

// nodeCallee splits reach's keys into owner and name.
func TestNodeCalleeKey(t *testing.T) {
	for key, want := range map[string]string{
		"acme-crypto.AES.encrypt":  "acme-crypto.AES|encrypt",
		"acme-crypto.x.(Y).<init>": "acme-crypto.x.Y|<init>",
		"(SubtleCrypto).digest":    "SubtleCrypto|digest",
		"hash.js.sha256":           "hash.js|sha256",
	} {
		_, name, _ := strings.Cut(want, "|")
		owner, got := nodeCallee(key, name)
		if owner+"|"+got != want {
			t.Errorf("nodeCallee(%q) = %s|%s, want %s", key, owner, got, want)
		}
	}
}

// End to end from rule YAML: the compiler's entries are what the matcher
// reads.
func TestNodeCompiledRule(t *testing.T) {
	dir := t.TempDir()
	rules := `rules:
- id: acme-cipher
  message: acme cipher
  severity: INFO
  languages: [javascript, typescript]
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: $algo
  patterns:
  - pattern-either:
    - pattern-inside: |
        $NS = require("acme-crypto")
        ...
    - pattern-inside: |
        import $NS from "acme-crypto"
        ...
  - pattern: |
      $NS.cipher.encrypt($DATA, {..., alg: $ALG, ...})
  - metavariable-regex:
      metavariable: $ALG
      regex: '^"(?P<algo>AES|DES)"$'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load("", "", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	checkNode(t, a, nodeFragment(
		call{line: 4, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "c.cipher.encrypt", args: []string{"data", `{alg: "DES"}`}},
		call{line: 5, col: 1, key: "acme-crypto.cipher.encrypt", method: "encrypt", raw: "c.cipher.encrypt", args: []string{"data", `{alg: "RC4"}`}},
	), `acme-cipher@4 {"assetType": "algorithm", "algorithmName": "DES"}`)
}

// A producer requires the argument it names to read a variable an earlier
// call of the same function assigned or destructured into, the call matching
// the producer (here a text callee: the callee as written, any binding).
func TestNodeProducers(t *testing.T) {
	gen := `{"callee": {"bind": "text", "path_regex": "^(?P<GEN>.+)$"}, "method": null, "min_arity": 1, "max_arity": null, "arg_pattern": "$TYPE, ...",
		"constraints": [{"metavar": "$GEN", "regex": "^(?:[\\w$]+\\.)?makePair$"}, {"metavar": "$TYPE", "regex": "^[\"'](?:x1)[\"']$"}]}`
	a := nodeAssets(t,
		`{"rule_id": "var", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "agree"}, "method": "agree",
		"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., privateKey: <... $K ...>, ...}",
		"producers": [{"use": "$K", "via": "var", "from": [`+gen+`]}]}`,
		`{"rule_id": "destructure", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "agree"}, "method": "agree",
		"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., privateKey: <... $K ...>, ...}",
		"producers": [{"use": "$K", "via": "destructure", "from": [`+gen+`]}]}`,
	)
	fr := nodeFragment(
		// alice = makePair('x1'), read through a property: var.
		call{line: 1, col: 15, key: "acme-crypto.makePair", method: "makePair", raw: "acme.makePair", assigned: "alice", args: []string{"'x1'"}},
		call{line: 2, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: alice.privateKey }"}},
		// const { priv } = makePair('x1'): destructure.
		call{line: 3, col: 18, key: "other.makePair", method: "makePair", raw: "makePair", args: []string{"'x1'"}},
		call{line: 4, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: priv }"}},
		// Another type: no finding.
		call{line: 5, col: 13, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "bob", args: []string{"'x2'"}},
		call{line: 6, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: bob }"}},
		// The variable read as a property name, not a variable: no finding.
		call{line: 7, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: x.alice }"}},
		// The producer in another function: no finding.
		call{line: 8, col: 15, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "carol", caller: "src/app.run", args: []string{"'x1'"}},
		call{line: 9, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: carol }"}},
		// The producer after the call: no finding.
		call{line: 10, col: 1, key: "acme-crypto.agree", method: "agree", raw: "agree", args: []string{"{ privateKey: dave }"}},
		call{line: 11, col: 14, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "dave", args: []string{"'x1'"}},
	)
	fr.SourceLines = map[string]map[int]string{"src/app.js": {3: "const { priv } = makePair('x1');"}}
	checkNode(t, a, fr, `var@2 {}`, `destructure@4 {}`)
}

func TestDestructuredNames(t *testing.T) {
	for before, want := range map[string][]string{
		"const { a, b: c, d = 1, ...e } = ": {"a", "c", "d", "e"},
		"  let {x} = await ":                {"x"},
		"const x = ":                        nil,
		"const { a: { b } } = ":             nil,
		"f({ a }) = ":                       nil,
	} {
		s := &Site{File: "f.js", Line: 1, Col: len(before) + 1, ColOK: true}
		got := destructuredNames(map[string]map[int]string{"f.js": {1: before + "g()"}}, s)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", before, got, want)
		}
	}
}

// destructuredNamesFullPrefix is destructuredNames before the window: the
// declaration matched against the whole text before the call.
func destructuredNamesFullPrefix(before string) []string {
	m := destructuringDecl.FindStringSubmatch(before)
	if m == nil {
		return nil
	}
	decl := strings.TrimLeft(m[0], ";{( \t\n\f\r")
	return destructuredNames(map[string]map[int]string{"f.js": {1: decl + "g()"}}, &Site{File: "f.js", Line: 1, Col: len(decl) + 1, ColOK: true})
}

// On a line longer than the window, a declaration inside it gives the names
// the whole-prefix match gave, including when the window starts exactly at
// the keyword (the character before it then decides) or just before it.
func TestDestructuredNamesLongLine(t *testing.T) {
	const decl = "const { a, b: c, ...e } = "
	filler := strings.Repeat("x=f(1);", 2000)
	for _, pad := range []string{";", "(", " ", "\t", "x", "$", "\v"} {
		// off is where the window starts, relative to the keyword.
		for off := -3; off <= 0; off++ {
			tail := strings.Repeat(" ", maxDestructuringDeclBytes-len(decl)+off)
			before := filler + pad + decl + tail
			s := &Site{File: "f.js", Line: 1, Col: len(before) + 1, ColOK: true}
			got := destructuredNames(map[string]map[int]string{"f.js": {1: before + "g()"}}, s)
			want := destructuredNamesFullPrefix(before)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("pad %q, window start %d from the keyword: got %v, want %v", pad, off, got, want)
			}
			if wantSome := pad != "x" && pad != "$" && pad != "\v"; wantSome != (want != nil) {
				t.Errorf("pad %q: whole-prefix names %v", pad, want)
			}
		}
	}
	// A declaration that starts before the window gives none.
	before := filler + ";" + decl + strings.Repeat(" ", maxDestructuringDeclBytes)
	s := &Site{File: "f.js", Line: 1, Col: len(before) + 1, ColOK: true}
	if got := destructuredNames(map[string]map[int]string{"f.js": {1: before + "g()"}}, s); got != nil {
		t.Errorf("declaration before the window: got %v", got)
	}
}

// BenchmarkDestructuredNamesLongLine reads the declaration before the last
// call of a one-line bundle. The read costs the window, not the line, so it
// does not grow with the line: over a bundle's calls that is linear, where
// matching the whole prefix was quadratic.
func BenchmarkDestructuredNamesLongLine(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			const call = "var{k}=g(1);"
			line := strings.Repeat(call, n)
			lines := map[string]map[int]string{"f.js": {1: line}}
			s := &Site{File: "f.js", Line: 1, Col: (n-1)*len(call) + len("var{k}=") + 1, ColOK: true}
			for i := 0; i < b.N; i++ {
				if got := destructuredNames(lines, s); len(got) != 1 {
					b.Fatalf("got %v", got)
				}
			}
		})
	}
}

// A consumer's producer: the consumer's argument must read the produced
// variable.
func TestNodeConsumerProducers(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "signer", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "createSigner"},
		"method": "createSigner", "min_arity": 0, "max_arity": null,
		"consumers": [{"via": "receiver", "method_regex": "^sign$", "arg_pattern": "<... $K ...>, ...",
		  "producers": [{"use": "$K", "via": "var", "from": [{"callee": {"bind": "text", "path_regex": "^(?P<GEN>.+)$"}, "method": null,
		    "min_arity": 1, "max_arity": null, "arg_pattern": "$TYPE, ...", "constraints": [{"metavar": "$TYPE", "regex": "^'x1'$"}]}]}]}]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 11, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "k", args: []string{"'x1'"}},
		call{line: 2, col: 11, key: "acme-crypto.createSigner", method: "createSigner", raw: "acme.createSigner", assigned: "s", args: []string{"'sha256'"}},
		call{line: 3, col: 1, key: "acme-crypto.(Signer).sign", method: "sign", raw: "s.sign", recv: "s", args: []string{"k.priv"}},
		call{line: 4, col: 11, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "j", args: []string{"'x2'"}},
		call{line: 5, col: 11, key: "acme-crypto.createSigner", method: "createSigner", raw: "acme.createSigner", assigned: "t", args: []string{"'sha256'"}},
		call{line: 6, col: 1, key: "acme-crypto.(Signer).sign", method: "sign", raw: "t.sign", recv: "t", args: []string{"j.priv"}},
	), `signer@2 {}`)
}

// not_entries: a call one of them matches (callee, arguments read as
// written, its producers) gives no finding.
func TestNodeNotEntries(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "sign", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "sign"}, "method": "sign",
		"min_arity": 2, "max_arity": 2, "arg_pattern": "$D, <... $K ...>",
		"not_entries": [{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "sign"}, "method": "sign", "min_arity": 2, "max_arity": 2,
		  "arg_pattern": "$D, <... $K ...>", "producers": [{"use": "$K", "via": "var", "from": [{"callee": {"bind": "text", "path_regex": "^(?P<GEN>.+)$"},
		    "method": null, "min_arity": 1, "max_arity": null, "arg_pattern": "$T, ...", "constraints": [{"metavar": "$T", "regex": "^'x1'$"}]}]}]}]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 11, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "k", args: []string{"'x1'"}},
		call{line: 2, col: 1, key: "acme-crypto.sign", method: "sign", raw: "acme.sign", args: []string{"'sha256'", "k"}},
		call{line: 3, col: 11, key: "acme-crypto.makePair", method: "makePair", raw: "makePair", assigned: "j", args: []string{"'x2'"}},
		call{line: 4, col: 1, key: "acme-crypto.sign", method: "sign", raw: "acme.sign", args: []string{"'sha256'", "j"}},
	), `sign@4 {}`)
}

// A literal entry: an object literal of the fragment, outermost or nested,
// in a file importing the module at or before it.
func TestNodeObjectLiterals(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "alg", "metadata": {}, "callee": {"bind": "literal", "modules": ["acme-crypto"]}, "method": null,
		"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg: \"x1\", ...}"}`,
	)
	fr := nodeFragment()
	fr.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {{Line: 2, Module: "acme-crypto"}}}
	fr.ObjectLiterals = map[string][]graphfrag.GraphFragmentObjectLiteral{"src/app.js": {
		// Before the import: no finding.
		{Line: 1, StartCol: 11, EndCol: 25, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>"},
		{Line: 3, StartCol: 11, EndCol: 25, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>"},
		// Another value: no finding.
		{Line: 4, StartCol: 11, EndCol: 25, Text: "{ alg: 'x2' }", CallerKey: "src/app.<module>"},
		// Nested, on the third line of the outer literal.
		{Line: 5, StartCol: 7, EndLine: 9, EndCol: 2, Text: "{\n  a: 1,\n  b: { c: 2,\n    d: { alg: \"x1\" } },\n}", CallerKey: "src/app.run"},
	}}
	checkNode(t, a, fr, `alg@3 {}`, `alg@8 {}`)
}

// Object literal sites: the outermost at the fragment's span, a nested one
// found in its source (quotes and separators normalised away), end exclusive.
func TestNodeObjectSiteSpans(t *testing.T) {
	src := "{\n  a: 'x', // {not}\n  b: [ { c: \"y}\" } ],\n}"
	sites := nodeObjectSites(map[string][]graphfrag.GraphFragmentObjectLiteral{"f.js": {
		{Line: 3, StartCol: 11, EndLine: 6, EndCol: 2, Text: src, CallerKey: "f.<module>"},
	}})
	type span struct{ line, col, endLine, endCol int }
	got := make([]span, 0, len(sites))
	for _, s := range sites {
		got = append(got, span{s.Line, s.Col, s.EndLine, s.EndCol})
	}
	want := []span{{3, 11, 6, 2}, {5, 8, 0, 19}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("spans: got %v, want %v", got, want)
	}
}

// A focus inside an object literal reports the value itself, on its own
// line, matched on whole words.
func TestNodeObjectLiteralFocus(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "allow", "metadata": {}, "callee": {"bind": "literal"}, "method": null, "min_arity": 1, "max_arity": 1,
		"arg_pattern": "{..., algs: [$X, $ALG], ...}", "constraints": [{"metavar": "$ALG", "regex": "^['\"]A128GCM['\"]$"}], "focus_metavar": "$ALG"}`,
	)
	fr := nodeFragment()
	fr.ObjectLiterals = map[string][]graphfrag.GraphFragmentObjectLiteral{"src/app.js": {
		{Line: 1, StartCol: 15, EndLine: 4, EndCol: 2, Text: "{\n  algs: ['A128GCMKW',\n    'A128GCM'],\n}", CallerKey: "src/app.<module>"},
	}}
	found, _ := a.mustMatch(t, fr)
	if len(found) != 1 || found[0].Line != 3 || found[0].Col != 5 || found[0].EndCol != 14 {
		t.Fatalf("focus: got %+v", found)
	}
}

// A finding strictly inside another of the same rule and file is dropped.
func TestDropSubmatches(t *testing.T) {
	f := func(rule string, line, col, endCol int) *Finding {
		return &Finding{RuleID: rule, File: "a.js", Line: line, LineOK: true, Col: col, ColOK: true, EndCol: endCol}
	}
	call, inner, other, same := f("r", 1, 5, 40), f("r", 1, 20, 35), f("s", 1, 20, 35), f("r", 1, 5, 40)
	got := dropSubmatches([]*Finding{call, inner, other, same})
	if len(got) != 3 || got[0] != call || got[1] != other || got[2] != same {
		t.Errorf("kept %+v", got)
	}
}

// A method reached through a property chain on a produced value: an object
// callee with props, its producer found by the variable that heads the
// callee text, in the function or (none there) at module level; and an
// instance-keyed import callee on a site reach left unbound, whose variable
// holds the instance the class's constructor makes.
func TestNodePropertyChainsOnProducedValues(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "props", "metadata": {}, "callee": {"bind": "object", "path": "sign", "props": "priv",
		  "from": [{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "gen"}, "method": "gen", "min_arity": 0, "max_arity": null}], "via": ["var"]},
		"method": "sign", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "inst", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(default).utils.hash"},
		"method": "hash", "min_arity": 0, "max_arity": null}`,
	)
	fr := nodeFragment(
		call{line: 1, col: 14, key: "acme-crypto.gen", method: "gen", raw: "acme.gen", assigned: "keys"},
		call{line: 2, col: 1, key: "src/app.sign", method: "sign", raw: "keys.priv.sign", args: []string{"m"}},
		// Another property: no finding.
		call{line: 3, col: 1, key: "src/app.sign", method: "sign", raw: "keys.pub.sign", args: []string{"m"}},
		// The module-level variable used in a function.
		call{line: 9, col: 1, key: "src/app.sign", method: "sign", raw: "keys.priv.sign", caller: "src/app.run", args: []string{"m"}},
		call{line: 4, col: 13, key: "acme-crypto.(default).<init>", method: "<init>", raw: "new Acme", assigned: "w"},
		call{line: 5, col: 1, key: "src/app.hash", method: "hash", raw: "w.utils.hash", args: []string{"d"}},
		// Not the instance: no finding.
		call{line: 6, col: 1, key: "src/app.hash", method: "hash", raw: "other.utils.hash", args: []string{"d"}},
	)
	checkNode(t, a, fr, `props@2 {}`, `props@9 {}`, `inst@5 {}`)
}

// A text callee headed by a metavariable reads the callee as written; its
// producer's regex groups fill the finding.
func TestNodeTextCalleeChainAndProducerGroups(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "signhash", "metadata": {"bits": "$bits"}, "callee": {"bind": "text", "path_regex": "^(?P<R>.+)\\.sign$"}, "method": "sign",
		"min_arity": 1, "max_arity": null, "arg_pattern": "$MD, ...",
		"producers": [{"use": "$MD", "via": "var", "from": [{"callee": {"bind": "text", "path_regex": "^(?P<NS>.+)\\.(?P<H>[^.()]+)\\.create$"},
		  "method": "create", "min_arity": 0, "max_arity": null, "constraints": [{"metavar": "$H", "regex": "^sha(?P<bits>256|512)$"}]}]}]}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 12, key: "acme-crypto.md.sha512.create", method: "create", raw: "acme.md.sha512.create", assigned: "md"},
		call{line: 2, col: 1, key: "src/app.sign", method: "sign", raw: "keys.priv.sign", args: []string{"md"}},
		call{line: 3, col: 12, key: "acme-crypto.md.md5.create", method: "create", raw: "acme.md.md5.create", assigned: "weak"},
		call{line: 4, col: 1, key: "src/app.sign", method: "sign", raw: "keys.priv.sign", args: []string{"weak"}},
	), `signhash@2 {"bits": "512"}`)
}

// An instance callee written as a path regex holds on an unbound site whose
// variable holds the class's instance; an object callee also takes a site
// reach keyed on a contract-typed instance.
func TestNodeInstanceRegexAndTypedObject(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "inst", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-kms"], "path_regex": "^\\((?P<LIB>[^.()]+)\\)\\.encrypt$"},
		"method": "encrypt", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "obj", "metadata": {}, "callee": {"bind": "object", "path": "Gen",
		  "from": [{"callee": {"bind": "import", "modules": ["acme-seal"], "path": "default"}, "method": "default", "min_arity": 0, "max_arity": null}], "via": ["var"]},
		"method": "Gen", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 13, key: "acme-kms.(KMS).<init>", method: "<init>", raw: "new KMS", assigned: "kms"},
		call{line: 2, col: 1, key: "src/app.encrypt", method: "encrypt", raw: "kms.encrypt", args: []string{"{}"}},
		call{line: 3, col: 14, key: "acme-seal.default", method: "default", raw: "SEAL", assigned: "seal"},
		call{line: 4, col: 1, key: "acme-seal.(Seal).Gen", method: "Gen", raw: "seal.Gen", recv: "seal", args: []string{"ctx"}},
	), `inst@2 {}`, `obj@4 {}`)
}

// A focus that can stand for an array element reports each element that
// satisfies the rule, at the element's own string.
func TestNodeFocusEachArrayElement(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "allow", "metadata": {}, "callee": {"bind": "literal"}, "method": null, "min_arity": 1, "max_arity": 1,
		"arg_pattern": "{..., algs: [..., $ALG, ...], ...}", "constraints": [{"metavar": "$ALG", "regex": "^['\"]X-(1|2)['\"]$"}], "focus_metavar": "$ALG"}`,
	)
	fr := nodeFragment()
	fr.ObjectLiterals = map[string][]graphfrag.GraphFragmentObjectLiteral{"src/app.js": {
		{Line: 1, StartCol: 15, EndLine: 5, EndCol: 2, Text: "{\n  algs: ['X-1-256',\n    'X-1',\n    \"X-2\"],\n}", CallerKey: "src/app.<module>"},
	}}
	found, _ := a.mustMatch(t, fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%d:%d-%d", f.Line, f.Col, f.EndCol))
	}
	if want := []string{"3:5-10", "4:5-10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("focus: got %v, want %v", got, want)
	}
}

// not_enclosed rules out a call written as a direct argument of another call
// or as an object property value; within keeps a literal only inside its
// context call.
func TestNodeEnclosure(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "md", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "md.sha.create"}, "method": "create",
		"min_arity": 0, "max_arity": null, "not_enclosed": ["argument", "property"]}`,
		`{"rule_id": "hdr", "metadata": {}, "callee": {"bind": "literal"}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg: \"x1\", ...}",
		"within": [{"callee": {"bind": "text", "path_regex": "^(?P<H>.+)\\.header$"}, "method": "header", "min_arity": 1, "max_arity": null, "arg_pattern": "..., <... {..., alg: \"x1\", ...} ...>, ..."}]}`,
	)
	fr := nodeFragment(
		call{line: 1, col: 12, endCol: 32, key: "acme-crypto.md.sha.create", method: "create", raw: "acme.md.sha.create", args: []string{}},
		call{line: 2, col: 1, endCol: 29, key: "src/app.sign", method: "sign", raw: "k.sign", args: []string{"acme.md.sha.create()"}},
		call{line: 2, col: 8, endCol: 28, key: "acme-crypto.md.sha.create", method: "create", raw: "acme.md.sha.create", args: []string{}},
		call{line: 3, col: 9, endCol: 29, key: "acme-crypto.md.sha.create", method: "create", raw: "acme.md.sha.create", args: []string{}},
		call{line: 4, col: 1, endCol: 30, key: "src/app.header", method: "header", raw: "h.header", args: []string{"{ alg: 'x1' }"}},
	)
	fr.SourceLines = map[string]map[int]string{"src/app.js": {
		1: "const md = acme.md.sha.create();",
		2: "k.sign(acme.md.sha.create());",
		3: "f({ md: acme.md.sha.create() });",
	}}
	fr.ObjectLiterals = map[string][]graphfrag.GraphFragmentObjectLiteral{"src/app.js": {
		{Line: 3, StartCol: 3, EndCol: 31, Text: "{ md: acme.md.sha.create() }", CallerKey: "src/app.<module>"},
		{Line: 4, StartCol: 10, EndCol: 23, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>"},
		{Line: 5, StartCol: 10, EndCol: 23, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>"},
	}}
	checkNode(t, a, fr, `md@1 {}`, `hdr@4 {}`)
}

// A namespace member's call is written as a member access: the bare call of
// a named import, which reach keys the same, is not it; a destructured
// class binder matches its `new` (the key writes the class `(C)`).
func TestNodeMemberAndLocalClass(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "ns", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "verify", "member": true}, "method": "verify", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "cls", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(Cmd).<init>", "new": true, "local_first": true}, "method": "<init>", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.verify", method: "verify", raw: "jwt.verify", args: []string{"t"}},
		call{line: 2, col: 1, key: "acme-crypto.verify", method: "verify", raw: "verify", args: []string{"t"}},
		call{line: 3, col: 1, key: "acme-crypto.(Cmd).<init>", method: "<init>", raw: "new Cmd", args: []string{"{}"}},
		// The compiled interop of a default import: ns.default.verify.
		call{line: 4, col: 1, key: "acme-crypto.verify", method: "verify", raw: "jwt.default.verify", args: []string{"t"}},
		// A member of something else (`const v = require(m).x; v.verify()`).
		call{line: 5, col: 1, key: "acme-crypto.verify", method: "verify", raw: "a.b.verify", args: []string{"t"}},
		// A string-literal subscript is a member access.
		call{line: 6, col: 1, key: "acme-crypto.verify", method: "verify", raw: `jwt["verify"]`, args: []string{"t"}},
	), `ns@1 {}`, `cls@3 {}`, `ns@4 {}`, `ns@6 {}`)
	// Modules where one prefixes the other: the longest names the binding.
	b := nodeAssets(t,
		`{"rule_id": "curve", "metadata": {}, "callee": {"bind": "import", "modules": ["acme/c", "acme/c.js"], "path": "p1.agree", "local_first": true}, "method": "agree", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, b, nodeFragment(
		call{line: 1, col: 1, key: "acme/c.js.p1.agree", method: "agree", raw: "p1.agree", args: []string{"k"}},
	), `curve@1 {}`)
}

// A wrapped module's call goes through a variable the wrapper set, not the
// file's own binding of the module; a focus inside a call's argument is
// reported at the value, found in the call's source.
func TestNodeWrappedAndFocusInCall(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "wrap", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-crypto"], "path": "sign", "wrapped": true}, "method": "sign", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "path", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-ssh"], "path": "connect"}, "method": "connect", "min_arity": 1, "max_arity": 1,
		"arg_pattern": "{..., keyPath: $K, ...}", "focus_metavar": "$K"}`,
	)
	fr := nodeFragment(
		call{line: 1, col: 1, key: "acme-crypto.sign", method: "sign", raw: "acme.sign", args: []string{"m"}},
		call{line: 2, col: 1, key: "acme-crypto.sign", method: "sign", raw: "w.sign", args: []string{"m"}},
		call{line: 3, col: 7, endCol: 2, key: "acme-ssh.connect", method: "connect", raw: "ssh.connect", args: []string{"{\n  host: 'h',\n  keyPath: '/k',\n}"}},
	)
	fr.ExternalCalls[2].EndLine = 6
	fr.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {{Line: 1, Module: "acme-crypto", Alias: "acme", Kind: "require"}}}
	fr.SourceLines = map[string]map[int]string{"src/app.js": {3: "await ssh.connect({", 4: "  host: 'h',", 5: "  keyPath: '/k',", 6: "});"}}
	found, _ := a.mustMatch(t, fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s@%d:%d", f.RuleID, f.Line, f.Col))
	}
	if want := []string{"wrap@2:1", "path@5:12"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A method on a fresh instance in one chain (`new m.C(p).f()`): the chain's
// constructor link gives the instance key.
func TestNodeInstanceThroughChain(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "enc", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-pq"], "path": "(Kem).encap"}, "method": "encap", "min_arity": 0, "max_arity": null}`,
	)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 11, endCol: 30, key: "acme-pq.(Kem).<init>", method: "<init>", raw: "new pq.Kem", chain: "c1", args: []string{"'x'"}},
		call{line: 1, col: 11, endCol: 45, key: "src/app.encap", method: "encap", raw: "new pq.Kem('x').encap", chain: "c1", args: []string{"pk"}},
	), `enc@1 {}`)
}

// A read entry matches the fragment's property reads only, keyed as a call
// of the property; a not_producers entry negates a call whose argument reads
// a variable such a read assigned; an inline callee is written on the
// require call itself.
func TestNodeReadsNotProducersInline(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "md5", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-pgp"], "path": "enums.hash.md5"}, "method": "md5", "min_arity": 0, "max_arity": null, "read": true}`,
		`{"rule_id": "enc", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-iron"], "path": "encrypt"}, "method": "encrypt", "min_arity": 2, "max_arity": 2,
		"arg_pattern": "$PW, $OPTS", "not_producers": [{"use": "$OPTS", "via": "var", "from": [{"callee": {"bind": "import", "modules": ["acme-iron"], "path": "defaults.encryption"},
		  "method": "encryption", "min_arity": 0, "max_arity": null, "read": true}]}]}`,
		`{"rule_id": "inl", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-iron"], "path": "decrypt", "inline": true}, "method": "decrypt", "min_arity": 0, "max_arity": null}`,
	)
	fr := nodeFragment(
		// A call of the same key as a read: not the read entry's.
		call{line: 1, col: 1, key: "acme-pgp.enums.hash.md5", method: "md5", raw: "pgp.enums.hash.md5", args: []string{}},
		call{line: 4, col: 1, key: "acme-iron.encrypt", method: "encrypt", raw: "Iron.encrypt", args: []string{"pw", "opts"}},
		call{line: 5, col: 1, key: "acme-iron.encrypt", method: "encrypt", raw: "Iron.encrypt", args: []string{"pw", "custom"}},
		call{line: 6, col: 1, key: "acme-iron.decrypt", method: "decrypt", raw: "Iron.decrypt", args: []string{"pw", "x"}},
		call{line: 7, col: 1, key: "acme-iron.decrypt", method: "decrypt", raw: "require('acme-iron').decrypt", args: []string{"pw", "x"}},
	)
	fr.PropertyReads = map[string][]graphfrag.GraphFragmentPropertyRead{"src/app.js": {
		{CallerKey: "src/app.<module>", TargetKey: "acme-pgp.enums.hash.md5", MethodName: "md5", Raw: "pgp.enums.hash.md5", Line: 2, StartCol: 11, EndCol: 29, AssignedVar: "h"},
		{CallerKey: "src/app.<module>", TargetKey: "acme-iron.defaults.encryption", MethodName: "encryption", Raw: "Iron.defaults.encryption", Line: 3, StartCol: 14, EndCol: 38, AssignedVar: "opts"},
	}}
	checkNode(t, a, fr, `enc@5 {}`, `inl@7 {}`, `md5@2 {}`)
}

// An unbound call on a merged module object holds an import callee when one
// of its candidate modules with the rest of the callee text is a key; an
// assigned-literal entry needs an assigned object and starts at its
// variable; an object literal assigned to a variable produces it.
func TestNodeCandidatesAndAssignedObjects(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "sha", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-h/sha2"], "path": "sha256", "member": true}, "method": "sha256", "min_arity": 0, "max_arity": null}`,
		`{"rule_id": "opts", "metadata": {}, "callee": {"bind": "literal", "assigned": true}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg: \"x1\", ...}"}`,
		`{"rule_id": "gen", "metadata": {}, "callee": {"bind": "global", "path": "(SubtleCrypto).generateKey"}, "method": "generateKey", "min_arity": 1, "max_arity": null,
		"arg_pattern": "$V, ...", "producers": [{"use": "$V", "via": "var", "from": [{"callee": {"bind": "literal", "assigned": true}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., name: $ALG, ...}"}]}]}`,
	)
	fr := nodeFragment(
		call{line: 2, col: 1, key: "src/app.sha256", method: "sha256", raw: "H.sha256", args: []string{"d"}},
		call{line: 3, col: 1, key: "src/app.sha256", method: "sha256", raw: "G.sha256", args: []string{"d"}},
		call{line: 7, col: 1, key: "(SubtleCrypto).generateKey", method: "generateKey", raw: "crypto.subtle.generateKey", args: []string{"algo", "false"}},
	)
	fr.ExternalCalls[0].CandidateModules = []string{"acme-h/sha2", "acme-h/sha3"}
	fr.ExternalCalls[1].CandidateModules = []string{"acme-h/sha3"}
	fr.ObjectLiterals = map[string][]graphfrag.GraphFragmentObjectLiteral{"src/app.js": {
		{Line: 4, StartCol: 12, EndCol: 25, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>", AssignedVar: "o", AssignStartCol: 7},
		{Line: 5, StartCol: 6, EndCol: 19, Text: "{ alg: 'x1' }", CallerKey: "src/app.<module>"},
		{Line: 6, StartCol: 14, EndCol: 33, Text: "{ name: 'ECDSA' }", CallerKey: "src/app.<module>", AssignedVar: "algo", AssignStartCol: 7},
	}}
	found, _ := a.mustMatch(t, fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s@%d:%d", f.RuleID, f.Line, f.Col))
	}
	if want := []string{"sha@2:1", "gen@7:1", "opts@4:7"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A read on `new m.C(p)` that reach left unbound: the construction starting
// where the read does gives the instance key.
func TestNodeReadOnNew(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "fp", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-x509"], "path": "(Cert).fingerprint"}, "method": "fingerprint", "min_arity": 0, "max_arity": null, "read": true}`,
	)
	fr := nodeFragment(call{line: 1, col: 12, endCol: 33, key: "acme-x509.(Cert).<init>", method: "<init>", raw: "new x.Cert", args: []string{"pem"}})
	fr.PropertyReads = map[string][]graphfrag.GraphFragmentPropertyRead{"src/app.js": {
		{CallerKey: "src/app.<module>", TargetKey: "src/app.fingerprint", MethodName: "fingerprint", Raw: "new x.Cert(pem).fingerprint", Line: 1, StartCol: 12, EndCol: 45},
	}}
	checkNode(t, a, fr, `fp@1 {}`)
}

// A focus on array elements of a call argument reports each matching
// element, each at its own string (review of #14).
func TestNodeFocusEachArrayElementOfACall(t *testing.T) {
	a := nodeAssets(t,
		`{"rule_id": "algs", "metadata": {}, "callee": {"bind": "import", "modules": ["acme-jose"], "path": "f"}, "method": "f", "min_arity": 1, "max_arity": 1,
		"arg_pattern": "[..., $ALG, ...]", "constraints": [{"metavar": "$ALG", "regex": "^['\"]A-(1|2)['\"]$"}], "focus_metavar": "$ALG"}`,
	)
	fr := nodeFragment(call{line: 1, col: 1, endCol: 24, key: "acme-jose.f", method: "f", raw: "lib.f", args: []string{"['A-1', 'A-2']"}})
	fr.SourceLines = map[string]map[int]string{"src/app.js": {1: "lib.f(['A-1', 'A-2']);"}}
	found, _ := a.mustMatch(t, fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%d:%d-%d", f.Line, f.Col, f.EndCol))
	}
	if want := []string{"1:8-13", "1:15-20"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
