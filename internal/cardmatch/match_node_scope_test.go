package cardmatch

import (
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// A variable a function around the caller assigns is the receiver's producer
// when the caller assigns it none: a closure's captured `h`. The tightest
// such function wins; a sibling function's variable is not the caller's.
func TestNodeCapturedVariableProducer(t *testing.T) {
	a := nodeAssets(t, objectEntry)
	frag := nodeFragment(
		call{line: 2, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "h", caller: "src/app.outer", args: []string{`"md5"`}},
		call{line: 4, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "h", caller: "src/app.mid", args: []string{`"sha256"`}},
		call{line: 6, col: 1, key: "src/app.update", method: "update", raw: "h.update", recv: "h", caller: "src/app.inner", args: []string{"x"}},
		call{line: 11, col: 1, key: "src/app.update", method: "update", raw: "h.update", recv: "h", caller: "src/app.sibling", args: []string{"x"}},
	)
	frag.Functions = []FunctionJSON{
		{Key: "src/app.<module>", Package: "src/app", FilePath: "src/app.js", StartLine: 1, EndLine: 12},
		{Key: "src/app.outer", Package: "src/app", FilePath: "src/app.js", StartLine: 1, EndLine: 9},
		{Key: "src/app.mid", Package: "src/app", FilePath: "src/app.js", StartLine: 3, EndLine: 8},
		{Key: "src/app.inner", Package: "src/app", FilePath: "src/app.js", StartLine: 5, EndLine: 7},
		{Key: "src/app.sibling", Package: "src/app", FilePath: "src/app.js", StartLine: 10, EndLine: 12},
	}
	checkNode(t, a, frag, `update@6 {"algorithmName": "sha256"}`)
}

// reach keys an unbound method call by its bare name when the module
// declares a function of the caller-local key: such a site is unbound too.
func TestNodeBareKeyIsUnbound(t *testing.T) {
	a := nodeAssets(t, objectEntry)
	checkNode(t, a, nodeFragment(
		call{line: 1, col: 11, key: "acme-crypto.createHash", method: "createHash", raw: "acme.createHash", assigned: "h", args: []string{`"sha1"`}},
		call{line: 2, col: 1, key: "update", method: "update", raw: "h.update", recv: "h", args: []string{"x"}},
	),
		`update@2 {"algorithmName": "sha1"}`,
	)
}

// A namespace member callee (`$C.random(..)` under `$C = require('acme')`)
// matches, as OpenGrep does, a call written on the module's own name in a
// file whose module scope binds a name to require of the module, whatever
// the name holds: not under an import declaration or a require inside a
// function, and not on a call bound to another import.
func TestNodeModuleNameMember(t *testing.T) {
	a := nodeAssets(t, `{"rule_id": "rnd", "metadata": {}, "callee": {"bind": "import", "modules": ["acme", "node:acme"], "path": "random", "member": true},
		"method": "random", "min_arity": 0, "max_arity": null}`)
	frag := nodeFragment(
		call{line: 2, col: 1, key: "(Crypto).random", method: "random", raw: "acme.random", recv: "Crypto"},
		call{line: 3, col: 1, key: "src/app.random", method: "random", raw: "acme.random"},
		call{line: 4, col: 1, key: "other.random", method: "random", raw: "acme.random"},
		call{line: 5, col: 1, key: "acme.random", method: "random", raw: "n.random"},
	)
	frag.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {{Line: 1, Module: "node:acme", Alias: "n", Kind: "require"}}}
	checkNode(t, a, frag, `rnd@2 {}`, `rnd@3 {}`, `rnd@5 {}`)
	for _, im := range []graphfrag.GraphFragmentImport{
		{Line: 1, Module: "node:acme", Name: "default", Alias: "n"},
		{Line: 1, Module: "node:acme", Alias: "n", Kind: "require", Local: true},
		{Line: 1, Module: "other", Alias: "n", Kind: "require"},
	} {
		frag.Imports = map[string][]graphfrag.GraphFragmentImport{"src/app.js": {im}}
		checkNode(t, a, frag, `rnd@5 {}`)
	}
}
