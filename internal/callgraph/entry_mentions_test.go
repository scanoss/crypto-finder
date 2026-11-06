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

package callgraph

import "testing"

// TestMentionCounter_CountsReferencesInCodeOnly: a comment, a string that
// holds more than the name and a member of an imported foreign module are not
// references to the application's function; a bare use, a string that is
// exactly the name, a member of a local value and a member of the module the
// function lives in are.
func TestMentionCounter_CountsReferencesInCodeOnly(t *testing.T) {
	t.Parallel()
	home := &FunctionDecl{ID: FunctionID{Package: "app", Name: "fingerprint"}, FilePath: "/src/app/handlers.py"}
	for _, tc := range []struct {
		name, file, src string
		want            int
	}{
		{"python declaration only", "main.py", "def fingerprint(req):\n    pass\n", 1},
		{"python route string", "main.py", "def fingerprint(req):\n    pass\n\nurl = \"/fingerprint?data=hello\"\n", 1},
		{"python comment and docstring", "main.py", "# fingerprint is unused\ndef fingerprint(req):\n    \"\"\"fingerprint the request\"\"\"\n", 1},
		{"python foreign module member", "main.py", "import liba\n\ndef fingerprint(req):\n    return liba.fingerprint(req)\n", 1},
		{"python foreign from-import member", "main.py", "from cbench import liba as l\n\ndef fingerprint(req):\n    return l.fingerprint(req)\n", 1},
		{"python own module member", "main.py", "from app import handlers\n\nHOOKS = [handlers.fingerprint]\n", 1},
		{"python local value member", "main.py", "def run(obj):\n    return obj.fingerprint\n", 1},
		{"python bare reference", "main.py", "HOOKS = {\"start\": fingerprint}\n", 1},
		{"python getattr by exact name", "main.py", "import sys\nfn = getattr(sys.modules[__name__], \"fingerprint\")\n", 1},
		{"python f-string interpolation", "main.py", "msg = f\"{fingerprint}\"\n", 1},
		{"go route string and doc comment", "main.go", "package main\n\n// fingerprint hashes.\nfunc fingerprint() {}\n\nfunc main() { get(\"/fingerprint?data=hello\") }\n", 1},
		{"go foreign package member", "main.go", "package main\n\nimport \"example.com/liba\"\n\nfunc main() { liba.fingerprint() }\n", 0},
		{"go method value", "main.go", "package main\n\nfunc main() { register(s.fingerprint) }\n", 1},
		{"javascript foreign require member", "server.js", "const liba = require('liba');\napp.get('/fingerprint', (req, res) => liba.fingerprint(req));\n", 0},
		{"javascript foreign import member", "server.ts", "import * as liba from './liba';\nliba.fingerprint(1);\n", 0},
		{"javascript own module member", "server.js", "const h = require('./handlers');\nrouter.use(h.fingerprint);\n", 1},
		{"javascript template substitution", "server.js", "const s = `${fingerprint}`;\n", 1},
		{"javascript export shorthand", "server.js", "module.exports = { fingerprint };\n", 1},
		{"java foreign class member", "Main.java", "package app;\nimport org.lib.Liba;\nclass Main { void f() { Liba.fingerprint(\"/fingerprint\"); } }\n", 0},
		{"java own class reference", "Main.java", "package app;\nimport app.handlers;\nclass Main { Runnable r = handlers::fingerprint; }\n", 1},
		{"java reflection by exact name", "Main.java", "package app;\nclass Main { void f() throws Exception { Main.class.getMethod(\"fingerprint\"); } }\n", 1},
		{"rust foreign crate member", "main.rs", "fn main() { let _ = cbench_liba::fingerprint(b\"/fingerprint\"); }\n", 0},
		{"rust own module member", "main.rs", "use crate::handlers as h;\nfn main() { serve(h::fingerprint); }\n", 1},
		{"rust self type member", "main.rs", "impl S { fn f() { run(Self::fingerprint); } }\n", 1},
		{"unknown language counts every word", "notes.kt", "// fingerprint\n", 1},
	} {
		counter := newMentionCounter(map[string]bool{"fingerprint": true}, []*FunctionDecl{home})
		counter.countSource("/src/app/"+tc.file, []byte(tc.src))
		if got := counter.mentions["fingerprint"]; got != tc.want {
			t.Errorf("%s: mentions = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestMentionCounter_RustCrateWithAHyphen: source names the crate crypto-svc
// as crypto_svc, so crypto_svc::fingerprint refers to its function.
func TestMentionCounter_RustCrateWithAHyphen(t *testing.T) {
	t.Parallel()
	home := &FunctionDecl{ID: FunctionID{Package: "crypto-svc", Name: "fingerprint"}, FilePath: "/src/crypto-svc/src/lib.rs"}
	counter := newMentionCounter(map[string]bool{"fingerprint": true}, []*FunctionDecl{home})
	counter.countSource("/src/crypto-svc/src/main.rs", []byte("fn main() { Router::new().route(\"/fp\", get(crypto_svc::fingerprint)); }\n"))
	if got := counter.mentions["fingerprint"]; got != 1 {
		t.Fatalf("mentions = %d, want 1: crypto_svc is the crate crypto-svc", got)
	}
}

// TestUncalledRoots_GoHandlerNamedOnlyInAStringOrComment: a handler main
// never registers is dead code even when a route string and its own doc
// comment spell its name.
func TestUncalledRoots_GoHandlerNamedOnlyInAStringOrComment(t *testing.T) {
	t.Parallel()
	wantUnreachable(t, scopeCase{ecosystem: "go", parser: goParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import (
	"crypto/sha256"
	"net/http"
)

func main() {
	http.Get("http://localhost/fingerprint?data=hello")
}

// fingerprint answers /fingerprint.
func fingerprint(w http.ResponseWriter, r *http.Request) { digest(nil) }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
	}}.trace(t))
}

// TestUncalledRoots_PythonForeignMemberIsNotAReference: liba.fingerprint
// calls another module's function, not the application's uncalled
// fingerprint, which stays dead; a member of the application's own module
// still refers to it.
func TestUncalledRoots_PythonForeignMemberIsNotAReference(t *testing.T) {
	t.Parallel()
	app := func(main, handlers string) map[string]string {
		return map[string]string{
			"pyproject.toml":  "[project]\nname = \"app\"\n",
			"app/__init__.py": "",
			"app/handlers.py": `import hashlib


def digest(data):
    return hashlib.sha256(data).digest()


def fingerprint(request):
    return digest(request)
` + handlers,
			"app/main.py": main + `

if __name__ == "__main__":
    main()
`,
		}
	}
	wantUnreachable(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app(`import liba


def main():
    print(liba.fingerprint("/fingerprint?data=hello"))
`, "")}.trace(t))
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app(`from app import handlers

HOOKS = [handlers.fingerprint]


def main():
    print(HOOKS)
`, "")}.trace(t), "fingerprint")
}
