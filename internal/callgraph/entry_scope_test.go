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

import (
	"strings"
	"testing"
)

// scopeCase builds a graph from real sources, every package of it the
// application's, and traces the function named target.
type scopeCase struct {
	ecosystem string
	parser    func() Parser
	files     map[string]string
	dirs      []string // package directories under the tree; "" is the root
	target    string
}

func (c scopeCase) trace(t *testing.T) CondensedTrace {
	t.Helper()
	root := writePythonTree(t, c.files)
	dirs := c.dirs
	if len(dirs) == 0 {
		dirs = []string{""}
	}
	packages := make([]PackageDir, 0, len(dirs))
	for _, dir := range dirs {
		pkg := PackageDir{Dir: root + "/" + dir, ImportPath: "app"}
		if c.ecosystem == ecosystemPython {
			pkg.ImportPath = ""
		}
		packages = append(packages, pkg)
	}
	graph, err := NewBuilderForEcosystem(c.ecosystem, c.parser()).BuildFromDirectories(packages, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	userPackages := map[string]bool{}
	var target *FunctionDecl
	for _, decl := range graph.Functions {
		if strings.HasPrefix(decl.FilePath, root) {
			userPackages[decl.ID.Package] = true
		}
		if BaseFunctionName(decl.ID.Name) == c.target {
			target = decl
		}
	}
	if target == nil {
		keys := make([]string, 0, len(graph.Functions))
		for key := range graph.Functions {
			keys = append(keys, key)
		}
		t.Fatalf("no function %s in %v", c.target, keys)
	}
	sep := "."
	if c.ecosystem == ecosystemRust {
		sep = "::"
	}
	tracer := NewTracer(graph, sep)
	tracer.SetProjectRoot(root)
	return tracer.TraceBackCondensed(target.ID, userPackages, 0, 0)
}

func goParser() Parser     { return NewGoParser() }
func goTestParser() Parser { return NewGoParser(WithIncludeTests(true)) }
func pythonParser() Parser { return NewPythonParser() }
func rustParser() Parser   { return NewRustParser() }
func javaParser() Parser   { return NewJavaParser() }

func rootNames(trace CondensedTrace) []string {
	out := make([]string, 0, len(trace.Chains))
	for _, chain := range trace.Chains {
		out = append(out, chain.Steps[0].Function.Name+"["+string(chain.RootKind)+"]")
	}
	return out
}

func wantUnreachable(t *testing.T, trace CondensedTrace) {
	t.Helper()
	if len(trace.Chains) != 0 {
		t.Fatalf("chains rooted at %v, want none: only dead code reaches the target", rootNames(trace))
	}
}

// wantNoCallersRoot asserts a chain rooted at name, a function nothing calls.
func wantNoCallersRoot(t *testing.T, trace CondensedTrace, name string) {
	t.Helper()
	for _, chain := range trace.Chains {
		if BaseFunctionName(chain.Steps[0].Function.Name) == name && chain.RootKind == RootKindNoCallers {
			return
		}
	}
	t.Fatalf("chains rooted at %v, want one rooted at %s[no_callers]", rootNames(trace), name)
}

const goMod = "module app\n\ngo 1.22\n"

// TestUncalledRoots_GoApplicationWithMain: in a Go program, a function
// main never reaches is dead code, so what only it reaches is unreachable.
func TestUncalledRoots_GoApplicationWithMain(t *testing.T) {
	t.Parallel()
	wantUnreachable(t, scopeCase{ecosystem: "go", parser: goParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "crypto/sha256"

func main() { println("hello") }

func run(data []byte) []byte { return digest(data) }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
	}}.trace(t))
}

// TestUncalledRoots_GoLibraryKeepsTheFallback: a library without an entry
// point keeps its uncalled functions as roots, its public surface.
func TestUncalledRoots_GoLibraryKeepsTheFallback(t *testing.T) {
	t.Parallel()
	wantNoCallersRoot(t, scopeCase{ecosystem: "go", parser: goParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"lib.go": `package lib

import "crypto/sha256"

func Fingerprint(data []byte) []byte { return digest(data) }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
	}}.trace(t), "Fingerprint")
}

// TestUncalledRoots_GoFunctionValueStaysARoot: a function handed out as a
// value has no call edge; it is not dead code.
func TestUncalledRoots_GoFunctionValueStaysARoot(t *testing.T) {
	t.Parallel()
	wantNoCallersRoot(t, scopeCase{ecosystem: "go", parser: goParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "crypto/sha256"

var hooks []func()

func register(f func()) { hooks = append(hooks, f) }

func main() { register(onStart); for _, h := range hooks { h() } }

func onStart() { digest(nil) }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
	}}.trace(t), "onStart")
}

// TestUncalledRoots_GoInitIsARoot: the runtime runs init without a call.
func TestUncalledRoots_GoInitIsARoot(t *testing.T) {
	t.Parallel()
	trace := scopeCase{ecosystem: "go", parser: goParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "crypto/sha256"

var key []byte

func init() { key = digest([]byte("seed")) }

func main() { println(len(key)) }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
	}}.trace(t)
	if len(trace.Chains) == 0 || !strings.HasPrefix(trace.Chains[0].Steps[0].Function.Name, "<init:") {
		t.Fatalf("chains rooted at %v, want one rooted at init", rootNames(trace))
	}
}

// TestUncalledRoots_PythonMainGuard: the __main__ guard is the entry point;
// a module function it never reaches is dead code. A function stored as a
// value, or one a decorator registers, is not.
func TestUncalledRoots_PythonMainGuard(t *testing.T) {
	t.Parallel()
	app := func(extra string) map[string]string {
		return map[string]string{
			"pyproject.toml":  "[project]\nname = \"app\"\n",
			"app/__init__.py": "",
			"app/main.py": `import hashlib


def digest(data):
    return hashlib.sha256(data).digest()


def run(data):
    return digest(data)


def main():
    print("hello")
` + extra + `

if __name__ == "__main__":
    main()
`,
		}
	}
	wantUnreachable(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app("")}.trace(t))
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app(`

def worker():
    digest(b"x")


HOOKS = {"start": worker}
`)}.trace(t), "worker")
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app(`

@events.on("startup")
def warm():
    digest(b"x")
`)}.trace(t), "warm")
	// A route whose path holds "test" is still a registering decorator.
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: app(`

@routes.post("/attestation/verify")
def verify_attestation(request):
    digest(b"x")
`)}.trace(t), "verify_attestation")
	// A deployment file names the handler: the source never does.
	files := app(`

def handler(event, context):
    digest(b"x")
`)
	files["template.yaml"] = "Resources:\n  Fn:\n    Properties:\n      Handler: app.main.handler\n"
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: files}.trace(t), "handler")
}

// TestDecorated_ReadsTheDecoratorNameNotItsArguments: a test marker is told
// by its name, and a registering decorator above one still counts.
func TestDecorated_ReadsTheDecoratorNameNotItsArguments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"@routes.post(\"/attestation\")\ndef f(): pass", true},
		{"@app.get(\"/latest\")\ndef f(): pass", true},
		{"#[post(\"/attest\")]\nfn f() {}", true},
		{"#[test]\nfn f() {}", false},
		{"#[tokio::test]\nasync fn f() {}", false},
		{"#[cfg(test)]\nfn f() {}", false},
		{"@pytest.mark.slow\ndef f(): pass", false},
		{"@Test\nstatic void f() {}", false},
		{"#[get(\"/\")]\n#[cfg(not(test))]\nfn f() {}", true},
		{"@app.task\n@pytest.mark.slow\ndef f(): pass", true},
		{"}\nfn f() {}", false},
	} {
		var lines [][]byte
		for _, line := range strings.Split(tc.src, "\n") {
			lines = append(lines, []byte(line))
		}
		if got := decorated(lines, len(lines)); got != tc.want {
			t.Errorf("decorated(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// TestUncalledRoots_TestIsNotARoot: under --include-tests, a test nothing
// calls is not a root of an application with an entry point.
func TestUncalledRoots_TestIsNotARoot(t *testing.T) {
	t.Parallel()
	wantUnreachable(t, scopeCase{ecosystem: "go", parser: goTestParser, target: "digest", files: map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "crypto/sha256"

func main() { println("hello") }

func digest(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
`,
		"main_test.go": `package main

import "testing"

func TestDigest(t *testing.T) { digest(nil) }
`,
	}}.trace(t))
}

// TestUncalledRoots_ScopedPerModule: one module's entry point does not make
// a sibling module without one dead code. Each manifest directory is a
// module.
func TestUncalledRoots_ScopedPerModule(t *testing.T) {
	t.Parallel()
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemPython, parser: pythonParser, target: "digest", files: map[string]string{
		"cli/pyproject.toml":  "[project]\nname = \"cli\"\n",
		"cli/cli/__init__.py": "",
		"cli/cli/main.py":     "def main():\n    print(\"hello\")\n\n\nif __name__ == \"__main__\":\n    main()\n",
		"core/pyproject.toml": "[project]\nname = \"core\"\n",
		"core/core/__init__.py": `import hashlib


def digest(data):
    return hashlib.sha256(data).digest()


def fingerprint(data):
    return digest(data)
`,
	}}.trace(t), "fingerprint")
}

// TestUncalledRoots_RustHandlers: Rust has no framework catalog, so a web
// handler is kept a root by its route reference (axum) or its attribute
// (actix), while a function nothing names stays dead.
func TestUncalledRoots_RustHandlers(t *testing.T) {
	t.Parallel()
	crate := func(body string) map[string]string {
		return map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
			"src/main.rs": `use sha2::{Digest, Sha256};

fn digest(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
` + body,
		}
	}
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemRust, parser: rustParser, target: "digest", dirs: []string{"src"}, files: crate(`
async fn handler() -> Vec<u8> {
    digest(b"x")
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(handler));
    serve(app).await;
}
`)}.trace(t), "handler")
	wantNoCallersRoot(t, scopeCase{ecosystem: ecosystemRust, parser: rustParser, target: "digest", dirs: []string{"src"}, files: crate(`
#[get("/")]
async fn index() -> Vec<u8> {
    digest(b"x")
}

fn main() {
    println!("hello");
}
`)}.trace(t), "index")
	wantUnreachable(t, scopeCase{ecosystem: ecosystemRust, parser: rustParser, target: "digest", dirs: []string{"src"}, files: crate(`
fn run() -> Vec<u8> {
    digest(b"x")
}

fn main() {
    println!("hello");
}
`)}.trace(t))
}

// TestUncalledRoots_JavaStaticAndInstanceMethods: an uncalled static method
// of a program is dead code. An uncalled instance method may be reached
// through an interface the graph does not resolve, so it stays a root once
// something creates its class; while nothing does, it is dead code too
// (entry_java_instances.go).
func TestUncalledRoots_JavaStaticAndInstanceMethods(t *testing.T) {
	t.Parallel()
	program := func(method string) map[string]string {
		return programWith("System.out.println(\"hello\");", method)
	}
	wantUnreachable(t, scopeCase{
		ecosystem: "java", parser: javaParser, target: "digest", dirs: []string{"src/main/java"},
		files: program("    static byte[] run(byte[] data) throws Exception {\n        return digest(data);\n    }\n"),
	}.trace(t))
	instance := "    byte[] apply(byte[] data) throws Exception {\n        return digest(data);\n    }\n"
	wantUnreachable(t, scopeCase{
		ecosystem: "java", parser: javaParser, target: "digest", dirs: []string{"src/main/java"},
		files: program(instance),
	}.trace(t))
	wantNoCallersRoot(t, scopeCase{
		ecosystem: "java", parser: javaParser, target: "digest", dirs: []string{"src/main/java"},
		files: programWith("Runnable r = () -> System.out.println(new Main());", instance),
	}.trace(t), "apply")
}

// programWith is a Java program whose main runs body, with method added to
// its class.
func programWith(body, method string) map[string]string {
	return map[string]string{
		"pom.xml": "<project/>\n",
		"src/main/java/app/Main.java": `package app;

import java.security.MessageDigest;

public final class Main {
    public static void main(String[] args) {
        ` + body + `
    }

    static byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

` + method + `
}
`,
	}
}
