package dependency

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// mavenColorList is what `mvn dependency:list -DoutputFile=...` writes when
// Maven runs with color on (recorded from maven-dependency-plugin 3.6.1 with
// -Dstyle.color=always): the " -- module <name>" suffix of a library that
// declares a Java module name comes wrapped in ANSI escapes, glued to the
// scope.
const mavenColorList = "The following files have been resolved:\n" +
	"   org.bouncycastle:bcprov-jdk18on:jar:1.78.1:compile\x1b[36m -- module org.bouncycastle.provider\x1b[m\n" +
	"   org.example:automatic:jar:2.0.0:runtime\x1b[36m -- module org.example.automatic\x1b[0;1m [auto]\x1b[m\n" +
	"   org.example:plain:jar:3.0.0:compile\n" +
	"   org.example:testkit:jar:4.0.0:test\x1b[36m -- module org.example.testkit\x1b[m\n"

func TestMavenResolver_ParseDependencyList_ColorOutput(t *testing.T) {
	deps := NewMavenResolver().parseDependencyList(mavenColorList)
	got := make([]string, 0, len(deps))
	for _, dep := range deps {
		got = append(got, dep.Module+"@"+dep.Version)
	}
	want := []string{
		"org.bouncycastle:bcprov-jdk18on@1.78.1",
		"org.example:automatic@2.0.0",
		"org.example:plain@3.0.0",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parseDependencyList = %v, want %v", got, want)
	}
}

func TestMavenResolver_ParseTreeOutput_ColorOutput(t *testing.T) {
	tree := "\x1b[1mcom.example:bc-app:jar:1.0.0\x1b[m\n" +
		"+- org.bouncycastle:bcprov-jdk18on:jar:1.78.1:compile\x1b[36m -- module org.bouncycastle.provider\x1b[m\n" +
		"|  \\- org.example:automatic:jar:2.0.0:runtime\x1b[36m -- module org.example.automatic\x1b[0;1m [auto]\x1b[m\n" +
		"\\- org.example:plain:jar:3.0.0:compile\n"
	graph := NewMavenResolver().parseTreeOutput(tree)

	var root []Ref
	for parent, children := range graph {
		if strings.HasPrefix(parent, "com.example:bc-app@") {
			root = children
		}
	}
	if !containsDependencyRef(root, Ref{Module: "org.bouncycastle:bcprov-jdk18on", Version: "1.78.1"}) ||
		!containsDependencyRef(root, Ref{Module: "org.example:plain", Version: "3.0.0"}) {
		t.Fatalf("root children = %v, want bcprov and plain", root)
	}
	if got := graph["org.bouncycastle:bcprov-jdk18on@1.78.1"]; !containsDependencyRef(got, Ref{Module: "org.example:automatic", Version: "2.0.0"}) {
		t.Fatalf("bcprov children = %v, want org.example:automatic@2.0.0", got)
	}
}

func TestVerboseTreeEdges_ColorOutput(t *testing.T) {
	verbose := "com.example:bc-app:jar:1.0.0\n" +
		"+- org.example:a:jar:1.0.0:compile\x1b[36m -- module org.example.a\x1b[m\n" +
		"|  \\- org.example:shared:jar:2.0.0:compile\n" +
		"\\- org.example:b:jar:1.0.0:compile\x1b[36m -- module org.example.b\x1b[m\n" +
		"   \\- \x1b[2m(org.example:shared:jar:2.0.0:compile - omitted for duplicate)\x1b[m\n"
	versioned := map[string][]Ref{
		"com.example:bc-app@1.0.0": {{Module: "org.example:a", Version: "1.0.0"}, {Module: "org.example:b", Version: "1.0.0"}},
		"org.example:a@1.0.0":      {{Module: "org.example:shared", Version: "2.0.0"}},
	}
	_, omitted := verboseTreeEdges(verbose, versioned)
	if got := omitted["org.example:b@1.0.0"]; !containsDependencyRef(got, Ref{Module: "org.example:shared", Version: "2.0.0"}) {
		t.Fatalf("omitted edges = %v, want org.example:b@1.0.0 -> org.example:shared@2.0.0", omitted)
	}
}

// TestMavenResolver_Resolve_RunsMavenInBatchModeWithoutColor resolves a
// project against a fake mvn that records its arguments and writes color
// into the output files, as Maven does when a user's MAVEN_ARGS or settings
// force it on. Every invocation must ask for batch mode with color off, and
// the library that declares a module name must still resolve.
func TestMavenResolver_Resolve_RunsMavenInBatchModeWithoutColor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	pom := `<project><groupId>com.example</groupId><artifactId>bc-app</artifactId><dependencies><dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "mvn-args.log")
	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
echo "$*" >> "`+logPath+`"
out=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
  esac
done
if [ "$1" = "dependency:list" ]; then
  printf 'The following files have been resolved:\n   org.bouncycastle:bcprov-jdk18on:jar:1.78.1:compile\033[36m -- module org.bouncycastle.provider\033[m\n' > "$out"
fi
if [ "$1" = "dependency:tree" ]; then
  printf 'com.example:bc-app:jar:1.0.0\n\\- org.bouncycastle:bcprov-jdk18on:jar:1.78.1:compile\033[36m -- module org.bouncycastle.provider\033[m\n' > "$out"
fi
exit 0
`)
	prependPath(t, binDir)

	result, err := NewMavenResolver().Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(result.Dependencies) != 1 || result.Dependencies[0].Module != "org.bouncycastle:bcprov-jdk18on" {
		t.Fatalf("Dependencies = %#v, want org.bouncycastle:bcprov-jdk18on", result.Dependencies)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read mvn log: %v", err)
	}
	invocations := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(invocations) < 3 {
		t.Fatalf("mvn ran %d times, want at least list, tree and sources: %q", len(invocations), invocations)
	}
	for _, invocation := range invocations {
		args := strings.Fields(invocation)
		if !slices.Contains(args, "-B") || !slices.Contains(args, "-Dstyle.color=never") {
			t.Errorf("mvn %s: want -B and -Dstyle.color=never", invocation)
		}
		for _, want := range mavenParallelArgs {
			if !slices.Contains(args, want) {
				t.Errorf("mvn %s: want %s", invocation, want)
			}
		}
	}
}

// TestMavenExtraArgs_KeepsTheUsersResolverSettings: a resolver property the
// user sets in MAVEN_ARGS or MAVEN_OPTS is not passed again, since a -D on
// the command line would override the user's value; the others still are.
func TestMavenExtraArgs_KeepsTheUsersResolverSettings(t *testing.T) {
	t.Setenv("MAVEN_ARGS", "-B -Daether.connector.basic.threads=2")
	t.Setenv("MAVEN_OPTS", "-Xmx1g -Daether.dependencyCollector.impl=df")
	got := mavenExtraArgs()
	want := []string{"-B", "-Dstyle.color=never", "-Daether.dependencyCollector.bf.threads=8"}
	if !slices.Equal(got, want) {
		t.Fatalf("mavenExtraArgs() = %v, want %v", got, want)
	}

	t.Setenv("MAVEN_ARGS", "")
	t.Setenv("MAVEN_OPTS", "")
	if got := mavenExtraArgs(); !slices.Equal(got, slices.Concat(mavenBatchArgs, mavenParallelArgs)) {
		t.Fatalf("mavenExtraArgs() with no user settings = %v, want batch and parallel args", got)
	}
}

// TestMavenCommands_GoThroughNewMavenCommand keeps every mvn process in the
// package on newMavenCommand, which adds the batch-mode flags: a call that
// builds its own `exec.Command*(..., "mvn", ...)` would run Maven with color.
func TestMavenCommands_GoThroughNewMavenCommand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "newMavenCommand" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, _ := strconv.Unquote(lit.Value); s == "mvn" {
							t.Errorf("%s: %s builds an mvn command itself; use newMavenCommand", fset.Position(call.Pos()), fn.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
}

func TestMavenResolver_IsInterModuleFailure_ColorOutput(t *testing.T) {
	stderr := "[\x1b[1;31mERROR\x1b[m] Failed to execute goal on project \x1b[36mweb\x1b[m: \x1b[1;31mCould not resolve dependencies for project com.acme:web:jar:1.0: " +
		"Could not find artifact \x1b[1mcom.acme\x1b[m:\x1b[1mcore\x1b[m:jar:1.0\x1b[m"
	if !isInterModuleFailure(stderr, "com.acme", []string{"core"}) {
		t.Fatal("isInterModuleFailure = false for a colored inter-module failure, want true")
	}
}
