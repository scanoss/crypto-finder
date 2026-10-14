package opengrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// fakeOpengrep writes an executable that answers version and help probes,
// appends the working directory and arguments of a scan to calls.txt, one
// call per line, and prints outputs[name] as the scan's JSON with exit
// status 1 (findings), where name is the base name of its working
// directory. A name outputs lacks prints no results.
func fakeOpengrep(t *testing.T, dir string, outputs map[string]string) string {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires POSIX scanner fixture subprocesses")
	}
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
 --version) echo 1.12.1; exit 0;;
 scan|--help) echo '--x-ignore-semgrepignore-files --force-exclude'; exit 0;;
esac
here=$(pwd -P)
echo "$here|$*" >> '%[1]s/calls.txt'
out='%[1]s/out/'"${here##*/}"'.json'
if [ -f "$out" ]; then cat "$out"; else echo '{"version":"1.12.1","results":[],"errors":[]}'; fi
exit 1
`, dir)
	exe := filepath.Join(dir, "opengrep")
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, output := range outputs {
		writeTree(t, filepath.Join(dir, "out"), map[string]string{name + ".json": output})
	}
	return exe
}

// call is one recorded scan: its working directory and arguments.
type call struct {
	dir  string
	argv []string
}

func recordedCalls(t *testing.T, dir string) []call {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "calls.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var calls []call
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		cwd, args, _ := strings.Cut(line, "|")
		calls = append(calls, call{dir: cwd, argv: strings.Fields(args)})
	}
	return calls
}

func result(path string) string {
	return fmt.Sprintf(`{"check_id":"fixture.hash","path":%q,"start":{"line":1,"col":1},"end":{"line":1,"col":8},"extra":{"message":"hash","severity":"INFO","lines":"hash()","metadata":{"crypto":{"assetType":"algorithm","algorithmFamily":"SHA2","primitive":"hash"}}}}`, path)
}

func batchScanner(t *testing.T, exe string, skip ...string) *Scanner {
	t.Helper()
	s := NewScanner()
	if err := s.Initialize(context.Background(), scanner.Config{ExecutablePath: exe, Timeout: time.Second, SkipPatterns: skip}); err != nil {
		t.Fatal(err)
	}
	return s
}

func findingPaths(report *entities.InterimReport) []string {
	paths := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		paths = append(paths, filepath.ToSlash(finding.FilePath))
	}
	// The transformer groups results by file through a map, so finding order
	// is not part of the report's contract.
	slices.Sort(paths)
	return paths
}

// mkdirs creates dirs and returns their physical paths.
func mkdirs(t *testing.T, dirs ...string) []string {
	t.Helper()
	physical := make([]string, len(dirs))
	for i, dir := range dirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
		physical[i] = resolved
	}
	return physical
}

// rulesFixture writes a rules file in dir and returns the rule paths of a
// scan with it.
func rulesFixture(t *testing.T, dir string) []string {
	t.Helper()
	writeTree(t, dir, map[string]string{"rules.yaml": `rules: []`})
	return []string{filepath.Join(dir, "rules.yaml")}
}

func dirRoots(dirs ...string) []scanner.Root {
	roots := make([]scanner.Root, len(dirs))
	for i, dir := range dirs {
		roots[i] = scanner.Root{Dir: dir}
	}
	return roots
}

func excludesOf(argv []string) []string {
	excludes := []string{}
	for i, arg := range argv {
		if arg == "--exclude" && i+1 < len(argv) {
			excludes = append(excludes, argv[i+1])
		}
	}
	return excludes
}

// Each root runs in its own process, in its own directory, over ".": the
// engine sees the same relative paths wherever the root lies. Each report is
// what a scan of that root alone produces: paths relative to it and only its
// own limit errors, named under the root as the caller names it.
func TestScanRoots_EachRootRunsInItsDirectory(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	physical := mkdirs(t, a, b)
	exe := fakeOpengrep(t, dir, map[string]string{
		"a": fmt.Sprintf(`{"version":"1.12.1","results":[%s,%s],"errors":[{"type":"SemgrepError","level":"warn","message":"a notice without a file","path":""}]}`,
			result("index.js"), result("index.js")),
		"b": fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[{"type":"Timeout","level":"warn","message":"Timeout when running fixture.hash on lib/big.js","path":"lib/big.js"}]}`,
			result("lib/x.js")),
	})
	s := batchScanner(t, exe, "test/", "node_modules/")

	reports, err := s.ScanRoots(context.Background(), dirRoots(a, b), rulesFixture(t, dir), entities.ToolInfo{Name: "fixture", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want one per root", len(reports))
	}
	if got := findingPaths(reports[0]); !reflect.DeepEqual(got, []string{"index.js"}) || len(reports[0].Findings[0].CryptographicAssets) != 1 {
		t.Errorf("root a: findings = %v (%d assets), want [index.js] with the two same-line results merged", got, len(reports[0].Findings[0].CryptographicAssets))
	}
	if got := findingPaths(reports[1]); !reflect.DeepEqual(got, []string{"lib/x.js"}) {
		t.Errorf("root b: findings = %v, want [lib/x.js]", got)
	}
	if len(reports[0].IncompleteFiles) != 0 {
		t.Errorf("root a: incomplete files = %v, want none", reports[0].IncompleteFiles)
	}
	if want := []string{filepath.Join(b, "lib", "big.js")}; !reflect.DeepEqual(reports[1].IncompleteFiles, want) {
		t.Errorf("root b: incomplete files = %v, want %v named under the root", reports[1].IncompleteFiles, want)
	}
	for i, report := range reports {
		if report.Tool.Name != "fixture" || report.Findings[0].CryptographicAssets[0].Rules[0].ID != "fixture.hash" {
			t.Errorf("report %d: %+v, want the tool info and cleaned rule IDs a single scan carries", i, report)
		}
	}

	calls := recordedCalls(t, dir)
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want one process per root", calls)
	}
	for i, c := range calls {
		if c.dir != physical[i] {
			t.Errorf("call %d ran in %s, want the root %s", i, c.dir, physical[i])
		}
		if c.argv[len(c.argv)-1] != "." {
			t.Errorf("call %d: argv = %v, want it to end with the root as \".\"", i, c.argv)
		}
		if want := []string{"test/", "node_modules/"}; !reflect.DeepEqual(excludesOf(c.argv), want) {
			t.Errorf("call %d: excludes = %v, want %v", i, excludesOf(c.argv), want)
		}
		if slices.Contains(c.argv, "--force-exclude") {
			t.Errorf("call %d: argv = %v: directory roots must not be scanned as named files", i, c.argv)
		}
		if config := c.argv[slices.Index(c.argv, "--config")+1]; !filepath.IsAbs(config) {
			t.Errorf("call %d: config %s must be absolute: the engine runs elsewhere", i, config)
		}
	}
}

// A limit error the scanner reports without a file marks the root of its
// process incomplete, as a single scan treats its own target.
func TestScanRoots_LimitErrorWithoutFileMarksItsRootIncomplete(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdirs(t, a, b)
	exe := fakeOpengrep(t, dir, map[string]string{"a": `{"version":"1.12.1","results":[],"errors":[{"type":"Out of memory","level":"warn","message":"out of memory","path":""}]}`})
	s := batchScanner(t, exe)

	reports, err := s.ScanRoots(context.Background(), dirRoots(a, b), rulesFixture(t, dir), entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reports[0].IncompleteFiles, []string{a}) || len(reports[1].IncompleteFiles) != 0 {
		t.Errorf("incomplete files = %v and %v, want only root a marked", reports[0].IncompleteFiles, reports[1].IncompleteFiles)
	}
}

// Nested and repeated roots no longer share a process, so each is scanned
// whole, as alone.
func TestScanRoots_NestedRootsScanAlone(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	inner := filepath.Join(a, "node_modules", "b")
	mkdirs(t, a, inner)
	exe := fakeOpengrep(t, dir, map[string]string{
		"a": fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result("index.js")),
		"b": fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result("lib/y.js")),
	})
	s := batchScanner(t, exe)
	reports, err := s.ScanRoots(context.Background(), dirRoots(a, inner, a), rulesFixture(t, dir), entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	got := [][]string{findingPaths(reports[0]), findingPaths(reports[1]), findingPaths(reports[2])}
	if want := [][]string{{"index.js"}, {"lib/y.js"}, {"index.js"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings per root = %v, want %v", got, want)
	}
}

// A scoped root is scanned as its named files, relative to the root, with
// --force-exclude so the skip patterns still apply to them, and its report
// keeps paths relative to the root, as a scoped scan of that root alone
// does. A root whose scope is empty runs nothing and reports nothing.
func TestScanRoots_ScopedRootsScanTheirFilesOnly(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	mkdirs(t, a, b, c)
	exe := fakeOpengrep(t, dir, map[string]string{
		"a": fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result("pkg/x.go")),
		"b": fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result("y.go")),
	})
	s := batchScanner(t, exe, "*_test.go")

	roots := []scanner.Root{
		{Dir: a, Scope: &scanner.DetectionScope{Paths: []string{filepath.Join("pkg", "x.go"), filepath.Join("pkg", "x_test.go")}}},
		{Dir: b, Scope: &scanner.DetectionScope{Paths: []string{"y.go"}}},
		{Dir: c, Scope: &scanner.DetectionScope{}},
	}
	reports, err := s.ScanRoots(context.Background(), roots, rulesFixture(t, dir), entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	got := [][]string{findingPaths(reports[0]), findingPaths(reports[1]), findingPaths(reports[2])}
	if want := [][]string{{"pkg/x.go"}, {"y.go"}, {}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings per root = %v, want %v", got, want)
	}
	calls := recordedCalls(t, dir)
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want one per root with files", calls)
	}
	if argv := calls[0].argv; !reflect.DeepEqual(argv[len(argv)-2:], []string{"pkg/x.go", "pkg/x_test.go"}) || !slices.Contains(argv, "--force-exclude") {
		t.Errorf("argv = %v, want the scoped files relative to the root and --force-exclude", argv)
	}
	if argv := calls[1].argv; argv[len(argv)-1] != "y.go" {
		t.Errorf("argv = %v, want it to end with y.go", argv)
	}
}

// Extra scanner arguments may name paths relative to crypto-finder's
// working directory, so such a scan keeps running there over the root as
// named; absolute paths the engine reports stay as they are.
func TestScanRoots_ExtraArgumentsKeepTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	mkdirs(t, a)
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	exe := fakeOpengrep(t, dir, map[string]string{filepath.Base(cwd): fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result(filepath.Join(a, "x.go")))})
	s := NewScanner()
	if err := s.Initialize(context.Background(), scanner.Config{ExecutablePath: exe, Timeout: time.Second, ExtraArgs: []string{"--no-rewrite-rule-ids"}}); err != nil {
		t.Fatal(err)
	}
	reports, err := s.ScanRoots(context.Background(), dirRoots(a), rulesFixture(t, dir), entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got := findingPaths(reports[0]); !reflect.DeepEqual(got, []string{"x.go"}) {
		t.Errorf("findings = %v, want [x.go]", got)
	}
	calls := recordedCalls(t, dir)
	if len(calls) != 1 || calls[0].dir != cwd || calls[0].argv[len(calls[0].argv)-1] != a {
		t.Errorf("calls = %v, want one run in %s over %s", calls, cwd, a)
	}
}
