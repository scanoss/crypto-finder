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
// records the arguments of a scan into argv.txt and prints output as the
// scan's JSON with exit status 1 (findings).
func fakeOpengrep(t *testing.T, dir, output string) string {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires POSIX scanner fixture subprocesses")
	}
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
 --version) echo 1.12.1; exit 0;;
 scan|--help) echo '--x-ignore-semgrepignore-files --force-exclude'; exit 0;;
esac
printf '%%s\n' "$@" > '%s/argv.txt'
cat '%s/output.json'
exit 1
`, dir, dir)
	exe := filepath.Join(dir, "opengrep")
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "output.json"), []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	return exe
}

func recordedArgv(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
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

// One process scans every root; each root's report is what a scan of that
// root alone produces: paths relative to it, and only its own limit errors.
func TestScanRoots_ReportsEachRootAsItsOwnScan(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	output := fmt.Sprintf(`{"version":"1.12.1","results":[%s,%s,%s],"errors":[
 {"type":"Timeout","level":"warn","message":"Timeout when running fixture.hash on %s","path":%q},
 {"type":"SemgrepError","level":"warn","message":"a notice without a file","path":""}]}`,
		result(filepath.Join(b, "lib", "x.js")), result(filepath.Join(a, "index.js")), result(filepath.Join(a, "index.js")),
		filepath.Join(b, "lib", "big.js"), filepath.Join(b, "lib", "big.js"))
	exe := fakeOpengrep(t, dir, output)
	s := batchScanner(t, exe, "test/", filepath.ToSlash(a)+"/node_modules/", filepath.ToSlash(b)+"/node_modules/")

	reports, err := s.ScanRoots(context.Background(), dirRoots(a, b), []string{filepath.Join(dir, "rules.yaml")}, entities.ToolInfo{Name: "fixture", Version: "1"})
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
		t.Errorf("root b: incomplete files = %v, want %v", reports[1].IncompleteFiles, want)
	}
	for i, report := range reports {
		if report.Tool.Name != "fixture" || report.Findings[0].CryptographicAssets[0].Rules[0].ID != "fixture.hash" {
			t.Errorf("report %d: %+v, want the tool info and cleaned rule IDs a single scan carries", i, report)
		}
	}

	argv := recordedArgv(t, dir)
	if len(argv) < 2 || argv[len(argv)-2] != a || argv[len(argv)-1] != b {
		t.Errorf("argv = %v, want it to end with both roots", argv)
	}
	excludes := []string{}
	for i, arg := range argv {
		if arg == "--exclude" && i+1 < len(argv) {
			excludes = append(excludes, argv[i+1])
		}
	}
	if want := []string{"test/", filepath.ToSlash(a) + "/node_modules/", filepath.ToSlash(b) + "/node_modules/"}; !reflect.DeepEqual(excludes, want) {
		t.Errorf("excludes = %v, want %v", excludes, want)
	}
	if strings.Contains(strings.Join(argv, " "), "--force-exclude") {
		t.Errorf("argv = %v: directory roots must not be scanned as named files", argv)
	}
}

// A limit error the scanner reports without a file cannot be attributed, so
// every root in the process is treated as incomplete, as a single scan treats
// its own target.
func TestScanRoots_UnattributedLimitErrorMarksEveryRootIncomplete(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	exe := fakeOpengrep(t, dir, `{"version":"1.12.1","results":[],"errors":[{"type":"Out of memory","level":"warn","message":"out of memory","path":""}]}`)
	s := batchScanner(t, exe)

	reports, err := s.ScanRoots(context.Background(), dirRoots(a, b), []string{filepath.Join(dir, "rules.yaml")}, entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reports[0].IncompleteFiles, []string{a}) || !reflect.DeepEqual(reports[1].IncompleteFiles, []string{b}) {
		t.Errorf("incomplete files = %v and %v, want each root marked", reports[0].IncompleteFiles, reports[1].IncompleteFiles)
	}
}

// A root nested under another root would be hidden by the outer root's
// exclusions and a repeated root is scanned once, so neither can share a
// process; refusing them keeps attribution exact.
func TestScanRoots_RefusesNestedOrRepeatedRoots(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	exe := fakeOpengrep(t, dir, `{"version":"1.12.1","results":[],"errors":[]}`)
	s := batchScanner(t, exe)
	for _, roots := range [][]string{
		{a, filepath.Join(a, "node_modules", "b")},
		{filepath.Join(a, "node_modules", "b"), a},
		{a, a},
	} {
		if _, err := s.ScanRoots(context.Background(), dirRoots(roots...), []string{filepath.Join(dir, "rules.yaml")}, entities.ToolInfo{Name: "fixture"}); err == nil {
			t.Errorf("roots %v: want an error", roots)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "argv.txt")); err == nil {
		t.Error("the scanner ran for refused roots")
	}
}

// A result the scanner reports outside every root cannot be attributed; a
// single scan would keep it, so the batch fails instead of losing it.
func TestScanRoots_FailsOnAResultOutsideEveryRoot(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	exe := fakeOpengrep(t, dir, fmt.Sprintf(`{"version":"1.12.1","results":[%s],"errors":[]}`, result(filepath.Join(dir, "elsewhere", "index.js"))))
	s := batchScanner(t, exe)
	if _, err := s.ScanRoots(context.Background(), dirRoots(a, b), []string{filepath.Join(dir, "rules.yaml")}, entities.ToolInfo{Name: "fixture"}); err == nil {
		t.Fatal("want an error for a result under none of the roots")
	}
}

func dirRoots(dirs ...string) []scanner.Root {
	roots := make([]scanner.Root, len(dirs))
	for i, dir := range dirs {
		roots[i] = scanner.Root{Dir: dir}
	}
	return roots
}

// A scoped root is scanned as its named files, with --force-exclude so the
// skip patterns still apply to them, and its report keeps paths relative to
// the root, as a scoped scan of that root alone does. A root whose scope is
// empty runs nothing and reports nothing.
func TestScanRoots_ScopedRootsScanTheirFilesOnly(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	exe := fakeOpengrep(t, dir, fmt.Sprintf(`{"version":"1.12.1","results":[%s,%s],"errors":[]}`,
		result(filepath.Join(a, "pkg", "x.go")), result(filepath.Join(b, "y.go"))))
	s := batchScanner(t, exe, "*_test.go")

	roots := []scanner.Root{
		{Dir: a, Scope: &scanner.DetectionScope{Paths: []string{filepath.Join("pkg", "x.go"), filepath.Join("pkg", "x_test.go")}}},
		{Dir: b, Scope: &scanner.DetectionScope{Paths: []string{"y.go"}}},
		{Dir: c, Scope: &scanner.DetectionScope{}},
	}
	reports, err := s.ScanRoots(context.Background(), roots, []string{filepath.Join(dir, "rules.yaml")}, entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	got := [][]string{findingPaths(reports[0]), findingPaths(reports[1]), findingPaths(reports[2])}
	if want := [][]string{{"pkg/x.go"}, {"y.go"}, {}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings per root = %v, want %v", got, want)
	}
	argv := recordedArgv(t, dir)
	if want := []string{filepath.Join(a, "pkg", "x.go"), filepath.Join(a, "pkg", "x_test.go"), filepath.Join(b, "y.go")}; !reflect.DeepEqual(argv[len(argv)-3:], want) {
		t.Errorf("argv = %v, want it to end with the scoped files %v", argv, want)
	}
	if !slices.Contains(argv, "--force-exclude") {
		t.Errorf("argv = %v, want --force-exclude so the skip patterns apply to named files", argv)
	}
}

// Distributions installed into one namespace directory are roots with the
// same Dir and disjoint scopes: they share a process and each result goes to
// the root whose scope names its file. Overlapping or unscoped siblings would
// scan a file once for two roots, so they are refused.
func TestScanRoots_DisjointSiblingsShareAProcess(t *testing.T) {
	dir := t.TempDir()
	ns := filepath.Join(dir, "google")
	exe := fakeOpengrep(t, dir, fmt.Sprintf(`{"version":"1.12.1","results":[%s,%s],"errors":[]}`,
		result(filepath.Join(ns, "b", "y.py")), result(filepath.Join(ns, "a", "x.py"))))
	s := batchScanner(t, exe)
	rules := []string{filepath.Join(dir, "rules.yaml")}
	scoped := func(paths ...string) *scanner.DetectionScope { return &scanner.DetectionScope{Paths: paths} }

	reports, err := s.ScanRoots(context.Background(), []scanner.Root{
		{Dir: ns, Scope: scoped(filepath.Join("a", "x.py"))},
		{Dir: ns, Scope: scoped(filepath.Join("b", "y.py"))},
	}, rules, entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := [][]string{findingPaths(reports[0]), findingPaths(reports[1])}, [][]string{{"a/x.py"}, {"b/y.py"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings per sibling = %v, want %v", got, want)
	}

	for name, roots := range map[string][]scanner.Root{
		"overlapping":     {{Dir: ns, Scope: scoped("a/x.py")}, {Dir: ns, Scope: scoped("a/x.py", "b/y.py")}},
		"unscoped":        {{Dir: ns, Scope: scoped("a/x.py")}, {Dir: ns}},
		"holder names it": {{Dir: dir, Scope: scoped(filepath.Join("google", "a", "x.py"))}, {Dir: ns}},
	} {
		if _, err := s.ScanRoots(context.Background(), roots, rules, entities.ToolInfo{Name: "fixture"}); err == nil {
			t.Errorf("%s siblings: want an error", name)
		}
	}
}

// A scoped root holding another root's directory, as a Python distribution
// rooted at site-packages holds the packages below it, shares its process
// when it names none of the inner root's files: each result goes to the root
// whose scope names it, or else to the innermost root.
func TestScanRoots_ScopedHolderSharesAProcessWithTheRootsBelowIt(t *testing.T) {
	site := t.TempDir()
	solo := filepath.Join(site, "solo")
	exe := fakeOpengrep(t, site, fmt.Sprintf(`{"version":"1.12.1","results":[%s,%s,%s],"errors":[]}`,
		result(filepath.Join(solo, "y.py")), result(filepath.Join(site, "validate", "x.py")), result(filepath.Join(site, "six.py"))))
	s := batchScanner(t, exe)

	reports, err := s.ScanRoots(context.Background(), []scanner.Root{
		{Dir: site, Scope: &scanner.DetectionScope{Paths: []string{filepath.Join("validate", "x.py"), "six.py"}}},
		{Dir: solo},
	}, []string{filepath.Join(site, "rules.yaml")}, entities.ToolInfo{Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := [][]string{findingPaths(reports[0]), findingPaths(reports[1])}, [][]string{{"six.py", "validate/x.py"}, {"y.py"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings per root = %v, want %v", got, want)
	}
}

func TestInnermostRoot(t *testing.T) {
	roots := []string{filepath.FromSlash("/x/a"), filepath.FromSlash("/x/ab")}
	tests := map[string]int{
		filepath.FromSlash("/x/ab/i.js"):  1,
		filepath.FromSlash("/x/a/i.js"):   0,
		filepath.FromSlash("/x/a"):        0,
		filepath.FromSlash("/x/abc/i.js"): -1,
		filepath.FromSlash("/y/i.js"):     -1,
		"":                                -1,
	}
	for path, want := range tests {
		if got := innermostRoot(path, roots); got != want {
			t.Errorf("innermostRoot(%q) = %d, want %d", path, got, want)
		}
	}
}
