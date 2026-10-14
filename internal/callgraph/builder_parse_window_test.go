package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// stalledFirstParser parses the directory first only once the other
// directories stop being parsed, so the parse of every later package runs
// while package first waits to be merged.
type stalledFirstParser struct {
	first string
	// later counts the directories other than first parsed so far; ahead is
	// how many of them were parsed while first was still stalled.
	later, ahead *atomic.Int64
}

func (p stalledFirstParser) ParseDirectory(dir, _ string) ([]*FileAnalysis, error) {
	if dir != p.first {
		p.later.Add(1)
		return nil, nil
	}
	for last := int64(-1); ; time.Sleep(50 * time.Millisecond) {
		now := p.later.Load()
		if now == last {
			p.ahead.Store(now)
			return nil, nil
		}
		last = now
	}
}

func (p stalledFirstParser) SubPackagePath(parent, dir string) string { return parent + "/" + dir }
func (p stalledFirstParser) PackageSeparator() string                 { return "/" }
func (p stalledFirstParser) CloneParser() Parser                      { return p }

// A slow first package holds back the parse of the packages after it once
// the window is full, so their analyses do not all wait in memory for it.
func TestAnalyzePackagesParallel_BoundsPackagesParsedAheadOfMerge(t *testing.T) {
	t.Parallel()

	const workers, packageCount = 2, 100
	root := t.TempDir()
	packages := make([]PackageDir, packageCount)
	for i := range packages {
		packages[i] = PackageDir{Dir: filepath.Join(root, fmt.Sprintf("pkg%d", i)), ImportPath: "example.com/p"}
		if err := os.Mkdir(packages[i].Dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	parser := stalledFirstParser{first: packages[0].Dir, later: &atomic.Int64{}, ahead: &atomic.Int64{}}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{}, Callers: map[string][]string{}}

	errs := NewBuilderForEcosystem("go", parser).analyzePackagesParallel(packages, graph, parser, workers)

	for i, err := range errs {
		if err != nil {
			t.Fatalf("package %d: %v", i, err)
		}
	}
	if got, want := parser.later.Load(), int64(packageCount-1); got != want {
		t.Fatalf("later packages parsed = %d, want %d", got, want)
	}
	if got, limit := parser.ahead.Load(), int64(workers*parsePackageWindow-1); got > limit {
		t.Errorf("packages parsed ahead of the stalled first one = %d, want at most %d", got, limit)
	}
}
