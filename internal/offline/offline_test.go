// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package offline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gf "github.com/scanoss/reach/graphfrag"

	pr "github.com/scanoss/crypto-finder/pkg/appreach"
	"github.com/scanoss/crypto-finder/pkg/schema"
)

// fakeMiner mines a one-function component whose report holds one asset,
// with the absolute paths crypto-finder writes for a scanned directory.
type fakeMiner struct {
	mu        sync.Mutex
	mined     []string
	annotated int
	typeJARs  [][]string
}

func (m *fakeMiner) Mine(_ context.Context, dir string, typeJARs []string) ([]byte, []byte, error) {
	m.mu.Lock()
	m.mined = append(m.mined, dir)
	m.typeJARs = append(m.typeJARs, typeJARs)
	m.mu.Unlock()
	file := filepath.Join(dir, "p", "A.java")
	fragment := fmt.Sprintf(`{"schema_version":%q,"scan_metadata":{"root_module":"","rules_version":"r"},"functions":[{"key":"p.(A).f#0","function_name":"p.A.f","file_path":%q,"start_line":1,"end_line":9}],"crypto_annotations":[]}`, gf.SchemaVersion, file)
	return []byte(m.report(file)), []byte(fragment), nil
}

func (m *fakeMiner) report(file string) string {
	return fmt.Sprintf(`{"version":%q,"findings":[{"file_path":%q,"language":"java","cryptographic_assets":[{"finding_id":"f1","match":"Cipher.getInstance(\"AES\")","source":"direct","start_line":3,"end_line":3,"metadata":{"algorithmName":"AES"}}]}]}`, schema.InterimFormatVersion, file)
}

func (m *fakeMiner) Annotate(context.Context, []byte, func(context.Context) (string, error)) ([]byte, []byte, error) {
	m.mu.Lock()
	m.annotated++
	m.mu.Unlock()
	return []byte(fmt.Sprintf(`{"schema_version":%q,"crypto_annotations":[]}`, gf.SchemaVersion)), []byte(m.report("p/A.java")), nil
}

func testDependency(t *testing.T, name string, jars []string, sources error) Dependency {
	t.Helper()
	return Dependency{
		Key:      gf.ComponentKey{Purl: "pkg:maven/g/" + name, Version: "1.0"},
		Module:   "g:" + name,
		TypeJARs: jars,
		SourcesJAR: func(context.Context) (string, error) {
			if sources != nil {
				return "", sources
			}
			return name + "-1.0-sources.jar", nil
		},
	}
}

func testOptions(t *testing.T, cacheDir, rulesetKey string, miner Miner) Options {
	t.Helper()
	cache, err := OpenCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	extracted := t.TempDir()
	return Options{
		Cache: cache, RulesetKey: rulesetKey, RulesVersion: "rules-" + rulesetKey, Miner: miner, Workers: 2,
		Extract: func(_, module, version string) (string, error) {
			dir := filepath.Join(extracted, module, version)
			return dir, os.MkdirAll(dir, 0o750)
		},
	}
}

func writeJAR(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The first run mines, a second run reads the cache, a new ruleset
// re-annotates the cached graph, and a dependency without sources is served
// without data, its message saying why.
func TestPrepareMinesCachesAndReannotates(t *testing.T) {
	cacheDir, jars := t.TempDir(), t.TempDir()
	jar := writeJAR(t, jars, "b-1.0.jar", "b")
	deps := []Dependency{
		testDependency(t, "a", []string{jar}, nil),
		testDependency(t, "nosrc", nil, errors.New("no sources JAR for g:nosrc:1.0")),
	}

	miner := &fakeMiner{}
	got, stats, _ := Prepare(context.Background(), deps, testOptions(t, cacheDir, "k1", miner))
	if stats.Mined != 1 || stats.Unavailable != 1 || stats.Cached != 0 || len(miner.mined) != 1 {
		t.Fatalf("first run %+v, mined %v", stats, miner.mined)
	}
	if len(miner.typeJARs[0]) != 1 || miner.typeJARs[0][0] != jar {
		t.Errorf("mined with type JARs %v, want the dependency's closure", miner.typeJARs)
	}
	a := got[deps[0].Key]
	if a.Fragment == nil || a.Stored == nil || a.Fragment.RulesVersion != "rules-k1" {
		t.Fatalf("mined component %+v", a)
	}
	if path := a.Stored.Findings[0].FilePath; path != "p/A.java" {
		t.Errorf("stored report path %q, want relative to the mined directory", path)
	}
	if fn := a.Fragment.Functions; len(fn) != 1 {
		t.Errorf("graph functions %+v", fn)
	}
	if missing := got[deps[1].Key]; missing.Fragment != nil || missing.Code != pr.InfoNoInfo || !strings.Contains(missing.Message, "no sources JAR") {
		t.Errorf("component without sources %+v", missing)
	}

	again := &fakeMiner{}
	_, stats, _ = Prepare(context.Background(), deps, testOptions(t, cacheDir, "k1", again))
	if stats.Cached != 1 || stats.Mined != 0 || len(again.mined) != 0 || again.annotated != 0 {
		t.Errorf("second run %+v: want the cached dependency read, nothing mined", stats)
	}

	reannotate := &fakeMiner{}
	got, stats, _ = Prepare(context.Background(), deps, testOptions(t, cacheDir, "k2", reannotate))
	if stats.Reannotated != 1 || len(reannotate.mined) != 0 || reannotate.annotated != 1 || got[deps[0].Key].Fragment.RulesVersion != "rules-k2" {
		t.Errorf("new ruleset %+v: want the cached graph re-annotated, not mined", stats)
	}

	// Another closure JAR is another graph: mined again.
	if err := os.WriteFile(jar, []byte("b, rebuilt"), 0o600); err != nil {
		t.Fatal(err)
	}
	rebuilt := &fakeMiner{}
	_, stats, _ = Prepare(context.Background(), deps, testOptions(t, cacheDir, "k1", rebuilt))
	if stats.Mined != 1 || len(rebuilt.mined) != 1 {
		t.Errorf("changed closure JAR %+v: want the dependency mined again", stats)
	}
}

func TestGraphAndRulesetKeys(t *testing.T) {
	base := GraphKey("pkg:maven/g/a", "1", "", []string{"d1", "d2"}, "algo-1", "s-1")
	for name, other := range map[string]string{
		"version":   GraphKey("pkg:maven/g/a", "2", "", []string{"d1", "d2"}, "algo-1", "s-1"),
		"jar order": GraphKey("pkg:maven/g/a", "1", "", []string{"d2", "d1"}, "algo-1", "s-1"),
		"jar":       GraphKey("pkg:maven/g/a", "1", "", []string{"d1"}, "algo-1", "s-1"),
		"algo":      GraphKey("pkg:maven/g/a", "1", "", []string{"d1", "d2"}, "algo-2", "s-1"),
		"sources":   GraphKey("pkg:maven/g/a", "1", "x", []string{"d1", "d2"}, "algo-1", "s-1"),
	} {
		if other == base {
			t.Errorf("%s does not change the graph key", name)
		}
	}

	dir := t.TempDir()
	writeJAR(t, dir, "rule.yaml", "a")
	k1, err := RulesetKey([]string{dir}, nil, []string{"v1"})
	if err != nil {
		t.Fatal(err)
	}
	writeJAR(t, dir, "rule.yaml", "b")
	k2, _ := RulesetKey([]string{dir}, nil, []string{"v1"})
	k3, _ := RulesetKey([]string{dir}, nil, []string{"v2"})
	if k1 == k2 || k2 == k3 {
		t.Errorf("ruleset keys %s %s %s: content and labels must change the key", k1, k2, k3)
	}
}

// The per-run copies a ruleset cache keeps beside its versions
// (.crypto-finder-filtered/<version>/run-*) come and go with the scans that
// made them: they are never part of a hashed rules tree.
func TestRulesetKeySkipsPerRunCopies(t *testing.T) {
	dir := t.TempDir()
	writeJAR(t, dir, "v1/rule.yaml", "a")
	before, err := RulesetKey([]string{dir}, nil, []string{"v1"})
	if err != nil {
		t.Fatal(err)
	}
	writeJAR(t, dir, ".crypto-finder-filtered/v1/run-1/rule.yaml", "b")
	after, err := RulesetKey([]string{dir}, nil, []string{"v1"})
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("a per-run copy changed the key: %s, want %s", after, before)
	}
}

func TestRelativePaths(t *testing.T) {
	dir := t.TempDir()
	in := []byte(fmt.Sprintf(`{"findings":[{"file_path":%q,"n":12345678901234567890}],"other":{"file_path":"rel/B.java"}}`, filepath.Join(dir, "p", "A.java")))
	out := string(relativePaths(in, dir))
	if !strings.Contains(out, `"file_path":"p/A.java"`) || !strings.Contains(out, `12345678901234567890`) || !strings.Contains(out, `"file_path":"rel/B.java"`) {
		t.Errorf("rewritten %s", out)
	}
	unchanged := []byte(`{"file_path": "p/A.java"}`)
	if got := relativePaths(unchanged, dir); !bytes.Equal(got, unchanged) {
		t.Errorf("a document with no absolute path must keep its bytes: %s", got)
	}
}

// A budget lets through what fits and holds the rest until it is released.
func TestBudget(t *testing.T) {
	b := newBudget(10)
	if err := b.acquire(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.acquire(ctx, 6) }()
	b.release(6)
	if err := <-done; err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	cancel()
	if err := b.acquire(ctx, 6); err == nil {
		t.Fatal("acquire beyond the budget with a canceled context must fail")
	}
}

// blockingMiner mines nothing until released, as a call graph build that
// cannot be interrupted.
type blockingMiner struct {
	fakeMiner
	started chan string
	release chan struct{}
}

func (m *blockingMiner) Mine(ctx context.Context, dir string, typeJARs []string) ([]byte, []byte, error) {
	m.started <- dir
	<-m.release
	return m.fakeMiner.Mine(ctx, dir, typeJARs)
}

// When the scan's time runs out while a dependency is being mined, Prepare
// fails with the deadline at once, without waiting for that mine, and starts
// no further dependency. The mine under way still fills the cache when it
// finishes, so the next run reads it.
func TestPrepareStopsWhenTheScanTimesOut(t *testing.T) {
	cacheDir := t.TempDir()
	deps := []Dependency{testDependency(t, "a", nil, nil), testDependency(t, "b", nil, nil)}
	miner := &blockingMiner{started: make(chan string, 2), release: make(chan struct{})}
	opts := testOptions(t, cacheDir, "k1", miner)
	opts.Workers = 1
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	type result struct {
		got map[gf.ComponentKey]pr.Component
		err error
	}
	results := make(chan result, 1)
	go func() {
		got, _, err := Prepare(ctx, deps, opts)
		results <- result{got, err}
	}()
	<-miner.started
	select {
	case r := <-results:
		if r.got != nil || !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("Prepare = %v, %v; want the deadline's error", r.got, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare waited for the mine under way")
	}
	close(miner.release)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if found, _ := filepath.Glob(filepath.Join(cacheDir, "*", "rules-*", findingsFile)); len(found) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the abandoned mine never reached the cache")
		}
	}
	got, stats, err := Prepare(context.Background(), deps[:1], testOptions(t, cacheDir, "k1", unusedMiner{t}))
	if err != nil || stats.Cached != 1 || got[deps[0].Key].Fragment == nil {
		t.Errorf("next run %+v, %v: want the dependency read from the cache", stats, err)
	}
	if len(miner.started) != 0 {
		t.Errorf("a dependency was started after the deadline: %s", <-miner.started)
	}
}

// unusedMiner fails the test when it is asked to mine or annotate.
type unusedMiner struct{ t *testing.T }

func (m unusedMiner) Mine(context.Context, string, []string) ([]byte, []byte, error) {
	m.t.Error("a cached dependency was mined again")
	return nil, nil, errors.New("not mined")
}

func (m unusedMiner) Annotate(context.Context, []byte, func(context.Context) (string, error)) ([]byte, []byte, error) {
	m.t.Error("a cached dependency was annotated again")
	return nil, nil, errors.New("not annotated")
}
