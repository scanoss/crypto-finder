// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
	pr "github.com/scanoss/crypto-finder/pkg/appreach"
)

// The offline mode mines a dependency in process with what the miner's
// crypto-finder run writes: the same findings report and graph fragment, byte
// for byte, as `scan --languages java --output --export-graph-fragment`, and
// the same annotation and findings as `annotate --findings-output` over the
// stored graph. Two dependencies are mined at once, as an offline scan does.
func TestInProcessMinerWritesWhatTheScanWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	writeAnnotateCardsFile(t, filepath.Join(source, "org", "example", "Box.java"), annotateCardsJava)
	other := filepath.Join(dir, "other")
	writeAnnotateCardsFile(t, filepath.Join(other, "org", "example", "Box.java"), strings.ReplaceAll(annotateCardsJava, "AES/GCM/NoPadding", "DES"))
	ruleset := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "semgrep-rules", "java", "x", "rules.yaml"), annotateCardsRules)
	t.Setenv("HOME", dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	ruleArgs := []string{"--no-remote-rules", "--rules-dir", ruleset}
	scanFindings, scanFragment := filepath.Join(dir, "findings.json"), filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--languages", "java", "--output", scanFindings, "--export-graph-fragment", scanFragment, source}, ruleArgs...)...)

	miner := &inProcessMiner{
		rules:       rules.NewManager(&lockedRules{manager: rules.NewManager(rules.NewLocalRuleSource(nil, []string{ruleset}))}),
		ruleDirs:    []string{ruleset},
		javaRuntime: javaruntime.Config{},
		timeout:     5 * time.Minute,
		catalogs:    cards.NewCatalogs(),
	}
	type mined struct{ findings, fragment []byte }
	results := make(chan mined, 1)
	go func() {
		findings, fragment, err := miner.Mine(context.Background(), other, nil)
		if err != nil {
			t.Error(err)
		}
		results <- mined{findings, fragment}
	}()
	findings, fragment, err := miner.Mine(context.Background(), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	concurrent := <-results
	assertSameBytes(t, "findings", readBytes(t, scanFindings), findings)
	assertSameBytes(t, "fragment", withoutExportTime(readBytes(t, scanFragment)), withoutExportTime(fragment))
	if bytes.Contains(concurrent.findings, []byte("GCM")) || !bytes.Contains(concurrent.fragment, []byte(`\"DES\"`)) {
		t.Errorf("the dependency mined beside it holds another's code or findings:\n%s", concurrent.findings)
	}

	structural, err := graphfrag.StructuralExport(fragment)
	if err != nil {
		t.Fatal(err)
	}
	structuralPath := filepath.Join(dir, "structural.json")
	if err := os.WriteFile(structuralPath, structural, 0o600); err != nil {
		t.Fatal(err)
	}
	annotation, annotateFindings := filepath.Join(dir, "annotation.json"), filepath.Join(dir, "annotate-findings.json")
	run(append([]string{"annotate", "--import-fragment", structuralPath, "--output", annotation, "--findings-output", annotateFindings}, ruleArgs...)...)
	gotAnnotation, gotFindings, err := miner.Annotate(context.Background(), structural, func(context.Context) (string, error) {
		t.Error("a Java annotation reads the stored graph alone, not the sources")
		return "", os.ErrNotExist
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, "annotation", withoutExportTime(readBytes(t, annotation)), withoutExportTime(gotAnnotation))
	assertSameBytes(t, "annotate findings", readBytes(t, annotateFindings), gotFindings)
}

// A dependency is typed by the compiled JARs of its own subtree of the
// resolved tree, not by its parents' or siblings'.
func TestClosureJARs(t *testing.T) {
	dep := func(module, jar string) dependency.Dependency {
		return dependency.Dependency{Module: module, Version: "1", CompiledArtifactPath: jar}
	}
	a, b, c, d, e := dep("g:a", "/m2/a.jar"), dep("g:b", "/m2/b.jar"), dep("g:c", ""), dep("g:d", "/m2/d.jar"), dep("g:e", "/m2/e.jar")
	ref := func(x dependency.Dependency) dependency.Ref {
		return dependency.Ref{Module: x.Module, Version: x.Version}
	}
	byRef := map[string]dependency.Dependency{}
	for _, x := range []dependency.Dependency{a, b, c, d, e} {
		byRef[ref(x).Key()] = x
	}
	graph := map[string][]dependency.Ref{
		ref(a).Key(): {ref(c), ref(b)},
		ref(c).Key(): {ref(d), ref(a)},
		ref(e).Key(): {ref(a)},
	}
	if got := closureJARs(&dependency.ResolveResult{VersionedGraph: graph}, byRef, a); strings.Join(got, ",") != "/m2/b.jar,/m2/d.jar" {
		t.Errorf("a's closure JARs %v, want b and d (c has none; a is itself)", got)
	}
	if got := closureJARs(&dependency.ResolveResult{VersionedGraph: graph}, byRef, b); len(got) != 0 {
		t.Errorf("a leaf's closure JARs %v, want none", got)
	}
}

// Maven's tree prints a dependency's subtree once: bcprov, which the
// project declares itself, is "omitted for duplicate" under bcpkix and under
// bcutil, so the tree gives bcutil no children at all. Mined without bcprov's
// classes, bcutil's calls into them were exported name_only, and an offline
// scan read findings the API (which mines bcutil with its whole closure)
// proves unreachable as unknown, and some it proves unknown as unreachable.
// The omitted edges are part of each dependency's closure.
func TestClosureJARsFollowOmittedEdges(t *testing.T) {
	dep := func(module, jar string) dependency.Dependency {
		return dependency.Dependency{Module: module, Version: "1.78.1", CompiledArtifactPath: jar}
	}
	prov, pkix, util := dep("org.bouncycastle:bcprov-jdk18on", "/m2/bcprov.jar"), dep("org.bouncycastle:bcpkix-jdk18on", "/m2/bcpkix.jar"), dep("org.bouncycastle:bcutil-jdk18on", "/m2/bcutil.jar")
	ref := func(x dependency.Dependency) dependency.Ref {
		return dependency.Ref{Module: x.Module, Version: x.Version}
	}
	byRef := map[string]dependency.Dependency{}
	for _, x := range []dependency.Dependency{prov, pkix, util} {
		byRef[ref(x).Key()] = x
	}
	resolved := &dependency.ResolveResult{
		VersionedGraph: map[string][]dependency.Ref{
			"com.example:app:1": {ref(prov), ref(pkix)},
			ref(pkix).Key():     {ref(util)},
		},
		OmittedEdges: map[string][]dependency.Ref{
			ref(pkix).Key(): {ref(prov)},
			ref(util).Key(): {ref(prov)},
		},
	}
	if got := closureJARs(resolved, byRef, util); strings.Join(got, ",") != "/m2/bcprov.jar" {
		t.Errorf("bcutil's closure JARs %v, want bcprov's (omitted for duplicate under bcutil)", got)
	}
	if got := closureJARs(resolved, byRef, pkix); strings.Join(got, ",") != "/m2/bcprov.jar,/m2/bcutil.jar" {
		t.Errorf("bcpkix's closure JARs %v, want bcprov's and bcutil's", got)
	}
}

// withoutExportTime blanks the export time of a fragment or an annotation
// (compact or indented JSON), the one field two exports of the same graph
// differ in.
func withoutExportTime(fragment []byte) []byte {
	return exportedAt.ReplaceAll(fragment, []byte(`"exported_at":""`))
}

var exportedAt = regexp.MustCompile(`"exported_at":\s*"[^"]*"`)

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a test file.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertSameBytes(t *testing.T, what string, want, got []byte) {
	t.Helper()
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from the CLI's (%d vs %d bytes)\n cli: %.400s\n got: %.400s", what, len(want), len(got), want, got)
	}
}

// An npm dependency is mined from its package directory under the project's
// node_modules, found by name and version; one that is not installed is left
// out, and served without data.
func TestOfflineNodeDependencies(t *testing.T) {
	target := t.TempDir()
	files := map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"@noble/hashes":"^1.3.0","absent":"^1.0.0"}},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/absent":{"version":"1.0.0"}}}`,
		"node_modules/@noble/hashes/package.json": `{"name":"@noble/hashes","version":"1.3.2"}`,
	}
	for name, text := range files {
		writeAnnotateCardsFile(t, filepath.Join(target, name), text)
	}
	plan, skip, err := planNodeReachability(context.Background(), newGraphStore(target, ""), target, nil)
	if err != nil || plan == nil {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	keys := []pr.ComponentKey{
		{Purl: "pkg:npm/%40noble/hashes", Version: "1.3.2"},
		{Purl: "pkg:npm/absent", Version: "1.0.0"},
	}
	deps := offlineNodeDependencies(plan, keys)
	if len(deps) != 1 || deps[0].Key != keys[0] || deps[0].Module != "@noble/hashes" {
		t.Fatalf("dependencies = %+v, want only @noble/hashes", deps)
	}
	dir, err := deps[0].SourcesDir(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("node_modules", "@noble", "hashes"); !strings.HasSuffix(dir, want) {
		t.Errorf("sources dir = %s, want it to end in %s", dir, want)
	}
}

// A Rust dependency is mined from the source directory the Cargo resolver
// found (vendor/ here), keyed by its crates package URL; the dev-only crate
// is not in the closure and one with no source directory would be left out.
func TestOfflineRustDependencies(t *testing.T) {
	target := t.TempDir()
	writeRustProject(t, target)
	plan, skip, err := planRustReachability(context.Background(), newGraphStore(target, ""), target, nil)
	if err != nil || plan == nil {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	keys := []pr.ComponentKey{
		{Purl: "pkg:cargo/acme-sign", Version: "2.0.1"},
		{Purl: "pkg:cargo/acme-dev", Version: "0.5.0"},
	}
	deps := offlineSourceDirDependencies(plan, keys)
	if len(deps) != 1 || deps[0].Key != keys[0] || deps[0].Module != "acme-sign" {
		t.Fatalf("dependencies = %+v, want only acme-sign", deps)
	}
	dir, err := deps[0].SourcesDir(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(target, "vendor", "acme-sign"); dir != want {
		t.Errorf("sources dir = %s, want %s", dir, want)
	}
	if deps[0].SourcesDigest != "" {
		t.Errorf("sources digest = %q: a registry crate is keyed by its version alone", deps[0].SourcesDigest)
	}
}

// A Go module a local directory replaces is mined offline from that
// directory, keyed by what it holds: an edit to it is mined again, not served
// from the cache under the same version.
func TestOfflineGoLocalReplacement(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app/go.mod", "module example.com/app\n\ngo 1.22\n\nrequire example.com/liba v1.0.0\n\nreplace example.com/liba => ../liba\n")
	write("app/main.go", "package main\n\nfunc main() {}\n")
	write("liba/go.mod", "module example.com/liba\n")
	write("liba/liba.go", "package liba\n")
	target := filepath.Join(root, "app")
	plan, skip, err := planGoReachability(context.Background(), newGraphStore(target, ""), target, nil)
	if err != nil || plan == nil {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	keys := []pr.ComponentKey{{Purl: "pkg:golang/example.com/liba", Version: "v1.0.0"}}
	deps := offlineSourceDirDependencies(plan, keys)
	if len(deps) != 1 || deps[0].Module != "example.com/liba" {
		t.Fatalf("dependencies = %+v, want liba", deps)
	}
	dir, err := deps[0].SourcesDir(context.Background())
	if err != nil || dir != filepath.Join(root, "liba") {
		t.Fatalf("sources dir = %s (%v), want %s", dir, err, filepath.Join(root, "liba"))
	}
	before := deps[0].SourcesDigest
	write("liba/liba.go", "package liba\n\nfunc New() {}\n")
	if after := offlineSourceDirDependencies(plan, keys)[0].SourcesDigest; before == "" || after == before {
		t.Errorf("sources digest %q, then %q after an edit: want a digest that follows the directory", before, after)
	}
}
