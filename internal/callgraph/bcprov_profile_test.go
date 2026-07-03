// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

// bcprov_profile_test.go — a one-off profiling harness for the
// perf/mdaloia/dispatch-expansion-hotpath investigation. Not a regression
// test: gated on CRYPTO_FINDER_BCPROV_SRC so it never runs in CI. Point it at
// an unpacked bcprov-jdk15on source tree and run with -cpuprofile to find the
// hotspot in the dispatch-expansion machinery added by PR #57/#58.
//
// Example:
//
//	CRYPTO_FINDER_BCPROV_SRC=/path/to/bcprov/src go test \
//	  -run TestProfileBcprov -cpuprofile cpu.out -timeout 15m ./internal/callgraph/
//	go tool pprof -top -nodecount=20 cpu.out

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func bcprovSourceDir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("CRYPTO_FINDER_BCPROV_SRC")
	if dir == "" {
		t.Skip("set CRYPTO_FINDER_BCPROV_SRC to an unpacked bcprov-jdk15on src dir to run this profiling harness")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("bcprov fixture source not available at %s: %v", dir, err)
	}
	return dir
}

func password4jSourceDirForEquivalence(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("CRYPTO_FINDER_PASSWORD4J_SRC")
	if dir == "" {
		t.Skip("set CRYPTO_FINDER_PASSWORD4J_SRC to a password4j src/main/java checkout to run this equivalence check")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("password4j fixture source not available at %s: %v", dir, err)
	}
	return dir
}

// TestProfileBcprov builds the call graph over the full bcprov source tree
// once. Run under `go test -cpuprofile` to capture a CPU profile of the
// build pipeline (parse + buildCallerIndex dispatch expansion +
// resolveParameterPassthroughDispatch + inference).
func TestProfileBcprov(t *testing.T) {
	dir := bcprovSourceDir(t)

	builder := NewBuilder(NewJavaParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "org.bouncycastle"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(bcprov): %v", err)
	}

	t.Logf("functions=%d callers=%d edgeResolutions=%d", len(graph.Functions), len(graph.Callers), len(graph.EdgeResolutions))
}

// canonicalGraphDump renders graph.Callers and graph.EdgeResolutions as a
// fully sorted, deterministic text dump so two builds (e.g. before/after an
// algorithmic change to the dispatch-expansion passes) can be compared byte
// for byte. Any difference here means the change altered observable output,
// not just performance.
func canonicalGraphDump(graph *CallGraph) string {
	var b strings.Builder

	fmt.Fprintf(&b, "functions=%d\n", len(graph.Functions))

	calleeKeys := make([]string, 0, len(graph.Callers))
	for k := range graph.Callers {
		calleeKeys = append(calleeKeys, k)
	}
	sort.Strings(calleeKeys)
	fmt.Fprintf(&b, "callers_entries=%d\n", len(calleeKeys))
	for _, calleeKey := range calleeKeys {
		callers := append([]string(nil), graph.Callers[calleeKey]...)
		sort.Strings(callers)
		fmt.Fprintf(&b, "CALLERS %s <- %s\n", calleeKey, strings.Join(callers, ","))
	}

	edgeKeys := make([]string, 0, len(graph.EdgeResolutions))
	for k := range graph.EdgeResolutions {
		edgeKeys = append(edgeKeys, k)
	}
	sort.Strings(edgeKeys)
	fmt.Fprintf(&b, "edge_resolutions=%d\n", len(edgeKeys))
	for _, k := range edgeKeys {
		res := graph.EdgeResolutions[k]
		fmt.Fprintf(&b, "EDGE %s kind=%s declaredType=%s method=%s arity=%d callSite=%d resolvedReceiverType=%s\n",
			k, res.Kind, res.DeclaredType, res.MethodName, res.Arity, res.CallSite, res.ResolvedReceiverType)
	}

	return b.String()
}

// dumpGraphEquivalence builds the call graph for dir and writes a canonical
// sorted dump plus its sha256 to outPath, then logs the hash and top-level
// counts. Used to diff builder.go's output before vs after an algorithmic
// change — see perf/mdaloia/dispatch-expansion-hotpath.
func dumpGraphEquivalence(t *testing.T, dir, importPath, outPath string) {
	t.Helper()

	builder := NewBuilder(NewJavaParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(%s): %v", importPath, err)
	}

	dump := canonicalGraphDump(graph)
	sum := sha256.Sum256([]byte(dump))
	hash := hex.EncodeToString(sum[:])

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, []byte(dump), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", outPath, err)
	}

	t.Logf("functions=%d callers=%d edgeResolutions=%d sha256=%s dump=%s",
		len(graph.Functions), len(graph.Callers), len(graph.EdgeResolutions), hash, outPath)
}

// TestEquivalenceDumpBcprov writes a canonical sorted dump of the bcprov call
// graph's Callers/EdgeResolutions to CRYPTO_FINDER_EQUIV_OUT (or a default
// scratch path) so it can be diffed against a dump taken on the other side of
// an algorithmic change. Gated on CRYPTO_FINDER_BCPROV_SRC; not a CI test.
func TestEquivalenceDumpBcprov(t *testing.T) {
	dir := bcprovSourceDir(t)
	out := os.Getenv("CRYPTO_FINDER_EQUIV_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "bcprov_equivalence_dump.txt")
	}
	dumpGraphEquivalence(t, dir, "org.bouncycastle", out)
}

// TestEquivalenceDumpPassword4j is TestEquivalenceDumpBcprov's counterpart
// for the password4j fixture used by TestStitch_RealParse_Password4j in
// internal/scan, giving a second, structurally different corpus for the
// same before/after equivalence check.
func TestEquivalenceDumpPassword4j(t *testing.T) {
	dir := password4jSourceDirForEquivalence(t)
	out := os.Getenv("CRYPTO_FINDER_EQUIV_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "password4j_equivalence_dump.txt")
	}
	dumpGraphEquivalence(t, dir, "com.password4j", out)
}
