// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// serialOnlyParser hides the underlying parser's CloneParser method so the
// builder takes the serial path, letting the test compare serial vs parallel
// output for the same corpus.
type serialOnlyParser struct {
	inner Parser
}

func (s *serialOnlyParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	return s.inner.ParseDirectory(dir, packagePath)
}
func (s *serialOnlyParser) SkipDirs() map[string]bool { return s.inner.SkipDirs() }
func (s *serialOnlyParser) SubPackagePath(parent, dir string) string {
	return s.inner.SubPackagePath(parent, dir)
}
func (s *serialOnlyParser) PackageSeparator() string { return s.inner.PackageSeparator() }

// TestBuilder_ParallelParseMatchesSerial builds the same multi-directory Java
// tree through the serial path and the parallel path and requires the two
// graphs to be canonically identical. Guards the ordering contract of
// analyzePackageParallel: results must merge in serial pre-order so
// addAnalyses collision handling behaves the same.
func TestBuilder_ParallelParseMatchesSerial(t *testing.T) {
	root := t.TempDir()

	writeJava := func(rel, class, callee string) {
		dir := filepath.Join(root, filepath.Dir(rel))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		src := fmt.Sprintf(`package com.example.%s;

public class %s {
    public void run(byte[] data) {
        %s helper = new %s();
        helper.process(data);
    }
    public void process(byte[] data) {
        helper2.transform(data);
    }
}
`, filepath.Base(filepath.Dir(rel)), class, callee, callee)
		if err := os.WriteFile(filepath.Join(root, rel), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Several classes spread over nested directories so the parallel path has
	// real fan-out, including same-name methods across packages to exercise
	// dispatch expansion identically on both paths.
	for i := 0; i < 6; i++ {
		pkg := fmt.Sprintf("mod%d", i)
		writeJava(filepath.Join(pkg, fmt.Sprintf("Alpha%d.java", i)), fmt.Sprintf("Alpha%d", i), fmt.Sprintf("Beta%d", i))
		writeJava(filepath.Join(pkg, "deep", fmt.Sprintf("Beta%d.java", i)), fmt.Sprintf("Beta%d", i), fmt.Sprintf("Alpha%d", i))
	}

	serialGraph, err := NewBuilder(&serialOnlyParser{inner: NewJavaParser()}).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.example"}}, nil)
	if err != nil {
		t.Fatalf("serial BuildFromDirectories: %v", err)
	}

	parallelGraph, err := NewBuilder(NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.example"}}, nil)
	if err != nil {
		t.Fatalf("parallel BuildFromDirectories: %v", err)
	}

	if len(parallelGraph.Functions) == 0 {
		t.Fatal("parallel graph is empty; fixture did not parse")
	}
	serialDump := canonicalGraphDump(serialGraph)
	parallelDump := canonicalGraphDump(parallelGraph)
	if serialDump != parallelDump {
		t.Fatalf("parallel parse produced a different graph than serial parse:\nserial:\n%s\nparallel:\n%s", serialDump, parallelDump)
	}
}
