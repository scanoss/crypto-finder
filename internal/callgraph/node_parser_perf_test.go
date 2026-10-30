// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// nodeBundleSource writes a bundle the way esbuild and rollup do: one IIFE
// that declares every function of the bundle and many variables beside them.
func nodeBundleSource(functions int) string {
	var b strings.Builder
	b.WriteString("(function () {\n")
	for i := 0; i < functions; i++ {
		fmt.Fprintf(&b, "  var v%d = %d, w%d = [v%d];\n", i, i, i, i)
		fmt.Fprintf(&b, "  function f%d(a, b) {\n    var x = a + b;\n    w%d.map(f%d);\n    return [x].map((y) => y + v%d);\n  }\n", i, i, (i+1)%functions, i)
	}
	b.WriteString("})();\n")
	return b.String()
}

// Each function of a bundle used to re-walk the whole IIFE around it to learn
// the names its enclosing scopes bind, so parsing grew with the square of the
// bundle: a 13 MB bundle ran for over an hour, and this one took about three minutes.
// A parse linear in the bundle takes under a second, a few under -race; the
// bound leaves room for a loaded CI runner.
func TestNodeParser_BundleParsesInLinearTime(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("parses a large generated bundle")
	}
	const functions = 2000
	start := time.Now()
	analysis := parseNodeSource(t, nodeBundleSource(functions))
	elapsed := time.Since(start)
	if elapsed > 30*time.Second {
		t.Fatalf("parsing a bundle of %d functions took %s", functions, elapsed)
	}
	declared := 0
	for i := range analysis.Functions {
		if strings.HasPrefix(analysis.Functions[i].ID.Name, "f") {
			declared++
		}
	}
	if declared != functions {
		t.Fatalf("declared functions = %d, want %d", declared, functions)
	}
}

func BenchmarkNodeParser_Bundle(b *testing.B) {
	for _, functions := range []int{250, 500, 1000} {
		src := nodeBundleSource(functions)
		b.Run(fmt.Sprintf("functions=%d", functions), func(b *testing.B) {
			for b.Loop() {
				parseNodeSource(b, src)
			}
		})
	}
}
