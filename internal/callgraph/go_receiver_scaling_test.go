// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// receiverBoundOnceTime parses one function holding `pairs` bindings, each used
// by one selector call, and times asking every call whether its receiver is
// bound once.
func receiverBoundOnceTime(t *testing.T, pairs int) time.Duration {
	t.Helper()
	var text strings.Builder
	text.WriteString("package mypkg\n\ntype T struct{}\n\nfunc (T) Use() {}\n\nfunc big() {\n")
	for i := 0; i < pairs; i++ {
		fmt.Fprintf(&text, "\tv%d := T{}\n\tv%d.Use()\n", i, i)
	}
	text.WriteString("}\n")
	src := []byte(text.String())
	parser := sitter.NewParser()
	parser.SetLanguage(golang.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()

	var selectors []*sitter.Node
	var collect func(*sitter.Node)
	collect = func(n *sitter.Node) {
		if n.Type() == goNodeSelectorExpression {
			selectors = append(selectors, n)
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			collect(n.Child(i))
		}
	}
	collect(tree.RootNode())
	if len(selectors) != pairs {
		t.Fatalf("found %d selector calls, want %d", len(selectors), pairs)
	}

	var indexes goBindingIndexes
	start := time.Now()
	for i, selector := range selectors {
		if !indexes.boundOnce(selector, fmt.Sprintf("v%d", i), src) {
			t.Fatalf("v%d is bound once above its call", i)
		}
	}
	return time.Since(start)
}

// TestGoReceiverBoundOnce_CostDoesNotGrowWithFunctionSize pins that answering
// for every call of one function costs one walk of it, not one walk per call.
// A per-call walk is quadratic: quadrupling the calls multiplies the time by
// about sixteen, where one shared index stays near four.
func TestGoReceiverBoundOnce_CostDoesNotGrowWithFunctionSize(t *testing.T) {
	const small, large = 500, 2000
	best := func(pairs int) time.Duration {
		fastest := receiverBoundOnceTime(t, pairs)
		for i := 0; i < 2; i++ {
			if d := receiverBoundOnceTime(t, pairs); d < fastest {
				fastest = d
			}
		}
		return fastest
	}
	smallTime, largeTime := best(small), best(large)
	ratio := float64(largeTime) / float64(smallTime)
	t.Logf("%d calls %v, %d calls %v, ratio %.1f", small, smallTime, large, largeTime, ratio)
	if ratio > 9 {
		t.Fatalf("time grew %.1fx for %dx the calls in one function, want linear (about 4x)", ratio, large/small)
	}
}
