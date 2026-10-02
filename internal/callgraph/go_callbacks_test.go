// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

func buildGoCallbackGraph(t *testing.T, source string) *CallGraph {
	t.Helper()
	root := writePythonTree(t, map[string]string{"main.go": source})
	graph, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func TestBuilder_GoCallbackReferences(t *testing.T) {
	t.Parallel()
	const header = `package main

import (
	"context"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

var once sync.Once

func cmp(a, b int) int { return 0 }
func tick()           {}
func job()            {}
func task() error     { return nil }
func walk(p string, d fs.DirEntry, err error) error { return nil }
func less(i, j int) bool { return false }

`
	tests := []callbackCase{
		{
			name: "standard library callbacks",
			source: `func start(xs []int) {
	slices.SortFunc(xs, cmp)
	sort.Slice(xs, less)
	time.AfterFunc(time.Second, tick)
	filepath.WalkDir(".", walk)
}
`,
			want: []string{"app.start -> app.cmp", "app.start -> app.less", "app.start -> app.tick", "app.start -> app.walk"},
		},
		{
			name: "package variable Once and errgroup values",
			source: `func start(ctx context.Context) {
	once.Do(job)
	var g errgroup.Group
	g.Go(task)
}
`,
			want: []string{"app.start -> app.job", "app.start -> app.task"},
		},
		{
			name: "errgroup from WithContext",
			source: `func start(ctx context.Context) {
	g, _ := errgroup.WithContext(ctx)
	g.Go(task)
}
`,
			want: []string{"app.start -> app.task"},
		},
		{
			name: "unknown registrar",
			source: `func reg(f func()) { f() }

func start() {
	reg(job)
}
`,
			not: []string{"app.start -> app.job"},
		},
		{
			name: "function literal and call result arguments",
			source: `func make1() func() { return job }

func start() {
	once.Do(make1())
	once.Do(func() {})
}
`,
			not: []string{"app.start -> app.job"},
		},
		{
			name: "local variable shadows the function",
			source: `func start(xs []int) {
	job := func() {}
	once.Do(job)
}
`,
			not: []string{"app.start -> app.job"},
		},
		{
			name: "parameter shadows the function",
			source: `func start(job func()) {
	once.Do(job)
}
`,
			not: []string{"app.start -> app.job"},
		},
		{
			name: "name that resolves to nothing",
			source: `func start() {
	once.Do(ghost)
	once.Do(other.Thing)
}
`,
			not: []string{"app.start -> app.ghost"},
		},
		{
			name: "argument position that takes no callback",
			source: `func start(xs []int) {
	sort.Slice(job, nil)
	time.AfterFunc(0, nil)
}
`,
			not: []string{"app.start -> app.job"},
		},
		{
			name: "method value is left unresolved",
			source: `type T struct{}

func (T) m() {}

func start(t T) {
	once.Do(t.m)
}
`,
			not: []string{"app.start -> app.(T).m"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildGoCallbackGraph(t, header+tc.source)
			checkCallbackEdges(t, graph, tc)
		})
	}
}

// A handler field assigned after the literal is built is an entry point, as
// it is in &cobra.Command{RunE: run}.
func TestBuilder_GoAssignedHandlerFieldIsAnEntryPoint(t *testing.T) {
	t.Parallel()
	graph := buildGoCallbackGraph(t, `package main

import "github.com/spf13/cobra"

type own struct{ RunE func() }

type holder struct{ cmd *cobra.Command }

func run1()      {}
func run2()      {}
func run3()      {}
func run4()      {}
func complete()  {}
func ownRun()    {}
func untouched() {}

func build(c *cobra.Command, h *holder) {
	cmd := &cobra.Command{}
	cmd.RunE = run1
	c.PreRunE = run2
	h.cmd.PostRun = run3
	cmd.Use, cmd.ValidArgsFunction = "x", complete
	o := &own{}
	o.RunE = ownRun
	cmd.RunE = func() {}
}
`)
	for _, name := range []string{"run1", "run2", "run3"} {
		if got := graph.Functions["app."+name].EntryKind; got == "" {
			t.Errorf("%s is not an entry point, want the cobra handler it is assigned to", name)
		}
	}
	for _, name := range []string{"run4", "complete", "ownRun", "untouched"} {
		if got := graph.Functions["app."+name].EntryKind; got != "" {
			t.Errorf("%s is an entry point (%q), want none", name, got)
		}
	}
}
