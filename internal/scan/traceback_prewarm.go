// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/perf"
)

// prewarmTracebacks traces, concurrently, the functions structuralTracebackChains
// has not traced yet, and leaves the results in ctx.pretraced for it to consume
// in its own order. Each worker traces with a fork of the shared tracer; the
// module lookup the forks share fills ctx's path cache under a lock. The
// results are the ones the shared tracer would return: a trace reads only the
// graph, the edge index and module names.
func prewarmTracebacks(ctx *exportBuildContext, fns []*callgraph.FunctionDecl) {
	ensureCallChainCaches(ctx)
	var todo []callgraph.FunctionID
	seen := make(map[string]bool)
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		key := fn.ID.String()
		if _, traced := ctx.callChainRawCache[key]; traced || seen[key] {
			continue
		}
		if _, ready := ctx.pretraced[key]; ready {
			continue
		}
		seen[key] = true
		todo = append(todo, fn.ID)
	}
	workers := min(runtime.GOMAXPROCS(0), len(todo))
	if workers < 2 {
		return
	}

	span := perf.Start("export.tracebacks")
	defer span.End()
	shared := ctx.sharedTracer()
	var moduleMu sync.Mutex
	moduleOf := func(key string) string {
		moduleMu.Lock()
		defer moduleMu.Unlock()
		return ctx.traceModule(key)
	}
	maxChains := ctx.emitMaxChains()
	traces := make([]callgraph.CondensedTrace, len(todo))
	var next atomic.Int64
	next.Store(-1)
	var wg sync.WaitGroup
	for range workers {
		// Forked here, not in the worker: the first Fork builds the shared
		// edge index.
		tracer := shared.Fork(moduleOf)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1))
				if i >= len(todo) {
					return
				}
				traces[i] = tracer.TraceBackCondensed(todo[i], ctx.userPackages, ctx.maxDepth, maxChains)
			}
		}()
	}
	wg.Wait()

	if ctx.pretraced == nil {
		ctx.pretraced = make(map[string]callgraph.CondensedTrace, len(todo))
	}
	for i, id := range todo {
		ctx.pretraced[id.String()] = traces[i]
	}
}
