// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"runtime"
	"sync"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// fragmentEdgeWorkers is how many goroutines build graph-fragment edges.
// Tests pin it to compare the serial and the parallel build.
var fragmentEdgeWorkers = func() int { return runtime.GOMAXPROCS(0) }

const (
	// fragmentEdgeItemCallers is about how many caller-callee pairs one work
	// item covers: enough to amortize the hand-off, few enough to keep the
	// workers balanced. A callee with more callers is cut into several items,
	// so one widely called function does not leave the other workers idle.
	fragmentEdgeItemCallers = 256
	// fragmentEdgeWindow bounds, per worker, how many work items may be built
	// ahead of the one being consumed, so the edges held in memory stay a
	// small window of the graph instead of all of it.
	fragmentEdgeWindow = 4
)

// fragmentEdges is a run of graph-fragment edges in emission order: the
// internal edges in order and the external calls, of one callee or of a run
// of its callers.
type fragmentEdges struct {
	internal []graphfrag.GraphFragmentEdge
	external []graphfrag.GraphFragmentExternal
	// entryCalls holds internal[i].EntryCall's JSON encoding when
	// encodeFragmentEntryCalls ran, nil where it could not encode it.
	entryCalls [][]byte
}

// encodeFragmentEntryCalls encodes the entry calls of edges' internal edges,
// the costly part of writing them, so workers do it instead of the writer.
// An entry call that fails to encode is left nil, for the writer to encode
// (and fail on) itself.
func encodeFragmentEntryCalls(edges *fragmentEdges) {
	edges.entryCalls = make([][]byte, len(edges.internal))
	for i := range edges.internal {
		if call := edges.internal[i].EntryCall; call != nil {
			if data, err := json.Marshal(call); err == nil {
				edges.entryCalls[i] = data
			}
		}
	}
}

// fragmentEdgePiece names the edges into calleeKey from callers, a run of its
// sorted callers; nil callers means all of them.
type fragmentEdgePiece struct {
	calleeKey string
	callers   []string
}

// forEachFragmentEdges builds the edges into every callee in calleeKeys, on
// all cores, and hands them to consume in runs whose concatenation is exactly
// what a serial build emits, in that order. Each worker builds on its own fork
// of ctx (forkForFragmentEdges); at most fragmentEdgeWindow work items per
// worker are held ahead of consume. prepare, when set, runs over each run in
// the worker that built it. The build stops once consume returns false.
func forEachFragmentEdges(ctx *exportBuildContext, calleeKeys []string, prepare func(*fragmentEdges), consume func(fragmentEdges) bool) {
	workers := fragmentEdgeWorkers()
	var items [][]fragmentEdgePiece
	if workers >= 2 {
		items = planFragmentEdgeItems(ctx.graph, calleeKeys)
		workers = min(workers, len(items))
	}
	if workers < 2 {
		for _, calleeKey := range calleeKeys {
			if !consume(buildFragmentEdgePiece(ctx, fragmentEdgePiece{calleeKey: calleeKey}, prepare)) {
				return
			}
		}
		return
	}

	ctx.prepareFragmentEdgeForks()
	build := &fragmentEdgeBuild{
		items:   items,
		prepare: prepare,
		results: make([][]fragmentEdges, len(items)),
		ready:   make([]chan struct{}, len(items)),
		window:  make(chan struct{}, workers*fragmentEdgeWindow),
		stop:    make(chan struct{}),
	}
	for i := range build.ready {
		build.ready[i] = make(chan struct{})
	}
	jobs := build.dispatch()
	var wg sync.WaitGroup
	for range workers {
		fork := ctx.forkForFragmentEdges()
		wg.Go(func() { build.work(fork, jobs) })
	}
	build.consumeInOrder(consume)
	wg.Wait()
}

// planFragmentEdgeItems cuts the edge build into work items of about
// fragmentEdgeItemCallers caller-callee pairs, in calleeKeys order.
func planFragmentEdgeItems(graph *callgraph.CallGraph, calleeKeys []string) [][]fragmentEdgePiece {
	var items [][]fragmentEdgePiece
	var item []fragmentEdgePiece
	pairs := 0
	closeItem := func() {
		if len(item) > 0 {
			items = append(items, item)
			item, pairs = nil, 0
		}
	}
	for _, calleeKey := range calleeKeys {
		callers := graph.Callers[calleeKey]
		if len(callers) <= fragmentEdgeItemCallers {
			item = append(item, fragmentEdgePiece{calleeKey: calleeKey})
			// A callee counts at least one, so callees without callers
			// still fill items.
			if pairs += max(len(callers), 1); pairs >= fragmentEdgeItemCallers {
				closeItem()
			}
			continue
		}
		closeItem()
		sorted := sortedFragmentCallers(graph, calleeKey)
		for lo := 0; lo < len(sorted); lo += fragmentEdgeItemCallers {
			hi := min(lo+fragmentEdgeItemCallers, len(sorted))
			items = append(items, []fragmentEdgePiece{{calleeKey: calleeKey, callers: sorted[lo:hi:hi]}})
		}
	}
	closeItem()
	return items
}

// buildFragmentEdgePiece builds the edges piece names and, when prepare is
// set, runs it over them.
func buildFragmentEdgePiece(ctx *exportBuildContext, piece fragmentEdgePiece, prepare func(*fragmentEdges)) fragmentEdges {
	callers := piece.callers
	if callers == nil {
		callers = sortedFragmentCallers(ctx.graph, piece.calleeKey)
	}
	edges := buildResolvedFragmentEdgesFrom(ctx, piece.calleeKey, callers)
	if prepare != nil {
		prepare(&edges)
	}
	return edges
}

// fragmentEdgeBuild is the shared state of one parallel edge build: the
// worker of items[i] stores its edges in results[i] and closes ready[i].
type fragmentEdgeBuild struct {
	items   [][]fragmentEdgePiece
	prepare func(*fragmentEdges)
	results [][]fragmentEdges
	ready   []chan struct{}
	// window holds a token per work item handed out and not yet consumed.
	window chan struct{}
	// stop is closed when the consumer quits early.
	stop chan struct{}
}

// dispatch hands out the work items in order, never more than the window
// allows ahead of the consumer.
func (b *fragmentEdgeBuild) dispatch() <-chan int {
	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := range b.items {
			select {
			case b.window <- struct{}{}:
			case <-b.stop:
				return
			}
			select {
			case jobs <- i:
			case <-b.stop:
				return
			}
		}
	}()
	return jobs
}

func (b *fragmentEdgeBuild) work(ctx *exportBuildContext, jobs <-chan int) {
	for i := range jobs {
		batch := make([]fragmentEdges, 0, len(b.items[i]))
		for _, piece := range b.items[i] {
			batch = append(batch, buildFragmentEdgePiece(ctx, piece, b.prepare))
		}
		b.results[i] = batch
		close(b.ready[i])
	}
}

// consumeInOrder hands the built edges to consume in work item order.
func (b *fragmentEdgeBuild) consumeInOrder(consume func(fragmentEdges) bool) {
	for i := range b.results {
		<-b.ready[i]
		batch := b.results[i]
		b.results[i] = nil
		for _, edges := range batch {
			if !consume(edges) {
				close(b.stop)
				return
			}
		}
		<-b.window
	}
}

// forkForFragmentEdges returns a copy of ctx one edge-building goroutine can
// use while others use theirs. The graph, the indexes built before forking
// (prepareFragmentEdgeForks) and the exportMemo caches stay shared; what the
// edge build writes outside an exportMemo (returnInlining, the recursion guard
// of one walk) is the fork's own. A cache the edge build starts to fill must
// be an exportMemo, built in prepareFragmentEdgeForks or reset here, or the
// forks race on it.
func (ctx *exportBuildContext) forkForFragmentEdges() *exportBuildContext {
	fork := *ctx
	fork.returnInlining = nil
	return &fork
}

// prepareFragmentEdgeForks builds, before ctx is forked, the lazy indexes the
// edge build reads.
func (ctx *exportBuildContext) prepareFragmentEdgeForks() {
	if ctx.graph != nil && ctx.callsReverseIndex == nil {
		ctx.callsReverseIndex = buildCallsReverseIndex(ctx.graph)
	}
}
