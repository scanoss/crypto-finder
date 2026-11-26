// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package offline makes a project's pinned dependencies available to the
// application reachability stitch without the SCANOSS API: each dependency is
// mined the way the SCANOSS miner mines it (a typed cards scan of its
// sources, with the compiled JARs of its own closure as type-only packages,
// exporting its graph fragment and findings report; a Python distribution
// from the files its environment installed), kept in a local
// content-addressed cache, and loaded as the API loads a stored component.
// The caller then runs pkg/appreach over them, the code the API runs.
package offline

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/utils"
	pr "github.com/scanoss/crypto-finder/pkg/appreach"
)

// Dependency is one pinned dependency of the closure.
type Dependency struct {
	// Key is the dependency as the project request pins it: its canonical
	// versionless purl and its version.
	Key gf.ComponentKey
	// Module is its coordinate, group:artifact for Maven.
	Module string
	// SourcesJAR returns its sources JAR, fetching it if the build tool can.
	SourcesJAR func(ctx context.Context) (string, error)
	// SourcesDir, when set, returns the directory of its sources instead
	// (a Python distribution's installed files): no JAR, no extraction.
	SourcesDir func(ctx context.Context) (string, error)
	// SourcesDigest, when set, keys its graph by the content of its sources
	// as well as its version (a Python distribution's RECORD): an installed
	// distribution is whatever its environment holds, not only its release.
	SourcesDigest string
	// TypeJARs are the compiled JARs of its own dependency closure, the
	// type-only packages its graph is typed with, in index order.
	TypeJARs []string
	// SizeHint orders the work: larger dependencies are prepared first, so
	// the longest mine does not start last (its compiled JAR's size will do).
	SizeHint int64
}

// Miner runs crypto-finder's scan of one component, the miner's path, in
// process.
type Miner interface {
	// Mine scans the sources in dir, typed by typeJARs, and returns what the
	// miner's crypto-finder run writes: the findings report (--output) and
	// the graph fragment (--export-graph-fragment).
	Mine(ctx context.Context, dir string, typeJARs []string) (findings, fragment []byte, err error)
	// Annotate re-detects a structural graph with the scan's ruleset
	// (crypto-finder annotate --findings-output) and returns the annotation
	// and the findings report. sources returns the component's sources for
	// a miner whose annotation reads them (--source); others match the
	// graph alone and never call it.
	Annotate(ctx context.Context, structural []byte, sources func(context.Context) (string, error)) (annotation, findings []byte, err error)
}

// Options configure Prepare.
type Options struct {
	Cache *Cache
	// RulesetKey identifies the scan's ruleset (RulesetKey).
	RulesetKey string
	// RulesVersion names the ruleset in the response.
	RulesVersion string
	Miner        Miner
	// Extract unpacks a sources JAR and returns the directory to mine.
	Extract func(jar, module, version string) (string, error)
	// MemoryBudget bounds the memory the dependencies mined at once may take,
	// in bytes, as estimated from their sources (MemoryEstimate). Zero means
	// DefaultMemoryBudget.
	MemoryBudget int64
	// Workers bounds the dependencies prepared at once; zero means
	// GOMAXPROCS.
	Workers int
}

// DefaultMemoryBudget is the memory budget of mining when none is set.
const DefaultMemoryBudget int64 = 5 << 30

// Stats counts how each dependency was prepared.
type Stats struct {
	Cached      int
	Reannotated int
	Mined       int
	Unavailable int
	// Mining is the time spent mining and re-annotating, summed over
	// dependencies.
	Mining time.Duration
}

// count adds one dependency prepared as how, in took.
func (s *Stats) count(how outcome, took time.Duration) {
	switch how {
	case fromCache:
		s.Cached++
	case reannotated:
		s.Reannotated++
		s.Mining += took
	case mined:
		s.Mined++
		s.Mining += took
	case unavailable:
		s.Unavailable++
	}
}

// outcome is how one dependency was prepared.
type outcome int

const (
	fromCache outcome = iota
	reannotated
	mined
	unavailable
)

// Prepare makes every dependency a appreach.Component: from the cache,
// by re-annotating a cached graph with a new ruleset, or by mining its
// sources. A dependency that cannot be mined (no sources JAR, a failed scan)
// gets a component without a graph whose message says why; it is served as
// a dependency without reachability data, as the API serves one it never
// mined.
//
// When ctx ends first, Prepare returns its error at once: no further
// dependency is started, and the mines under way are left to finish on their
// own, since building a call graph cannot be interrupted. What each one mines
// is still cached when it finishes, while the process runs.
func Prepare(ctx context.Context, deps []Dependency, opts Options) (map[gf.ComponentKey]pr.Component, Stats, error) {
	if opts.MemoryBudget <= 0 {
		opts.MemoryBudget = DefaultMemoryBudget
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	p := &preparer{opts: opts, budget: newBudget(opts.MemoryBudget), digests: map[string]string{}}

	out := make(map[gf.ComponentKey]pr.Component, len(deps))
	var stats Stats
	prepared := 0
	var mu sync.Mutex
	next := make(chan Dependency)
	var wg sync.WaitGroup
	for range min(workers, max(len(deps), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dep := range next {
				started := time.Now()
				comp, how := p.prepare(ctx, dep)
				mu.Lock()
				out[dep.Key] = comp
				prepared++
				stats.count(how, time.Since(started))
				mu.Unlock()
			}
		}()
	}
	order := slices.Clone(deps)
	slices.SortStableFunc(order, func(a, b Dependency) int { return cmp.Compare(b.SizeHint, a.SizeHint) })
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer wg.Wait()
		defer close(next)
		for _, dep := range order {
			select {
			case next <- dep:
			case <-ctx.Done():
				return
			}
		}
	}()
	select {
	case <-finished:
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil && prepared < len(deps) {
		return nil, stats, fmt.Errorf("offline: %d of %d dependencies prepared: %w", prepared, len(deps), err)
	}
	return out, stats, nil
}

type preparer struct {
	opts    Options
	budget  *budget
	mu      sync.Mutex
	digests map[string]string
}

func noData(dep Dependency, format string, args ...any) pr.Component {
	msg := fmt.Sprintf(format, args...)
	log.Warn().Str("dependency", dep.Module+"@"+dep.Key.Version).Msg("Offline: " + msg)
	return pr.Component{Code: pr.InfoNoInfo, Message: msg}
}

func (p *preparer) prepare(ctx context.Context, dep Dependency) (pr.Component, outcome) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	graphKey, err := p.graphKey(dep)
	if err != nil {
		return noData(dep, "offline: cannot key %s@%s: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	cache := p.opts.Cache
	graph, cached := cache.Graph(graphKey)
	if annotation, findings, ok := cache.Annotation(graphKey, p.opts.RulesetKey); ok && cached {
		if comp, err := p.component(dep, graph, annotation, findings); err == nil {
			return comp, fromCache
		}
	}
	if cached { //nolint:nestif // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
		annotation, findings, err := p.opts.Miner.Annotate(ctx, graph, func(ctx context.Context) (string, error) { return p.sources(ctx, dep) })
		if err == nil {
			sections, err := annotationSections(dep.Key, annotation, graph)
			if err == nil {
				if err := cache.PutAnnotation(graphKey, p.opts.RulesetKey, sections, findings); err != nil {
					log.Warn().Err(err).Msg("Offline: could not cache an annotation")
				}
				if comp, err := p.component(dep, graph, sections, findings); err == nil {
					return comp, reannotated
				}
			}
		}
		log.Warn().Err(err).Str("dependency", dep.Module+"@"+dep.Key.Version).Msg("Offline: re-annotating the cached graph failed; mining the sources again")
	}

	dir, err := p.sources(ctx, dep)
	if err != nil {
		return noData(dep, "offline: %v; the dependency is not mined", err), unavailable
	}
	weight := min(MemoryEstimate(dir), p.opts.MemoryBudget)
	if err := p.budget.acquire(ctx, weight); err != nil {
		return noData(dep, "offline: %v", err), unavailable
	}
	started := time.Now()
	findings, fragment, err := p.opts.Miner.Mine(ctx, dir, dep.TypeJARs)
	p.budget.release(weight)
	if err != nil {
		return noData(dep, "offline: mining %s@%s failed: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	log.Debug().Str("dependency", dep.Module+"@"+dep.Key.Version).Int("type_jars", len(dep.TypeJARs)).
		Dur("duration", time.Since(started)).Msg("Offline: mined")
	findings, fragment = relativePaths(findings, dir), relativePaths(fragment, dir)
	graph, err = gf.StructuralExport(fragment)
	if err != nil {
		return noData(dep, "offline: %s@%s: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	full, err := gf.DecodeFragment(dep.Key, fragment)
	if err != nil {
		return noData(dep, "offline: %s@%s: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	sections, err := json.Marshal(cryptoSections{full.CryptoOperations, full.SupportingCalls, full.CryptoEntryPoints})
	if err != nil {
		return noData(dep, "offline: %s@%s: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	if err := cache.PutGraph(graphKey, graph, GraphMeta{Purl: dep.Key.Purl, Version: dep.Key.Version, Module: dep.Module, TypeJARs: dep.TypeJARs}); err != nil {
		log.Warn().Err(err).Msg("Offline: could not cache a graph")
	} else if err := cache.PutAnnotation(graphKey, p.opts.RulesetKey, sections, findings); err != nil {
		log.Warn().Err(err).Msg("Offline: could not cache an annotation")
	}
	comp, err := p.component(dep, graph, sections, findings)
	if err != nil {
		return noData(dep, "offline: %s@%s: %v", dep.Module, dep.Key.Version, err), unavailable
	}
	return comp, mined
}

// sources returns the directory to mine dep from: its sources directory, or
// its sources JAR extracted.
func (p *preparer) sources(ctx context.Context, dep Dependency) (string, error) {
	if dep.SourcesDir != nil {
		return dep.SourcesDir(ctx)
	}
	jar, err := dep.SourcesJAR(ctx)
	if err != nil {
		return "", err
	}
	dir, err := p.opts.Extract(jar, dep.Module, dep.Key.Version)
	if err != nil {
		return "", fmt.Errorf("extracting %s: %w", filepath.Base(jar), err)
	}
	return dir, nil
}

// cryptoSections is a component's crypto annotation as the API stores it.
type cryptoSections struct {
	CryptoOperations  []gf.CryptoOperation  `json:"crypto_operations,omitempty"`
	SupportingCalls   []gf.SupportingCall   `json:"supporting_calls,omitempty"`
	CryptoEntryPoints []gf.CryptoEntryPoint `json:"crypto_entry_points,omitempty"`
}

// annotationSections reads the output of annotate over graph as the miner's
// re-annotation reads it (its crypto entry points address the graph's
// functions, which the annotation does not repeat) and returns its crypto
// sections.
func annotationSections(key gf.ComponentKey, annotation, graph []byte) ([]byte, error) {
	var export gf.GraphFragmentExport
	if err := json.Unmarshal(annotation, &export); err != nil {
		return nil, fmt.Errorf("decode annotation: %w", err)
	}
	if len(export.Functions) == 0 {
		var structural struct {
			Functions []gf.GraphFragmentFunction `json:"functions"`
		}
		if err := json.Unmarshal(graph, &structural); err != nil {
			return nil, fmt.Errorf("decode graph functions: %w", err)
		}
		export.Functions = structural.Functions
	}
	frag := export.ToFragment(key)
	return json.Marshal(cryptoSections{frag.CryptoOperations, frag.SupportingCalls, frag.CryptoEntryPoints})
}

// component builds the dependency as the API loads a stored one: the
// structural graph, the annotation's crypto sections, the findings report.
func (p *preparer) component(dep Dependency, graph, sections, findings []byte) (pr.Component, error) {
	frag, err := pr.DecodeProducerGraph(dep.Key, graph)
	if err != nil {
		return pr.Component{}, err
	}
	var ann cryptoSections
	if err := json.Unmarshal(sections, &ann); err != nil {
		return pr.Component{}, fmt.Errorf("decode annotation: %w", err)
	}
	frag.CryptoOperations, frag.SupportingCalls, frag.CryptoEntryPoints = ann.CryptoOperations, ann.SupportingCalls, ann.CryptoEntryPoints
	frag.RulesVersion = p.opts.RulesVersion
	comp := pr.Component{Fragment: frag}
	stored, err := pr.DecodeStoredReport(findings, "")
	if err != nil {
		comp.StoredErr = err.Error()
	} else {
		comp.Stored = &stored
	}
	return comp, nil
}

// graphKey is dep's cache key. A Maven release never changes, so the
// package and version stand for its sources; a SNAPSHOT is keyed by its
// sources JAR's content too.
func (p *preparer) graphKey(dep Dependency) (string, error) {
	digests := make([]string, 0, len(dep.TypeJARs))
	for _, jar := range dep.TypeJARs {
		d, err := p.digest(jar)
		if err != nil {
			return "", err
		}
		digests = append(digests, d)
	}
	sources := dep.SourcesDigest
	if sources == "" && strings.HasSuffix(dep.Key.Version, "-SNAPSHOT") {
		jar, err := dep.SourcesJAR(context.Background())
		if err == nil {
			sources, err = p.digest(jar)
		}
		if err != nil {
			return "", err
		}
	}
	return GraphKey(dep.Key.Purl, dep.Key.Version, sources, digests, gf.GraphAlgoVersionForPurl(dep.Key.Purl), gf.SchemaVersion), nil
}

func (p *preparer) digest(path string) (string, error) {
	p.mu.Lock()
	d, ok := p.digests[path]
	p.mu.Unlock()
	if ok {
		return d, nil
	}
	d, err := FileDigest(path)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.digests[path] = d
	p.mu.Unlock()
	return d, nil
}

// bytesPerSourceByte estimates a dependency's mining memory from its Java
// source size, minMiningBytes is the least any dependency is given. Measured
// on the 162 PoC dependencies mined one per process: peak RSS above the
// process's baseline (the Java platform index, which an offline scan shares)
// is 70 to 135 times the Java source size for the large ones (bcprov 13.5 MB
// of source: 1.7 GB; poi-ooxml-lite 40 MB: 2.8 GB).
const (
	bytesPerSourceByte = 120
	minMiningBytes     = 128 << 20
)

// MemoryEstimate is the memory mining the Java sources under dir is expected
// to take.
func MemoryEstimate(dir string) int64 {
	var total int64
	utils.Discard(filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && strings.HasSuffix(path, ".java") {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	}))
	return max(total*bytesPerSourceByte, minMiningBytes)
}
