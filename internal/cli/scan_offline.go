// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	runtimedebug "runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/language"
	"github.com/scanoss/reach/perf"
	"github.com/scanoss/reach/purl"
	"github.com/scanoss/reach/skip"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/offline"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/internal/pqc"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
	"github.com/scanoss/crypto-finder/internal/utils"
	pr "github.com/scanoss/crypto-finder/pkg/appreach"
)

// Offline mode is the same dependency scan without the SCANOSS API: the
// client does what the miner and the API do. It mines each pinned dependency
// of the closure from its Maven sources JAR the way the miner mines a
// component (mineComponent: the scan's own pipeline, in process, typed by the
// dependency's own closure), keeps the result in a local cache, and runs
// pkg/appreach over the closure, the code the API's
// /reachability/application runs. The answer is the API's answer.

var (
	scanOffline               bool
	scanOfflineCacheDir       string
	scanOfflineMemoryMB       int
	scanOfflinePythonPackages string
)

func init() {
	scanCmd.Flags().BoolVar(&scanOffline, "offline", false,
		"With --scan-dependencies: decide dependency reachability locally instead of asking the SCANOSS API. Each dependency is mined from its published sources and cached; the verdicts come from the code the API runs")
	scanCmd.Flags().StringVar(&scanOfflineCacheDir, "offline-cache-dir", "",
		"With --offline or the online offline fallback: directory of the mined-dependency cache (default ~/.scanoss/crypto-finder/cache/mined)")
	scanCmd.Flags().StringVar(&scanOfflinePythonPackages, "offline-python-packages", "",
		"With --offline or the online offline fallback, on a Python target: installed Python packages to mine the dependencies from (OS path-list separated: virtual environments, site-packages directories, unpacked wheels), after the project's .venv, venv and VIRTUAL_ENV. Nothing is installed, downloaded or run")
	scanCmd.Flags().IntVar(&scanOfflineMemoryMB, "offline-memory-mb", defaultOfflineMemoryMB,
		"With --offline or the online offline fallback: memory budget in MiB. The scan's soft memory limit (unless GOMEMLIMIT is set); half of it bounds the dependencies mined at once, estimated from their sources")
}

// defaultOfflineMemoryMB is the default --offline-memory-mb: the closure of an
// internal Java test project (131 dependencies) stitches in about 9 GB.
const defaultOfflineMemoryMB = 10240

// limitOfflineMemory makes the offline budget the process's soft memory limit
// when GOMEMLIMIT does not set one, so the garbage collector keeps the heap
// near what the scan holds instead of letting it grow to twice that while
// dependencies are mined. It returns the function that restores the limit.
func limitOfflineMemory() func() {
	if _, set := os.LookupEnv("GOMEMLIMIT"); set || scanOfflineMemoryMB <= 0 {
		return func() {}
	}
	previous := runtimedebug.SetMemoryLimit(int64(scanOfflineMemoryMB) << 20)
	return func() { runtimedebug.SetMemoryLimit(previous) }
}

// openOfflineCache opens the offline cache in the directory the flag names, or
// else the default one, and returns that directory too.
func openOfflineCache() (*offline.Cache, string, error) {
	cacheDir := scanOfflineCacheDir
	if cacheDir == "" {
		var err error
		if cacheDir, err = offline.DefaultCacheDir(); err != nil {
			return nil, "", err
		}
	}
	cache, err := offline.OpenCache(cacheDir)
	if err != nil {
		return nil, "", err
	}
	return cache, cacheDir, nil
}

// offlineReachability answers request locally. With only set (the offline
// fallback of an online scan), it mines the dependencies pinned under only
// and those leading to them (fallbackMineKeys); the others are served
// without data and spliced out of the stitch. With only nil it mines every
// dependency.
func offlineReachability(ctx context.Context, plan *applicationReachabilityPlan, request *api.ApplicationReachabilityRequest, rulesManager *rules.Manager, javaRuntime javaruntime.Config, only []string) (*api.ApplicationReachability, error) {
	req := pr.Request{
		SchemaVersion:       request.SchemaVersion,
		CallSites:           request.CallSites,
		IncludeCallChains:   request.IncludeCallChains,
		MaxChainsPerFinding: request.MaxChainsPerFinding,
		ConditionedRules:    request.ConditionedRules,
	}
	for _, d := range request.Dependencies {
		req.Dependencies = append(req.Dependencies, pr.Dependency{Purl: d.Purl, Version: d.Version, Direct: d.Direct, Requires: d.Requires, Markers: d.Markers, Extras: d.Extras})
	}
	// The API's limits protect a shared server; a local run takes its own
	// closure whole.
	limits := pr.Limits{MaxDependencies: max(len(req.Dependencies), pr.DefaultLimits.MaxDependencies), MaxCallSites: max(len(req.CallSites.ExternalCalls), pr.DefaultLimits.MaxCallSites)}
	stitchPlan, rejected := pr.NewPlan(req, limits)
	if rejected != nil {
		return answerOf(*rejected)
	}

	mineKeys := stitchPlan.Keys
	if only != nil {
		mineKeys = fallbackMineKeys(stitchPlan, only)
	}

	cache, cacheDir, err := openOfflineCache()
	if err != nil {
		return nil, err
	}
	shared := &lockedRules{manager: rulesManager}
	rulesetKey, rulesVersion, err := offlineRulesetKey(shared)
	if err != nil {
		return nil, err
	}
	sources, err := dependency.NewSourceCache()
	if err != nil {
		return nil, err
	}
	timeout := utils.Lenient(scanutil.ParseDuration(scanTimeout))
	miner := &inProcessMiner{
		rules:       rules.NewManager(shared),
		ruleDirs:    scanRuleDirs,
		javaRuntime: javaRuntime,
		timeout:     timeout,
		catalogs:    cards.NewCatalogs(),
		language:    plan.closure.Ecosystem,
	}

	var deps []offline.Dependency
	switch plan.closure.Ecosystem {
	case ecosystemPython:
		work, err := os.MkdirTemp("", "crypto-finder-offline-python-")
		if err != nil {
			return nil, err
		}
		defer func() { utils.Discard(os.RemoveAll(work)) }()
		deps = offlinePythonDependencies(plan, mineKeys, work)
	case ecosystemGo, ecosystemRust, ecosystemRuby, ecosystemCSharp:
		// A gem's sources sit in a directory of the local installation, as a
		// Go module's and a crate's do, so they are read the same way. A gem
		// installed nowhere is left out and served without data: offline
		// mode downloads nothing. A NuGet package ships assemblies rather
		// than source, so a C# dependency is mined only where its package
		// carries source files.
		deps = offlineSourceDirDependencies(plan, mineKeys)
	case ecosystemNode:
		deps = offlineNodeDependencies(plan, mineKeys)
	default:
		deps = offlineDependencies(plan, mineKeys)
	}
	// Every dependency mined here indexes the Java platform once. The
	// project's graph, built before, does not share it: a scan that mines
	// nothing would pay for products it never reuses.
	javaTypeIndex = callgraph.NewSharedJavaTypeIndex()
	defer func() { javaTypeIndex = nil }()
	span := perf.Start("dependencies.offline_prepare")
	loaded, stats, err := offline.Prepare(ctx, deps, offline.Options{
		Cache:        cache,
		RulesetKey:   rulesetKey,
		RulesVersion: rulesVersion,
		Miner:        miner,
		Extract: func(jar, module, version string) (string, error) {
			return sources.ExtractZip(jar, module, version, []string{".java"})
		},
		MemoryBudget: int64(scanOfflineMemoryMB) << 19,
	})
	span.End()
	if err != nil {
		return nil, fmt.Errorf("offline mining (%d mined, %d from the cache before it stopped): %w", stats.Mined, stats.Cached, err)
	}
	serveUnloaded(loaded, stitchPlan.Keys, mineKeys)
	log.Info().
		Int("dependencies", len(mineKeys)).
		Int("cached", stats.Cached).
		Int("reannotated", stats.Reannotated).
		Int("mined", stats.Mined).
		Int("unavailable", stats.Unavailable).
		Dur("mining", stats.Mining).
		Str("cache", cacheDir).
		Msg("Offline: dependencies prepared")

	edges, _ := stitchPlan.RequestEdges()
	stitchSpan := perf.Start("dependencies.offline_stitch")
	resp, _, err := stitchPlan.Run(ctx, loaded, edges, pr.RunOptions{})
	stitchSpan.End()
	if err != nil {
		return nil, fmt.Errorf("offline application reachability: %w", err)
	}
	return answerOf(resp)
}

// serveUnloaded serves without data each key Prepare loaded nothing for:
// a mined key whose resolver named no artifact, and a key left unmined
// because the API answered it (the offline fallback).
func serveUnloaded(loaded map[pr.ComponentKey]pr.Component, keys, mineKeys []pr.ComponentKey) {
	mined := make(map[pr.ComponentKey]bool, len(mineKeys))
	for _, key := range mineKeys {
		mined[key] = true
	}
	for _, key := range keys {
		if _, ok := loaded[key]; ok {
			continue
		}
		msg := "offline: the resolver named no artifact for this dependency"
		if !mined[key] {
			msg = "offline fallback: answered by the SCANOSS API, not mined"
		}
		loaded[key] = pr.Component{Code: pr.InfoNoInfo, Message: msg}
	}
}

// answerOf reads a appreach response as the API client reads the API's.
func answerOf(resp pr.Response) (*api.ApplicationReachability, error) {
	body, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var answer api.ApplicationReachability
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, err
	}
	answer.ResponseBytes = len(body)
	return &answer, nil
}

// offlineDependencies are the pinned dependencies to mine, keyed as the
// stitch plan keys them, each typed by the compiled JARs of its own subtree
// of the resolved tree: what the miner holds as the component's closure.
func offlineDependencies(plan *applicationReachabilityPlan, keys []pr.ComponentKey) []offline.Dependency {
	closure := plan.closure
	byRef := make(map[string]dependency.Dependency, len(closure.Resolved.Dependencies))
	byKey := make(map[pr.ComponentKey]dependency.Dependency, len(closure.Resolved.Dependencies))
	for _, dep := range closure.Resolved.Dependencies {
		byRef[dependency.Ref{Module: dep.Module, Version: dep.Version}.Key()] = dep
		p, err := pr.ParsePurl(purl.Dependency(closure.Ecosystem, dep.Module, ""))
		if err != nil {
			continue
		}
		p.Version = ""
		key := pr.ComponentKey{Purl: p.String(), Version: dep.Version}
		if _, seen := byKey[key]; !seen {
			byKey[key] = dep
		}
	}
	out := make([]offline.Dependency, 0, len(keys))
	for _, key := range keys {
		dep, ok := byKey[key]
		if !ok {
			continue
		}
		var size int64
		if info, err := os.Stat(dep.CompiledArtifactPath); err == nil {
			size = info.Size()
		}
		out = append(out, offline.Dependency{
			Key:      key,
			Module:   dep.Module,
			SizeHint: size,
			TypeJARs: closureJARs(closure.Resolved, byRef, dep),
			SourcesJAR: func(ctx context.Context) (string, error) {
				return plan.resolver.SourcesJAR(ctx, dep)
			},
		})
	}
	return out
}

// offlineSourceDirDependencies are the pinned Go and Rust dependencies to
// mine, each from the source directory its resolver found: a Go module in the
// module cache, a crate in Cargo's registry cache or the project's vendor/.
// A dependency with no source directory is left out and served without data:
// offline mode downloads nothing.
func offlineSourceDirDependencies(plan *applicationReachabilityPlan, keys []pr.ComponentKey) []offline.Dependency {
	closure := plan.closure
	byKey := make(map[pr.ComponentKey]dependency.Dependency, len(closure.Resolved.Dependencies))
	for _, dep := range closure.Resolved.Dependencies {
		p, err := pr.ParsePurl(purl.Dependency(closure.Ecosystem, dep.Module, ""))
		if err != nil || dep.Dir == "" {
			continue
		}
		p.Version = ""
		key := pr.ComponentKey{Purl: p.String(), Version: dep.Version}
		if _, seen := byKey[key]; !seen {
			byKey[key] = dep
		}
	}
	out := make([]offline.Dependency, 0, len(keys))
	for _, key := range keys {
		dep, ok := byKey[key]
		if !ok {
			continue
		}
		dir := dep.Dir
		d := offline.Dependency{
			Key:        key,
			Module:     dep.Module,
			SourcesDir: func(context.Context) (string, error) { return dir, nil },
		}
		if dep.Local {
			// A local directory changes under the same version: its graph is
			// keyed by what it holds.
			d.SourcesDigest, d.SizeHint = localSourcesDigest(dir)
		}
		out = append(out, d)
	}
	return out
}

// localSourcesDigest keys a local dependency's directory by each file's path,
// size and modification time, outside version control and build output
// directories, and sums their sizes.
func localSourcesDigest(dir string) (string, int64) {
	h := sha256.New()
	var total int64
	// An entry that cannot be read is left out: the walk goes on.
	utils.Discard(filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr == nil && d.IsDir() && path != dir && (d.Name() == ".git" || d.Name() == "target") {
			return filepath.SkipDir
		}
		if walkErr != nil || d.IsDir() {
			return nil //nolint:nilerr // see above
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			rel := utils.Lenient(filepath.Rel(dir, path))
			utils.Lenient(fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
			total += info.Size()
		}
		return nil
	}))
	return hex.EncodeToString(h.Sum(nil)), total
}

// offlineNodeDependencies are the pinned npm dependencies to mine, each from
// its package directory under the project's node_modules, found by name and
// version. A dependency that is not installed is left out and served without
// data: offline mode installs nothing.
func offlineNodeDependencies(plan *applicationReachabilityPlan, keys []pr.ComponentKey) []offline.Dependency {
	closure := plan.closure
	byKey := make(map[pr.ComponentKey]dependency.Dependency, len(closure.Resolved.Dependencies))
	for _, dep := range closure.Resolved.Dependencies {
		p, err := pr.ParsePurl(purl.Dependency(closure.Ecosystem, dep.Module, ""))
		if err != nil {
			continue
		}
		p.Version = ""
		key := pr.ComponentKey{Purl: p.String(), Version: dep.Version}
		if existing, seen := byKey[key]; !seen || existing.Dir == "" {
			byKey[key] = dep
		}
	}
	out := make([]offline.Dependency, 0, len(keys))
	for _, key := range keys {
		dep, ok := byKey[key]
		if !ok {
			continue
		}
		if dep.Dir == "" {
			log.Warn().Str("dependency", dep.Module+"@"+dep.Version).Msg("Offline: this dependency is not installed under the project's node_modules; it is not mined")
			continue
		}
		dir := dep.Dir
		out = append(out, offline.Dependency{
			Key:        key,
			Module:     dep.Module,
			SourcesDir: func(context.Context) (string, error) { return dir, nil },
		})
	}
	return out
}

// offlinePythonDependencies are the pinned Python dependencies to mine, each
// from the files its installed distribution's RECORD lists: the
// distribution the resolver read from an environment, else the one of that
// name and version (PEP 440 equal) in the project's environments or
// --offline-python-packages. A dependency installed nowhere is left out and
// served without data. The sources (.py, .pyi) are copied under work, one
// directory per distribution, as an unpacked wheel lays them out.
func offlinePythonDependencies(plan *applicationReachabilityPlan, keys []pr.ComponentKey, work string) []offline.Dependency {
	closure := plan.closure
	installed := make(map[string][]dependency.PythonDistribution)
	var roots []string
	roots = append(roots, dependency.PythonEnvironmentDirs(closure.Target)...)
	if scanOfflinePythonPackages != "" {
		roots = append(roots, filepath.SplitList(scanOfflinePythonPackages)...)
	}
	for _, root := range roots {
		for _, d := range dependency.InstalledPythonDistributions(root) {
			installed[d.Name] = append(installed[d.Name], d)
		}
	}
	for _, dep := range closure.Resolved.Dependencies {
		if dep.Dir != "" && dep.Files != nil {
			name := purl.PyPIName(dep.Module)
			installed[name] = append([]dependency.PythonDistribution{{Name: name, Version: dep.Version, Dir: dep.Dir, Files: dep.Files}}, installed[name]...)
		}
	}
	out := make([]offline.Dependency, 0, len(keys))
	for _, key := range keys {
		module := pr.PurlToModule(key.Purl)
		var dist *dependency.PythonDistribution
		for i, d := range installed[module] {
			if pr.PyPIVersionsEqual(d.Version, key.Version) {
				dist = &installed[module][i]
				break
			}
		}
		if dist == nil {
			log.Warn().Str("dependency", module+"@"+key.Version).Msg("Offline: no installed distribution of this dependency in the project's environments or --offline-python-packages; it is not mined")
			continue
		}
		digest, size := pythonSourcesDigest(dist)
		d := *dist
		out = append(out, offline.Dependency{
			Key:           key,
			Module:        module,
			SizeHint:      size,
			SourcesDigest: digest,
			SourcesDir: func(context.Context) (string, error) {
				return copyPythonSources(d, filepath.Join(work, module+"@"+key.Version))
			},
		})
	}
	return out
}

// isPythonSource reports whether an installed file is Python source a mine
// reads.
func isPythonSource(path string) bool {
	return strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".pyi")
}

// pythonSourcesDigest keys an installed distribution's sources by each
// source file's path, size and modification time, and sums their sizes.
func pythonSourcesDigest(d *dependency.PythonDistribution) (string, int64) {
	h := sha256.New()
	var total int64
	for _, file := range d.Files {
		if !isPythonSource(file) {
			continue
		}
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		rel := utils.Lenient(filepath.Rel(d.Dir, file))
		utils.Lenient(fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
		total += info.Size()
	}
	return hex.EncodeToString(h.Sum(nil)), total
}

// copyPythonSources copies a distribution's Python sources under dir, at
// their paths below its installation directory.
func copyPythonSources(d dependency.PythonDistribution, dir string) (string, error) {
	copied := 0
	for _, file := range d.Files {
		if !isPythonSource(file) {
			continue
		}
		rel, err := filepath.Rel(d.Dir, file)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		data, err := os.ReadFile(file) // #nosec G304 -- a file the distribution's RECORD installed.
		if err != nil {
			continue
		}
		dest := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return "", err
		}
		if err := os.WriteFile(dest, data, 0o600); err != nil {
			return "", err
		}
		copied++
	}
	if copied == 0 {
		return "", fmt.Errorf("the installed distribution %s %s has no Python source", d.Name, d.Version)
	}
	return dir, nil
}

// closureJARs are the compiled JARs of every dependency below dep in the
// resolved tree, sorted. The edges a tree omits are followed too: Maven
// prints a subtree once, so a dependency the project also declares (bcprov
// under bcpkix and bcutil) is a child only in the omitted edges, and a
// dependency mined without its classes exports its calls into them
// name_only, which the API, mining it with its whole closure, does not.
func closureJARs(resolved *dependency.ResolveResult, byRef map[string]dependency.Dependency, dep dependency.Dependency) []string {
	self := dependency.Ref{Module: dep.Module, Version: dep.Version}.Key()
	seen := map[string]bool{self: true}
	stack := []string{self}
	var jars []string
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, child := range slices.Concat(resolved.VersionedGraph[node], resolved.OmittedEdges[node]) {
			key := child.Key()
			if seen[key] {
				continue
			}
			seen[key] = true
			stack = append(stack, key)
			if jar := byRef[key].CompiledArtifactPath; jar != "" && !slices.Contains(jars, jar) {
				jars = append(jars, jar)
			}
		}
	}
	sort.Strings(jars)
	return jars
}

// offlineRulesetKey is the cache key and the response label of the scan's
// ruleset: its name and version, and the content of every rule and card file
// it loaded or the scan named.
func offlineRulesetKey(manager *lockedRules) (key, label string, err error) {
	paths, err := manager.Load()
	if err != nil {
		return "", "", err
	}
	info := manager.Info()
	label = info.Version
	if label == "" && info.ChecksumSHA256 != "" {
		label = "local-" + info.ChecksumSHA256[:12]
	}
	dirs := slices.Clone(scanRuleDirs)
	files := []string{scanCardsIndex}
	if len(dirs) == 0 {
		// A leased or cached remote ruleset: its rule files, and the cards
		// beside them. A leased one loads as the directory it was decrypted
		// into for this run, hashed by the paths under it: its name changes
		// every run.
		for _, path := range paths {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				dirs = append(dirs, path)
			} else {
				files = append(files, path)
			}
		}
	}
	if scanCardsDir != "" {
		dirs = append(dirs, scanCardsDir)
	}
	key, err = offline.RulesetKey(dirs, files, []string{info.Name, info.Version, info.ChecksumSHA256})
	return key, label, err
}

// lockedRules serializes a rules manager for the dependencies mined at once.
type lockedRules struct {
	mu      sync.Mutex
	manager *rules.Manager
}

func (l *lockedRules) Load() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.manager.Load()
}

func (l *lockedRules) Name() string { return "scan ruleset" }

func (l *lockedRules) Info() entities.RulesInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.manager.Info()
}

// inProcessMiner mines a dependency as the SCANOSS miner does, with this
// scan's ruleset: `scan --languages java --output F --export-graph-fragment G
// --type-jars J DIR`, in process.
type inProcessMiner struct {
	rules       *rules.Manager
	ruleDirs    []string
	javaRuntime javaruntime.Config
	timeout     time.Duration
	// catalogs loads the ruleset's cards once for every dependency.
	catalogs *cards.Catalogs
	// language is the closure's ecosystem, java or python: the language
	// every dependency is mined in.
	language string
}

// cardsLanguage is the cards scanner's language option: the cards language
// of the ecosystem the miner mines (mineLanguage).
func (m *inProcessMiner) cardsLanguage() string {
	lang, _ := cards.ForEcosystem(m.mineLanguage())
	return lang.Name
}

// mineLanguage is the language a dependency is mined in.
func (m *inProcessMiner) mineLanguage() string {
	switch m.language {
	case ecosystemPython, ecosystemGo, ecosystemNode, ecosystemRust, ecosystemRuby:
		return m.language
	}
	return ecosystemJava
}

// mineLanguageHints are the language hints of the miner's scan of a
// dependency, `scan --languages <cards language>`: the scan names its
// ecosystem as rule files and card directories do (javascript and
// typescript for node). The hints pick the rules the scan loads, and
// with them the rule ids it reports, so a hint the rule filter does not
// know ("node") would load every rule and report other ids.
func (m *inProcessMiner) mineLanguageHints() []string {
	return scannedLanguageHints([]string{m.mineLanguage()})
}

// mineSetup is a scan of dir with the miner's options: Java, the default
// exclusions, tests skipped.
func mineSetup(dir string) (targetDir string, skipPatterns []string, skipMatcher skip.SkipMatcher, err error) {
	targetDir, err = callGraphTargetDir(dir)
	if err != nil {
		return "", nil, nil, err
	}
	skipPatterns, _ = buildSkipPatterns(targetDir, false, nil)
	skipPatterns = applyTestSkipPatterns(skipPatterns, false)
	skipPatterns = applyCTestSkipPatterns(skipPatterns, targetDir, false)
	return targetDir, skipPatterns, skip.NewMatcher(skipPatterns, true), nil
}

func (m *inProcessMiner) Mine(ctx context.Context, dir string, typeJARs []string) (findings, fragment []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	languages := m.mineLanguageHints()
	graphs := newGraphStore(dir, strings.Join(typeJARs, string(os.PathListSeparator)))
	_, skipPatterns, skipMatcher, err := mineSetup(dir)
	if err != nil {
		return nil, nil, err
	}
	runtime := func() (javaruntime.Config, error) { return m.javaRuntime, nil }
	registry := scanner.NewRegistry()
	registry.RegisterFactory(cards.ScannerName, cards.NewScannerFactory(cards.Options{
		IndexPath: scanCardsIndex,
		CardsDir:  scanCardsDir,
		Ruleset:   cardsRuleset(m.ruleDirs, m.rules),
		Fragment:  cardsFragmentBuilder(graphs, dir, m.mineLanguage(), runtime, false, "", skipMatcher),
		Catalogs:  m.catalogs,
		Language:  m.cardsLanguage(),
	}))
	report, err := engine.NewOrchestrator(language.NewEnryDetector(skipMatcher), m.rules, registry).Scan(ctx, engine.ScanOptions{
		Target:        dir,
		ScannerName:   cards.ScannerName,
		LanguageHint:  languages,
		ScannerConfig: scanner.Config{Timeout: m.timeout, SkipPatterns: skipPatterns},
	})
	if err != nil {
		return nil, nil, err
	}
	engine.EnsureFindingSources(report)
	result, err := buildStandaloneCallGraphResult(graphs, dir, report, languages, m.javaRuntime, false, "", skipMatcher)
	if err != nil {
		return nil, nil, fmt.Errorf("build call graph: %w", err)
	}
	if passes := ruleGraphPassResults(result); len(passes) > 0 {
		if err := runRuleGraphPasses(nil, "", m.rules, report, passes); err != nil {
			return nil, nil, err
		}
	}
	engine.AssignFindingIDs(report)
	result = prepareReportOccurrenceKeys(graphs, dir, report, languages, m.javaRuntime, false, "", skipMatcher, result)
	resolved, err := prepareScanOIDProjection(report, false)
	if err != nil {
		return nil, nil, err
	}
	out, err := os.MkdirTemp("", "crypto-finder-offline-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { utils.Discard(os.RemoveAll(out)) }()
	fragmentPath, findingsPath := filepath.Join(out, "fragment.json"), filepath.Join(out, "findings.json")
	if err := scanutil.ExportResolvedGraphFragment(fragmentPath, "json", result, resolved); err != nil {
		return nil, nil, err
	}
	// After the export, so the classification never enters the fragment.
	if err := writeResolvedJSON(resolved, findingsPath); err != nil {
		return nil, nil, err
	}
	return readPair(findingsPath, fragmentPath)
}

// Annotate re-annotates a cached graph as the miner's annotate job does: over
// the stored graph alone, except for npm, whose package source the job passes
// as --source, because its API entry points are synthesized from its
// package.json and modules, which a stored graph does not carry.
func (m *inProcessMiner) Annotate(ctx context.Context, structural []byte, sources func(context.Context) (string, error)) (annotation, findings []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	var document graphfrag.GraphFragmentExport
	if err := json.Unmarshal(structural, &document); err != nil {
		return nil, nil, fmt.Errorf("decode cached graph: %w", err)
	}
	document.RestoreElided()
	document.ExpandInternalEdges()
	work, err := os.MkdirTemp("", "crypto-finder-offline-annotate-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { utils.Discard(os.RemoveAll(work)) }()
	target := work
	if m.mineLanguage() == ecosystemNode {
		if target, err = sources(ctx); err != nil {
			return nil, nil, fmt.Errorf("the package source to annotate: %w", err)
		}
	}
	targetDir, skipPatterns, skipMatcher, err := mineSetup(target)
	if err != nil {
		return nil, nil, err
	}
	registry := scanner.NewRegistry()
	registry.RegisterFactory(cards.ScannerName, cards.NewScannerFactory(cards.Options{
		IndexPath: scanCardsIndex,
		CardsDir:  scanCardsDir,
		Ruleset:   cardsRuleset(m.ruleDirs, m.rules),
		Fragment:  func(string) (graphfrag.GraphFragmentExport, error) { return document, nil },
		Catalogs:  m.catalogs,
		Language:  m.cardsLanguage(),
	}))
	// The miner's re-annotation hints the cards language: `annotate
	// --languages <cards language>`.
	report, err := engine.NewOrchestrator(language.NewEnryDetector(skipMatcher), m.rules, registry).Scan(ctx, engine.ScanOptions{
		Target:        target,
		ScannerName:   cards.ScannerName,
		LanguageHint:  []string{m.cardsLanguage()},
		ScannerConfig: scanner.Config{Timeout: m.timeout, SkipPatterns: skipPatterns},
	})
	if err != nil {
		return nil, nil, err
	}
	graph, err := runFragmentGraphPasses(report, &document, targetDir, m.rules)
	if err != nil {
		return nil, nil, err
	}
	resolved, err := prepareAnnotateProjection(report)
	if err != nil {
		return nil, nil, err
	}
	payload := scanutil.BuildGraphAnnotateExport(graph, resolved, &document)
	annotation, err = scanutil.MarshalAnnotateExport(&payload)
	if err != nil {
		return nil, nil, err
	}
	findingsPath := filepath.Join(work, "findings.json")
	if err := writeResolvedJSON(resolved, findingsPath); err != nil {
		return nil, nil, err
	}
	findings, err = os.ReadFile(findingsPath) // #nosec G304 -- written above.
	return annotation, findings, err
}

// writeResolvedJSON writes the findings report as scan --output writes it,
// with the PQC classification.
func writeResolvedJSON(resolved *oid.ResolvedReport, path string) error {
	pqc.Annotate(resolved)
	writer, err := output.NewWriterFactory().GetWriter(formatJSON)
	if err != nil {
		return err
	}
	return writer.WriteResolved(resolved, path)
}

func readPair(first, second string) ([]byte, []byte, error) {
	a, err := os.ReadFile(first) // #nosec G304 -- written by the caller.
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(second) // #nosec G304 -- written by the caller.
	return a, b, err
}
