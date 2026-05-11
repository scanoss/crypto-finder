package dependency

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/javaruntime"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	mavenDependencyPluginVersion   = "3.6.1"
	sourceFallbackProgressInterval = 10
	// sourceFallbackMaxWorkers caps concurrent isolated `mvn :get` invocations
	// during per-dependency source fallback. Maven serializes writes to ~/.m2
	// internally; on top of that each invocation forks a JVM, so going beyond
	// ~8 yields diminishing returns and wastes RAM.
	sourceFallbackMaxWorkers = 8
)

// pomProject represents the minimal pom.xml structure needed for resolution.
type pomProject struct {
	XMLName      xml.Name        `xml:"project"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Parent       pomParent       `xml:"parent"`
	Modules      []string        `xml:"modules>module"`
	Packaging    string          `xml:"packaging"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

// pomDependency represents a single <dependency> element in pom.xml.
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

type pomParent struct {
	GroupID string `xml:"groupId"`
}

type mavenCommandOptions struct {
	dir            string
	args           []string
	startMessage   string
	successMessage string
	debugOutput    bool
}

type mavenCommandResult struct {
	stdout   string
	stderr   string
	duration time.Duration
}

type mavenSourceSummary struct {
	downloadedInFallback int
	missingAfterFallback int
}

// MavenResolver resolves Java/Maven dependencies using the `mvn` tool.
type MavenResolver struct {
	javaRuntime javaruntime.Config
}

// NewMavenResolver creates a new Maven dependency resolver.
func NewMavenResolver() *MavenResolver {
	return &MavenResolver{}
}

// SetJavaRuntime configures which Java runtime Maven commands should use.
func (r *MavenResolver) SetJavaRuntime(cfg javaruntime.Config) {
	r.javaRuntime = cfg
}

// Ecosystem returns "java".
func (r *MavenResolver) Ecosystem() string {
	return ecosystemJava
}

// Resolve uses Maven CLI to resolve all transitive dependencies for the project at targetDir.
// For multi-module projects, it uses a three-tier fallback strategy:
//
//	Tier 1: mvn dependency:list --fail-never (partial results from reactor)
//	Tier 2: Per-module resolution with -pl <module> (isolate each module)
//	Tier 3: mvn install -DskipTests, then retry Tier 1 (build locally first)
func (r *MavenResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	rootModule, err := r.parseRootModule(targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	result := &ResolveResult{
		RootModule:     rootModule,
		Dependencies:   make([]Dependency, 0),
		Graph:          make(map[string][]string),
		VersionedGraph: make(map[string][]Ref),
	}

	modules, isMultiModule := r.parseModules(targetDir)
	if isMultiModule {
		result.WorkspaceMembers = buildWorkspaceMembers(rootModule, targetDir, modules)
		log.Info().Int("modules", len(modules)).Msg("Detected multi-module Maven project")
	}

	// Fast path: if the pom.xml declares no dependencies and this is not a
	// multi-module project, skip the expensive Maven invocation entirely.
	// This is common for library artifacts that have no transitive dependencies.
	if !isMultiModule && !r.hasDeclaredDependencies(targetDir) {
		log.Info().Msg("No dependencies declared in pom.xml, skipping Maven resolution")
		return result, nil
	}

	depsResult, err := r.listDependencies(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Maven dependencies: %w", err)
	}
	deps := r.resolveWithFallbacks(ctx, targetDir, rootModule, modules, isMultiModule, depsResult)

	if len(deps) == 0 {
		log.Info().Msg("No Maven dependencies found")
		return result, nil
	}

	// Step 4: Download source JARs (best-effort)
	cache, err := NewSourceCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create source cache: %w", err)
	}

	m2Repo := r.findM2Repository()
	sourceSummary := r.downloadSources(ctx, targetDir, deps, m2Repo, cache)

	// Step 5: Extract source JARs to cache and attach source dirs when available.
	withSources := 0

	for _, dep := range deps {
		dep.CompiledArtifactPath = r.compiledJarPath(dep, m2Repo)
		dep.SourceArchivePath = r.sourceJarPath(dep, m2Repo)
		dir := r.resolveSourceDir(dep, m2Repo, cache)
		dep.Dir = dir
		result.Dependencies = append(result.Dependencies, dep)

		if dir == "" {
			log.Debug().Str("module", dep.Module).Str("version", dep.Version).Msg("No source JAR available; including dependency without source directory")
			continue
		}

		withSources++
	}

	// Step 6 — skipped: `mvn dependency:tree` was used to populate
	// result.VersionedGraph / result.Graph, but no consumer reads those
	// fields today (engine/callgraph builds packages from depResults +
	// resolver.WorkspaceMembers, not from the tree). For large transitive
	// trees this call alone takes minutes. Re-enable behind a flag if a
	// downstream consumer ever needs the graph.

	log.Info().
		Int("total", len(deps)).
		Int("withSources", withSources).
		Int("downloadedInFallback", sourceSummary.downloadedInFallback).
		Int("missingAfterFallback", sourceSummary.missingAfterFallback).
		Str("root", result.RootModule).
		Msg("Resolved Maven dependencies")

	return result, nil
}

func buildWorkspaceMembers(rootModule, targetDir string, modules []string) []WorkspaceMember {
	members := make([]WorkspaceMember, 0, len(modules))
	for _, module := range modules {
		members = append(members, WorkspaceMember{
			Name: rootModule + ":" + module,
			Dir:  filepath.Join(targetDir, module),
		})
	}
	return members
}

func (r *MavenResolver) resolveWithFallbacks(
	ctx context.Context,
	targetDir string,
	rootModule string,
	modules []string,
	isMultiModule bool,
	depsResult *listDepsResult,
) []Dependency {
	deps := depsResult.deps
	if len(deps) > 0 || !isMultiModule {
		return deps
	}

	log.Info().Msg("Tier 1 returned no dependencies, trying per-module resolution (Tier 2)")
	moduleArtifactIDs := r.collectModuleArtifactIDs(targetDir, modules)
	deps = r.resolvePerModule(ctx, targetDir, modules)
	if len(deps) > 0 {
		return deps
	}

	if !isInterModuleFailure(depsResult.stderr, rootModule, moduleArtifactIDs) {
		return deps
	}

	log.Info().Msg("Inter-module dependency failure detected, building modules locally (Tier 3)")
	if installErr := r.installModules(ctx, targetDir); installErr != nil {
		log.Warn().Err(installErr).Msg("Failed to build modules locally before retrying dependency resolution")
	}
	retryResult, retryErr := r.listDependencies(ctx, targetDir)
	if retryErr == nil && len(retryResult.deps) > 0 {
		return retryResult.deps
	}
	return deps
}

func (r *MavenResolver) resolvePerModule(ctx context.Context, targetDir string, modules []string) []Dependency {
	perModuleResult, err := r.listDependenciesPerModule(ctx, targetDir, modules)
	if err != nil || len(perModuleResult.deps) == 0 {
		return nil
	}
	return perModuleResult.deps
}

func (r *MavenResolver) runMavenCommand(ctx context.Context, opts mavenCommandOptions) (*mavenCommandResult, error) {
	if opts.startMessage != "" {
		log.Info().Strs("args", opts.args).Msg(opts.startMessage)
	}

	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", opts.args...)
	cmd.Dir = opts.dir
	if err := r.configureMavenCommand(cmd); err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startedAt := time.Now()
	err := cmd.Run()
	result := &mavenCommandResult{
		stdout:   stdout.String(),
		stderr:   stderr.String(),
		duration: time.Since(startedAt),
	}

	if opts.debugOutput && (result.stdout != "" || result.stderr != "") {
		log.Debug().
			Str("elapsed", utils.HumanDuration(result.duration)).
			Int64("elapsed_ms", result.duration.Milliseconds()).
			Str("stdout", truncate(result.stdout, 500)).
			Str("stderr", truncate(result.stderr, 500)).
			Msg("Maven command output")
	}

	if err == nil && opts.successMessage != "" {
		log.Info().
			Str("elapsed", utils.HumanDuration(result.duration)).
			Int64("elapsed_ms", result.duration.Milliseconds()).
			Msg(opts.successMessage)
	}

	return result, err
}

func (r *MavenResolver) configureMavenCommand(cmd *exec.Cmd) error {
	selection, err := javaruntime.ResolveExplicitSelection(r.javaRuntime)
	if err != nil {
		return err
	}
	if selection == nil {
		return nil
	}

	cmd.Env = javaruntime.EnvWithJavaHome(os.Environ(), selection.JavaHome)
	return nil
}

// collectModuleArtifactIDs reads each module's pom.xml to extract its artifactId.
func (r *MavenResolver) collectModuleArtifactIDs(targetDir string, modules []string) []string {
	ids := make([]string, 0, len(modules))
	for _, module := range modules {
		pomPath := filepath.Join(targetDir, module, "pom.xml")
		data, err := os.ReadFile(pomPath)
		if err != nil {
			// Use the directory name as a fallback artifactId (common convention)
			ids = append(ids, module)
			continue
		}
		var pom pomProject
		if err := xml.Unmarshal(data, &pom); err != nil || pom.ArtifactID == "" {
			ids = append(ids, module)
			continue
		}
		ids = append(ids, pom.ArtifactID)
	}
	return ids
}

// parseRootModule extracts the groupId from the project's pom.xml.
func (r *MavenResolver) parseRootModule(targetDir string) (string, error) {
	pomPath := filepath.Join(targetDir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return "", fmt.Errorf("reading pom.xml: %w", err)
	}

	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return "", fmt.Errorf("parsing pom.xml: %w", err)
	}

	groupID := pom.GroupID
	if groupID == "" {
		groupID = pom.Parent.GroupID
	}
	if groupID == "" {
		return "", fmt.Errorf("cannot determine groupId from pom.xml")
	}

	return groupID, nil
}

// parseModules reads the pom.xml and returns the list of module directory names.
// The second return value indicates whether this is a multi-module project.
func (r *MavenResolver) parseModules(targetDir string) ([]string, bool) {
	pomPath := filepath.Join(targetDir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, false
	}

	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, false
	}

	if len(pom.Modules) == 0 {
		return nil, false
	}

	// Validate that module directories exist
	modules := make([]string, 0, len(pom.Modules))
	for _, m := range pom.Modules {
		moduleDir := filepath.Join(targetDir, m)
		if info, err := os.Stat(moduleDir); err == nil && info.IsDir() {
			modules = append(modules, m)
		}
	}

	return modules, len(modules) > 0
}

// hasDeclaredDependencies checks if the pom.xml declares any dependencies.
// Returns true if there are <dependency> elements OR if parsing fails (to be safe).
// This enables skipping the expensive Maven invocation for library artifacts
// that have no transitive dependencies to resolve.
func (r *MavenResolver) hasDeclaredDependencies(targetDir string) bool {
	pomPath := filepath.Join(targetDir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		// If we can't read the pom, assume there might be dependencies
		return true
	}

	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		// If we can't parse the pom, assume there might be dependencies
		return true
	}

	return len(pom.Dependencies) > 0
}

// listDepsResult holds the result of a dependency listing attempt, including partial results.
type listDepsResult struct {
	deps    []Dependency
	stderr  string // full stderr for diagnostics
	partial bool   // true if some modules failed but others succeeded
}

// listDependencies runs `mvn dependency:list` with --fail-never to collect
// partial results from multi-module projects where some modules may fail.
func (r *MavenResolver) listDependencies(ctx context.Context, targetDir string) (*listDepsResult, error) {
	// Create a temp file for dependency output
	tmpFile, err := os.CreateTemp("", "mvn-deps-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", tmpPath).Msg("Failed to remove temporary file")
		}
	}()
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	// includeScope=compile includes compile + provided + system scopes (Maven's
	// scope hierarchy). This captures all dependencies the source code can call into,
	// while excluding test-only dependencies.
	// --fail-never continues past module failures in multi-module builds.
	// -DappendOutput=true appends each module's output instead of overwriting.
	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", "dependency:list",
		"-DoutputFile="+tmpPath,
		"-DincludeScope=compile",
		"-DoutputAbsoluteArtifactFilename=false",
		"-DappendOutput=true",
		"--fail-never",
	)
	cmd.Dir = targetDir
	if err := r.configureMavenCommand(cmd); err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Even on error, parse whatever was written to the output file (partial results).
	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	data, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		log.Debug().Err(readErr).Str("path", tmpPath).Msg("Failed to read Maven dependency:list output")
	}
	deps := r.parseDependencyList(string(data))

	result := &listDepsResult{
		deps:   deps,
		stderr: stderr.String(),
	}

	if runErr != nil {
		if len(deps) > 0 {
			// Partial success: some modules resolved, others failed.
			result.partial = true
			log.Warn().
				Int("resolved", len(deps)).
				Str("stderr", truncate(stderr.String(), 500)).
				Msg("Maven dependency:list partially succeeded (some modules failed)")
		} else {
			log.Debug().
				Str("stderr", truncate(stderr.String(), 500)).
				Str("stdout", truncate(stdout.String(), 500)).
				Msg("Maven dependency:list failed with no results")
		}
	}

	return result, nil
}

// parseDependencyList parses the output of `mvn dependency:list -DoutputFile=...`.
// Format: "groupId:artifactId:type:version:scope" or
// "groupId:artifactId:type:classifier:version:scope".
func (r *MavenResolver) parseDependencyList(output string) []Dependency {
	lines := strings.Split(output, "\n")
	deps := make([]Dependency, 0, len(lines))
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "The following") || strings.HasPrefix(line, "none") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}

		groupID := parts[0]
		artifactID := parts[1]
		// parts[2] is type (jar, pom, etc.)
		// scope is always last, so version is the penultimate token even when a classifier is present.
		version := parts[len(parts)-2]

		module := groupID + ":" + artifactID
		key := dependencyCoordinateKey(module, version)
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, Dependency{
			Module:  module,
			Version: version,
		})
	}

	return deps
}

// downloadSources runs a reactor-wide source download first, then falls back to
// isolated per-dependency source fetches for dependencies that are still missing
// local source JARs.
func (r *MavenResolver) downloadSources(ctx context.Context, targetDir string, deps []Dependency, m2Repo string, cache *SourceCache) mavenSourceSummary {
	summary := mavenSourceSummary{missingAfterFallback: len(deps)}
	if len(deps) == 0 || m2Repo == "" {
		return summary
	}

	_, err := r.runMavenCommand(ctx, mavenCommandOptions{
		dir:            targetDir,
		args:           []string{"dependency:sources", "-q"},
		startMessage:   "Starting Maven reactor source download",
		successMessage: "Maven reactor source download completed",
		debugOutput:    true,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Maven reactor source download failed; isolated fallback will be attempted for missing dependencies")
	}

	missing := r.missingSourceDependencies(deps, m2Repo, cache)
	if len(missing) == 0 {
		log.Info().Int("total", len(deps)).Msg("All Maven dependency sources are already available locally")
		summary.missingAfterFallback = 0
		return summary
	}

	workers := min(max(runtime.NumCPU()/2, 1), sourceFallbackMaxWorkers)
	if len(missing) < workers {
		workers = len(missing)
	}

	log.Info().
		Int("missingSources", len(missing)).
		Int("total", len(deps)).
		Int("workers", workers).
		Msg("Starting isolated Maven source fallback")

	summary.downloadedInFallback = r.runIsolatedSourceFallback(ctx, missing, m2Repo, workers)
	summary.missingAfterFallback = len(r.missingSourceDependencies(deps, m2Repo, cache))
	r.logSourceFallbackOutcome(summary)

	return summary
}

func (r *MavenResolver) runIsolatedSourceFallback(ctx context.Context, missing []Dependency, m2Repo string, workers int) int {
	var (
		downloaded int64 // atomic
		attempted  int64 // atomic
	)

	depCh := make(chan Dependency, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go r.runSourceFallbackWorker(ctx, depCh, m2Repo, len(missing), &downloaded, &attempted, &wg)
	}

	r.enqueueMissingSourceDependencies(ctx, depCh, missing)
	close(depCh)
	wg.Wait()

	return int(atomic.LoadInt64(&downloaded))
}

func (r *MavenResolver) runSourceFallbackWorker(
	ctx context.Context,
	depCh <-chan Dependency,
	m2Repo string,
	total int,
	downloaded, attempted *int64,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for dep := range depCh {
		ok, fetchErr := r.fetchDependencySource(ctx, dep, m2Repo)
		if fetchErr != nil {
			log.Debug().
				Err(fetchErr).
				Str("module", dep.Module).
				Str("version", dep.Version).
				Msg("Isolated Maven source fetch failed for dependency")
		}
		if ok {
			atomic.AddInt64(downloaded, 1)
		}

		done := atomic.AddInt64(attempted, 1)
		r.logSourceFallbackProgress(done, total, atomic.LoadInt64(downloaded))
	}
}

func (r *MavenResolver) enqueueMissingSourceDependencies(ctx context.Context, depCh chan<- Dependency, missing []Dependency) {
	for _, dep := range missing {
		select {
		case <-ctx.Done():
			// Stop scheduling new fetches if the parent context is done.
			// Already-running ones will see the cancellation themselves.
			return
		case depCh <- dep:
		}
	}
}

func (r *MavenResolver) logSourceFallbackProgress(done int64, total int, downloaded int64) {
	if done%sourceFallbackProgressInterval != 0 && done != int64(total) {
		return
	}

	log.Info().
		Int64("attempted", done).
		Int64("downloaded", downloaded).
		Int64("stillMissing", done-downloaded).
		Msg("Isolated Maven source fallback progress")
}

func (r *MavenResolver) logSourceFallbackOutcome(summary mavenSourceSummary) {
	if summary.missingAfterFallback > 0 {
		log.Warn().
			Int("downloadedInFallback", summary.downloadedInFallback).
			Int("missingAfterFallback", summary.missingAfterFallback).
			Msg("Some Maven dependency sources remain unavailable after isolated fallback")
		return
	}

	log.Info().
		Int("downloadedInFallback", summary.downloadedInFallback).
		Msg("Isolated Maven source fallback completed successfully")
}

// findM2Repository returns the path to the local Maven repository.
func (r *MavenResolver) findM2Repository() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".m2", "repository")
}

func (r *MavenResolver) sourceJarPath(dep Dependency, m2Repo string) string {
	if m2Repo == "" {
		return ""
	}

	parts := strings.Split(dep.Module, ":")
	if len(parts) != 2 || dep.Version == "" {
		return ""
	}

	groupPath := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifactID := parts[1]
	return filepath.Join(m2Repo, groupPath, artifactID, dep.Version,
		fmt.Sprintf("%s-%s-sources.jar", artifactID, dep.Version))
}

func (r *MavenResolver) compiledJarPath(dep Dependency, m2Repo string) string {
	if m2Repo == "" {
		return ""
	}

	parts := strings.Split(dep.Module, ":")
	if len(parts) != 2 || dep.Version == "" {
		return ""
	}

	groupPath := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifactID := parts[1]
	jarPath := filepath.Join(m2Repo, groupPath, artifactID, dep.Version,
		fmt.Sprintf("%s-%s.jar", artifactID, dep.Version))
	if _, err := os.Stat(jarPath); err != nil {
		return ""
	}
	return jarPath
}

func (r *MavenResolver) hasSourceJar(dep Dependency, m2Repo string) bool {
	sourceJAR := r.sourceJarPath(dep, m2Repo)
	if sourceJAR == "" {
		return false
	}

	if _, err := os.Stat(sourceJAR); err != nil {
		return false
	}
	return true
}

func (r *MavenResolver) missingSourceDependencies(deps []Dependency, m2Repo string, cache *SourceCache) []Dependency {
	missing := make([]Dependency, 0)
	for _, dep := range deps {
		if cache != nil && cache.CachedDir(dep.Module, dep.Version) != "" {
			continue
		}
		if r.hasSourceJar(dep, m2Repo) {
			continue
		}
		missing = append(missing, dep)
	}
	return missing
}

func (r *MavenResolver) fetchDependencySource(ctx context.Context, dep Dependency, m2Repo string) (bool, error) {
	if r.hasSourceJar(dep, m2Repo) {
		return false, nil
	}

	parts := strings.Split(dep.Module, ":")
	if len(parts) != 2 || dep.Version == "" {
		return false, fmt.Errorf("invalid Maven dependency coordinate: %s@%s", dep.Module, dep.Version)
	}

	tempDir, err := os.MkdirTemp("", "crypto-finder-maven-source-*")
	if err != nil {
		return false, fmt.Errorf("create isolated Maven temp dir: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			log.Debug().Err(removeErr).Str("dir", tempDir).Msg("Failed to remove isolated Maven temp dir")
		}
	}()

	minimalPom := `<project><modelVersion>4.0.0</modelVersion><groupId>scanoss.temp</groupId><artifactId>crypto-finder-temp</artifactId><version>1.0.0</version></project>`
	if err := os.WriteFile(filepath.Join(tempDir, "pom.xml"), []byte(minimalPom), 0o600); err != nil {
		return false, fmt.Errorf("write isolated Maven pom.xml: %w", err)
	}

	artifact := fmt.Sprintf("%s:%s:%s:jar:sources", parts[0], parts[1], dep.Version)
	_, err = r.runMavenCommand(ctx, mavenCommandOptions{
		dir: tempDir,
		args: []string{
			fmt.Sprintf("org.apache.maven.plugins:maven-dependency-plugin:%s:get", mavenDependencyPluginVersion),
			"-Dartifact=" + artifact,
			"-Dtransitive=false",
			"-q",
		},
		debugOutput: true,
	})
	if err != nil {
		return r.hasSourceJar(dep, m2Repo), err
	}

	return r.hasSourceJar(dep, m2Repo), nil
}

// resolveSourceDir finds and extracts the source JAR for a dependency.
func (r *MavenResolver) resolveSourceDir(dep Dependency, m2Repo string, cache *SourceCache) string {
	if m2Repo == "" {
		return ""
	}

	// Check cache first
	if dir := cache.CachedDir(dep.Module, dep.Version); dir != "" {
		return dir
	}

	// Locate source JAR in ~/.m2/repository/
	sourceJAR := r.sourceJarPath(dep, m2Repo)
	if sourceJAR == "" {
		return ""
	}

	if _, err := os.Stat(sourceJAR); err != nil {
		return ""
	}

	// Extract to cache
	dir, err := cache.ExtractZip(sourceJAR, dep.Module, dep.Version, []string{".java"})
	if err != nil {
		log.Debug().Err(err).Str("jar", sourceJAR).Msg("Failed to extract source JAR")
		return ""
	}

	return dir
}

// parseTreeOutput parses the text output of `mvn dependency:tree`.
// Each line is indented with tree characters like "+- ", "\- ", "|  ".
// Format: "groupId:artifactId:type:version:scope".
func (r *MavenResolver) parseTreeOutput(output string) map[string][]Ref {
	graph := make(map[string][]Ref)
	var stack []Ref // stack of modules at each depth

	for _, line := range strings.Split(output, "\n") {
		node, depth, ok := parseMavenTreeLine(line)
		if !ok {
			continue
		}
		stack = updateMavenTreeStack(graph, stack, node, depth)
	}

	return graph
}

func parseMavenTreeLine(line string) (Ref, int, bool) {
	if line == "" {
		return Ref{}, 0, false
	}
	depth, trimmed := parseMavenTreeDepth(line)
	node, ok := parseMavenTreeNode(strings.TrimSpace(trimmed))
	if !ok {
		return Ref{}, 0, false
	}
	return node, depth, true
}

func parseMavenTreeDepth(line string) (int, string) {
	depth := 0
	trimmed := line
	for strings.HasPrefix(trimmed, "|  ") || strings.HasPrefix(trimmed, "   ") {
		depth++
		trimmed = trimmed[3:]
	}
	if strings.HasPrefix(trimmed, "+- ") || strings.HasPrefix(trimmed, "\\- ") {
		depth++
		trimmed = trimmed[3:]
	}
	return depth, trimmed
}

func updateMavenTreeStack(graph map[string][]Ref, stack []Ref, node Ref, depth int) []Ref {
	if depth == 0 {
		return []Ref{node}
	}
	if depth <= len(stack) {
		stack = stack[:depth]
	}
	if len(stack) > 0 {
		parent := stack[len(stack)-1]
		parentKey := parent.Key()
		if !containsDependencyRef(graph[parentKey], node) {
			graph[parentKey] = append(graph[parentKey], node)
		}
	}
	return append(stack, node)
}

// listDependenciesPerModule resolves dependencies for each module independently.
// This is Tier 2: when the reactor build fails, individual modules may still resolve.
func (r *MavenResolver) listDependenciesPerModule(ctx context.Context, targetDir string, modules []string) (*listDepsResult, error) {
	seen := make(map[string]bool)
	var allDeps []Dependency
	anyPartial := false

	for _, module := range modules {
		deps, partial, err := r.resolveModuleDependencies(ctx, targetDir, module)
		if err != nil {
			return nil, err
		}
		if partial {
			anyPartial = true
		}
		for _, dep := range deps {
			key := dependencyCoordinateKey(dep.Module, dep.Version)
			if !seen[key] {
				seen[key] = true
				allDeps = append(allDeps, dep)
			}
		}
	}

	return &listDepsResult{
		deps:    allDeps,
		partial: anyPartial,
	}, nil
}

func (r *MavenResolver) resolveModuleDependencies(ctx context.Context, targetDir, module string) ([]Dependency, bool, error) {
	tmpFile, err := os.CreateTemp("", "mvn-deps-*.txt")
	if err != nil {
		return nil, false, err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", tmpPath).Msg("Failed to remove temporary file")
		}
	}()
	if err := tmpFile.Close(); err != nil {
		return nil, false, fmt.Errorf("close temp file: %w", err)
	}

	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", "dependency:list",
		"-pl", module,
		"-DoutputFile="+tmpPath,
		"-DincludeScope=compile",
		"-DoutputAbsoluteArtifactFilename=false",
	)
	cmd.Dir = targetDir
	if err := r.configureMavenCommand(cmd); err != nil {
		return nil, false, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	data, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		log.Debug().Err(readErr).Str("path", tmpPath).Msg("Failed to read per-module Maven dependency:list output")
		return nil, true, nil
	}

	if runErr != nil {
		log.Debug().
			Str("module", module).
			Str("stderr", truncate(stderr.String(), 300)).
			Msg("Per-module dependency:list failed, skipping module")
		return nil, true, nil
	}

	return r.parseDependencyList(string(data)), false, nil
}

func dependencyCoordinateKey(module, version string) string {
	return module + "@" + version
}

func parseMavenTreeNode(line string) (Ref, bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return Ref{}, false
	}
	module := parts[0] + ":" + parts[1]
	version := parts[len(parts)-2]
	return Ref{Module: module, Version: version}, true
}

func legacyGraphFromVersioned(versioned map[string][]Ref) map[string][]string {
	legacy := make(map[string][]string, len(versioned))
	for parentKey, children := range versioned {
		parentModule := parentKey
		if at := strings.LastIndex(parentKey, "@"); at > 0 {
			parentModule = parentKey[:at]
		}
		for _, child := range children {
			if child.Module == "" {
				continue
			}
			if !containsString(legacy[parentModule], child.Module) {
				legacy[parentModule] = append(legacy[parentModule], child.Module)
			}
		}
	}
	return legacy
}

func containsDependencyRef(values []Ref, want Ref) bool {
	for _, value := range values {
		if value.Module == want.Module && value.Version == want.Version {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// installModules runs `mvn install -DskipTests` to build all modules locally,
// making inter-module artifacts available in ~/.m2/repository.
// This is Tier 3: expensive but resolves inter-module transitive dependencies.
func (r *MavenResolver) installModules(ctx context.Context, targetDir string) error {
	result, err := r.runMavenCommand(ctx, mavenCommandOptions{
		dir: targetDir,
		args: []string{
			"install",
			"-DskipTests",
			"--fail-never",
			"-q",
		},
		startMessage: "Building modules locally to resolve inter-module dependencies (this may take several minutes)",
		debugOutput:  true,
	})
	if err != nil {
		entry := log.Warn().Err(err)
		if result == nil {
			entry.
				Str("target_dir", targetDir).
				Msg("mvn install failed before command output was available (some modules may not have built)")
		} else {
			entry.
				Str("stderr", truncate(result.stderr, 500)).
				Msg("mvn install partially failed (some modules may not have built)")
		}
		// Non-fatal: even partial install may unblock dependency resolution
		return err
	}

	return nil
}

// isInterModuleFailure checks whether Maven's stderr indicates that the failure
// is caused by unresolvable inter-module dependencies (i.e., the project's own
// artifacts are not yet built/installed).
func isInterModuleFailure(stderr, projectGroupID string, moduleArtifactIDs []string) bool {
	if projectGroupID == "" || len(moduleArtifactIDs) == 0 {
		return false
	}

	// Look for "Could not resolve dependencies" or "Could not find artifact"
	// where the missing artifact matches the project's own groupId + a known module.
	lowerStderr := strings.ToLower(stderr)
	hasResolutionError := strings.Contains(lowerStderr, "could not resolve dependencies") ||
		strings.Contains(lowerStderr, "could not find artifact") ||
		strings.Contains(lowerStderr, "could not transfer artifact")

	if !hasResolutionError {
		return false
	}

	// Check if any module artifactId appears in the error context
	for _, artifactID := range moduleArtifactIDs {
		marker := projectGroupID + ":" + artifactID
		if strings.Contains(stderr, marker) {
			return true
		}
	}

	return false
}

// truncate returns s trimmed to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
