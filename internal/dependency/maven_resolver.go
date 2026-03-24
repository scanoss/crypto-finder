package dependency

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// pomProject represents the minimal pom.xml structure needed for resolution.
type pomProject struct {
	XMLName    xml.Name  `xml:"project"`
	GroupID    string    `xml:"groupId"`
	ArtifactID string    `xml:"artifactId"`
	Parent     pomParent `xml:"parent"`
	Modules    []string  `xml:"modules>module"`
	Packaging  string    `xml:"packaging"`
}

type pomParent struct {
	GroupID string `xml:"groupId"`
}

// MavenResolver resolves Java/Maven dependencies using the `mvn` tool.
type MavenResolver struct{}

// NewMavenResolver creates a new Maven dependency resolver.
func NewMavenResolver() *MavenResolver {
	return &MavenResolver{}
}

// Ecosystem returns "java".
func (r *MavenResolver) Ecosystem() string {
	return "java"
}

// Resolve uses Maven CLI to resolve all transitive dependencies for the project at targetDir.
// For multi-module projects, it uses a three-tier fallback strategy:
//
//	Tier 1: mvn dependency:list --fail-never (partial results from reactor)
//	Tier 2: Per-module resolution with -pl <module> (isolate each module)
//	Tier 3: mvn install -DskipTests, then retry Tier 1 (build locally first)
func (r *MavenResolver) Resolve(ctx context.Context, targetDir string, _ int) (*ResolveResult, error) {
	// Step 1: Parse pom.xml for root module info
	rootModule, err := r.parseRootModule(targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	result := &ResolveResult{
		RootModule:   rootModule,
		Dependencies: make([]Dependency, 0),
		Graph:        make(map[string][]string),
	}

	// Step 2: Detect multi-module project
	modules, isMultiModule := r.parseModules(targetDir)
	if isMultiModule {
		log.Info().Int("modules", len(modules)).Msg("Detected multi-module Maven project")
		// Populate WorkspaceMembers so all modules are treated as user code
		// for call chain tracing (following the cargo_resolver pattern).
		for _, module := range modules {
			moduleDir := filepath.Join(targetDir, module)
			result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{
				Name: rootModule + ":" + module,
				Dir:  moduleDir,
			})
		}
	}

	// Step 3 (Tier 1): List dependencies with --fail-never
	depsResult, err := r.listDependencies(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Maven dependencies: %w", err)
	}
	deps := depsResult.deps

	// Tier 2: If zero deps from a multi-module project, try per-module resolution
	if len(deps) == 0 && isMultiModule {
		log.Info().Msg("Tier 1 returned no dependencies, trying per-module resolution (Tier 2)")

		// Collect module artifactIds for inter-module detection
		moduleArtifactIDs := r.collectModuleArtifactIDs(targetDir, modules)

		perModuleResult, perModuleErr := r.listDependenciesPerModule(ctx, targetDir, modules)
		if perModuleErr == nil && len(perModuleResult.deps) > 0 {
			deps = perModuleResult.deps
		}

		// Tier 3: If still zero deps and inter-module failure detected, build locally and retry
		if len(deps) == 0 && isInterModuleFailure(depsResult.stderr, rootModule, moduleArtifactIDs) {
			log.Info().Msg("Inter-module dependency failure detected, building modules locally (Tier 3)")
			_ = r.installModules(ctx, targetDir)

			// Retry Tier 1 after install
			retryResult, retryErr := r.listDependencies(ctx, targetDir)
			if retryErr == nil && len(retryResult.deps) > 0 {
				deps = retryResult.deps
			}
		}
	}

	if len(deps) == 0 {
		log.Info().Msg("No Maven dependencies found")
		return result, nil
	}

	// Step 4: Download source JARs (best-effort)
	r.downloadSources(ctx, targetDir)

	// Step 5: Extract source JARs to cache and attach source dirs when available.
	cache, err := NewSourceCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create source cache: %w", err)
	}

	m2Repo := r.findM2Repository()
	withSources := 0

	for _, dep := range deps {
		dir := r.resolveSourceDir(dep, m2Repo, cache)
		dep.Dir = dir
		result.Dependencies = append(result.Dependencies, dep)

		if dir == "" {
			log.Debug().Str("module", dep.Module).Str("version", dep.Version).Msg("No source JAR available; including dependency without source directory")
			continue
		}

		withSources++
	}

	// Step 6: Build dependency graph (best-effort, with --fail-never)
	graph, err := r.dependencyTree(ctx, targetDir)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to build Maven dependency graph, call chain tracing may be limited")
	} else {
		result.Graph = graph
	}

	log.Info().
		Int("total", len(deps)).
		Int("withSources", withSources).
		Str("root", result.RootModule).
		Msg("Resolved Maven dependencies")

	return result, nil
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

// listDepsResult holds the result of a dependency listing attempt, including partial results.
type listDepsResult struct {
	deps    []Dependency
	stderr  string   // full stderr for diagnostics
	partial bool     // true if some modules failed but others succeeded
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
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", tmpPath).Msg("Failed to remove temporary file")
		}
	}()

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

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Even on error, parse whatever was written to the output file (partial results).
	data, _ := os.ReadFile(tmpPath)
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
		if seen[module] {
			continue
		}
		seen[module] = true

		deps = append(deps, Dependency{
			Module:  module,
			Version: version,
		})
	}

	return deps
}

// downloadSources runs `mvn dependency:sources` to download source JARs.
func (r *MavenResolver) downloadSources(ctx context.Context, targetDir string) {
	cmd := exec.CommandContext(ctx, "mvn", "dependency:sources", "-q")
	cmd.Dir = targetDir

	if err := cmd.Run(); err != nil {
		log.Warn().Err(err).Msg("Failed to download source JARs (some dependencies may be skipped)")
	}
}

// findM2Repository returns the path to the local Maven repository.
func (r *MavenResolver) findM2Repository() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".m2", "repository")
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
	parts := strings.Split(dep.Module, ":")
	if len(parts) != 2 {
		return ""
	}
	groupID, artifactID := parts[0], parts[1]

	// groupId dots become path separators
	groupPath := strings.ReplaceAll(groupID, ".", string(os.PathSeparator))
	sourceJAR := filepath.Join(m2Repo, groupPath, artifactID, dep.Version,
		fmt.Sprintf("%s-%s-sources.jar", artifactID, dep.Version))

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

// dependencyTree runs `mvn dependency:tree` and parses the text output into an adjacency list.
func (r *MavenResolver) dependencyTree(ctx context.Context, targetDir string) (map[string][]string, error) {
	tmpFile, err := os.CreateTemp("", "mvn-tree-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", tmpPath).Msg("Failed to remove temporary file")
		}
	}()

	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", "dependency:tree",
		"-DoutputFile="+tmpPath,
		"-DoutputType=text",
		"-DappendOutput=true",
		"--fail-never",
	)
	cmd.Dir = targetDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mvn dependency:tree: %w\nstderr: %s", err, stderr.String())
	}

	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("reading dependency tree output: %w", err)
	}

	return r.parseTreeOutput(string(data)), nil
}

// parseTreeOutput parses the text output of `mvn dependency:tree`.
// Each line is indented with tree characters like "+- ", "\- ", "|  ".
// Format: "groupId:artifactId:type:version:scope".
func (r *MavenResolver) parseTreeOutput(output string) map[string][]string {
	graph := make(map[string][]string)
	var stack []string // stack of modules at each depth

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

		// Calculate depth by counting tree indentation characters
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

		parts := strings.Split(strings.TrimSpace(trimmed), ":")
		if len(parts) < 4 {
			continue
		}

		module := parts[0] + ":" + parts[1]

		// Maintain stack
		if depth == 0 {
			stack = []string{module}
		} else {
			// Trim stack to parent depth
			if depth <= len(stack) {
				stack = stack[:depth]
			}
			// Add edge from parent
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				graph[parent] = append(graph[parent], module)
			}
			stack = append(stack, module)
		}
	}

	return graph
}

// listDependenciesPerModule resolves dependencies for each module independently.
// This is Tier 2: when the reactor build fails, individual modules may still resolve.
func (r *MavenResolver) listDependenciesPerModule(ctx context.Context, targetDir string, modules []string) (*listDepsResult, error) {
	seen := make(map[string]bool)
	var allDeps []Dependency
	anyPartial := false

	for _, module := range modules {
		tmpFile, err := os.CreateTemp("", "mvn-deps-*.txt")
		if err != nil {
			continue
		}
		tmpPath := tmpFile.Name()
		_ = tmpFile.Close()

		// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
		cmd := exec.CommandContext(ctx, "mvn", "dependency:list",
			"-pl", module,
			"-DoutputFile="+tmpPath,
			"-DincludeScope=compile",
			"-DoutputAbsoluteArtifactFilename=false",
		)
		cmd.Dir = targetDir

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		runErr := cmd.Run()

		data, _ := os.ReadFile(tmpPath)
		_ = os.Remove(tmpPath)

		if runErr != nil {
			anyPartial = true
			log.Debug().
				Str("module", module).
				Str("stderr", truncate(stderr.String(), 300)).
				Msg("Per-module dependency:list failed, skipping module")
			continue
		}

		for _, dep := range r.parseDependencyList(string(data)) {
			if !seen[dep.Module] {
				seen[dep.Module] = true
				allDeps = append(allDeps, dep)
			}
		}
	}

	return &listDepsResult{
		deps:    allDeps,
		partial: anyPartial,
	}, nil
}

// installModules runs `mvn install -DskipTests` to build all modules locally,
// making inter-module artifacts available in ~/.m2/repository.
// This is Tier 3: expensive but resolves inter-module transitive dependencies.
func (r *MavenResolver) installModules(ctx context.Context, targetDir string) error {
	log.Info().Msg("Building modules locally to resolve inter-module dependencies (this may take several minutes)...")

	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", "install",
		"-DskipTests",
		"--fail-never",
		"-q",
	)
	cmd.Dir = targetDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Warn().
			Str("stderr", truncate(stderr.String(), 500)).
			Msg("mvn install partially failed (some modules may not have built)")
		// Non-fatal: even partial install may unblock dependency resolution
	}

	return nil
}

// isInterModuleFailure checks whether Maven's stderr indicates that the failure
// is caused by unresolvable inter-module dependencies (i.e., the project's own
// artifacts are not yet built/installed).
func isInterModuleFailure(stderr string, projectGroupID string, moduleArtifactIDs []string) bool {
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
