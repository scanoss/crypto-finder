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

	// Step 2: List dependencies
	deps, err := r.listDependencies(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Maven dependencies: %w", err)
	}

	if len(deps) == 0 {
		log.Info().Msg("No Maven dependencies found")
		return result, nil
	}

	// Step 3: Download source JARs (best-effort)
	r.downloadSources(ctx, targetDir)

	// Step 4: Extract source JARs to cache and attach source dirs when available.
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

	// Step 5: Build dependency graph (best-effort)
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

// listDependencies runs `mvn dependency:list` and parses the output.
func (r *MavenResolver) listDependencies(ctx context.Context, targetDir string) ([]Dependency, error) {
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
	// #nosec G702 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "mvn", "dependency:list",
		"-DoutputFile="+tmpPath,
		"-DincludeScope=compile",
		"-DoutputAbsoluteArtifactFilename=false",
		"-q", // quiet mode
	)
	cmd.Dir = targetDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mvn dependency:list: %w\nstderr: %s", err, stderr.String())
	}

	// Parse the output file
	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("reading dependency list output: %w", err)
	}

	return r.parseDependencyList(string(data)), nil
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
		"-q",
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
