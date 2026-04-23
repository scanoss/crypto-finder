package dependency

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

const pythonExecutable = "python"

// pipPackage represents a single entry from `pip list --format=json`.
type pipPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// pipShowInfo holds parsed fields from `pip show` output.
type pipShowInfo struct {
	Name     string
	Version  string
	Location string
	Requires string
}

// PipResolver resolves Python dependencies using the `pip` CLI.
type PipResolver struct {
	lookPath    func(string) (string, error)
	execCommand func(context.Context, string, ...string) *exec.Cmd
}

// NewPipResolver creates a new Python/pip dependency resolver.
func NewPipResolver() *PipResolver {
	return &PipResolver{
		lookPath:    exec.LookPath,
		execCommand: exec.CommandContext,
	}
}

// Ecosystem returns "python".
func (r *PipResolver) Ecosystem() string {
	return pythonExecutable
}

// Resolve uses `pip list` and `pip show` to resolve all installed Python packages
// for the environment associated with the project at targetDir.
//
//nolint:gocognit,gocyclo // This workflow intentionally keeps fallback resolution logic together.
func (r *PipResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	// Step 1: Detect root module name
	rootModule := r.detectRootModule(targetDir)
	pythonExec, err := r.resolvePythonExecutable()
	if err != nil {
		return nil, fmt.Errorf("failed to locate Python interpreter: %w", err)
	}

	result := &ResolveResult{
		RootModule:   rootModule,
		Dependencies: make([]Dependency, 0),
		Graph:        make(map[string][]string),
	}

	// Step 2: List installed packages
	packages, err := r.pipList(ctx, pythonExec)
	if err != nil {
		return nil, fmt.Errorf("failed to list pip packages: %w", err)
	}

	if len(packages) == 0 {
		log.Info().Msg("No pip packages found")
		return result, nil
	}

	// Step 3: Get detailed info for all packages (batched)
	pkgNames := make([]string, len(packages))
	for i, pkg := range packages {
		pkgNames[i] = pkg.Name
	}

	infoMap, err := r.pipShow(ctx, pythonExec, pkgNames)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get pip show info, falling back to basic resolution")
	}

	// Step 4: Build distribution→import mapping via importlib.metadata
	distToImport := r.pythonPackagesDistributions(ctx, pythonExec)
	if len(distToImport) > 0 {
		log.Info().Int("mappings", len(distToImport)).Msg("Loaded Python distribution-to-import mapping via importlib.metadata")
	} else {
		// Fallback for Python < 3.10: scan dist-info directories on disk
		locations := collectUniqueLocations(infoMap)
		distToImport = buildDistInfoMapping(locations)
		if len(distToImport) > 0 {
			log.Info().Int("mappings", len(distToImport)).Msg("Built distribution-to-import mapping from dist-info directories")
		} else {
			log.Warn().Msg("Could not build distribution-to-import mapping, falling back to heuristic resolution")
		}
	}

	// Step 5: Build dependencies list and graph
	skippedSingleFile := 0
	skippedNoSource := 0
	for _, pkg := range packages {
		// Skip the root project itself
		if strings.EqualFold(normalizePackageName(pkg.Name), normalizePackageName(rootModule)) {
			continue
		}

		info := infoMap[normalizePackageName(pkg.Name)]
		dir, reason := r.resolvePackageDir(pkg.Name, info, distToImport)
		if dir == "" {
			switch reason {
			case skipReasonUnknown:
				log.Debug().Str("package", pkg.Name).Msg("Could not determine package source location, skipping")
			case skipReasonSingleFile:
				skippedSingleFile++
				log.Debug().Str("package", pkg.Name).Msg("Single-file module (no directory to scan), skipping")
			case skipReasonNoSource:
				skippedNoSource++
				log.Debug().Str("package", pkg.Name).Msg("No Python source found (likely C-extension or missing), skipping")
			default:
				log.Debug().Str("package", pkg.Name).Msg("Could not locate package source, skipping")
			}
			continue
		}

		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  pkg.Name,
			Version: pkg.Version,
			Dir:     dir,
		})

		// Build graph from Requires field
		if info.Requires != "" {
			for _, req := range strings.Split(info.Requires, ", ") {
				req = strings.TrimSpace(req)
				if req != "" {
					result.Graph[pkg.Name] = append(result.Graph[pkg.Name], req)
				}
			}
		}
	}

	log.Info().
		Int("resolved", len(result.Dependencies)).
		Int("skippedSingleFile", skippedSingleFile).
		Int("skippedNoSource", skippedNoSource).
		Str("root", result.RootModule).
		Msg("Resolved pip dependencies")

	return result, nil
}

func (r *PipResolver) resolvePythonExecutable() (string, error) {
	if virtualEnv := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); virtualEnv != "" {
		for _, candidate := range virtualEnvPythonCandidates(virtualEnv) {
			if candidate == "" {
				continue
			}
			if existsPath(candidate) {
				return candidate, nil
			}
		}
	}

	for _, candidate := range []string{"python3", pythonExecutable} {
		path, err := r.lookPath(candidate)
		if err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("neither python3 nor python is available in PATH")
}

func virtualEnvPythonCandidates(virtualEnv string) []string {
	base := filepath.Clean(virtualEnv)
	return []string{
		filepath.Join(base, "bin", pythonExecutable),
		filepath.Join(base, "bin", "python3"),
		filepath.Join(base, "Scripts", "python.exe"),
		filepath.Join(base, "Scripts", pythonExecutable),
	}
}

func existsPath(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(filepath.Clean(path)) // #nosec G304 -- path is cleaned before existence check
	return err == nil && !info.IsDir()
}

// detectRootModule tries to determine the root project name from manifest files.
func (r *PipResolver) detectRootModule(targetDir string) string {
	// Try pyproject.toml first
	pyprojectPath := filepath.Join(targetDir, "pyproject.toml")
	if data, err := os.ReadFile(pyprojectPath); err == nil {
		if name := parsePyprojectName(string(data)); name != "" {
			return name
		}
	}

	// Try setup.py / setup.cfg — just use directory name as fallback
	return filepath.Base(targetDir)
}

// parsePyprojectName extracts the project name from pyproject.toml.
// Looks for `name = "..."` under `[project]` section.
func parsePyprojectName(content string) string {
	for _, section := range []string{"[project]", "[tool.poetry]"} {
		if name := parseNameFromSection(content, section); name != "" {
			return name
		}
	}
	return ""
}

func parseNameFromSection(content, section string) string {
	inSection := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == section {
			inSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = false
			continue
		}
		if inSection && strings.HasPrefix(line, "name") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, "\"'")
				return name
			}
		}
	}
	return ""
}

// pipList runs `python -m pip list --format=json` and parses the output.
func (r *PipResolver) pipList(ctx context.Context, pythonExec string) ([]pipPackage, error) {
	cmd := r.execCommand(ctx, pythonExec, "-m", "pip", "list", "--format=json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s -m pip list --format=json: %w\nstderr: %s", pythonExec, err, stderr.String())
	}

	var packages []pipPackage
	if err := json.Unmarshal(stdout.Bytes(), &packages); err != nil {
		return nil, fmt.Errorf("failed to parse pip list output: %w", err)
	}

	return packages, nil
}

// pipShow runs `pip show pkg1 pkg2 ...` and parses the multi-package output.
//
//nolint:unparam // error return kept for interface consistency; per-batch errors are logged and swallowed.
func (r *PipResolver) pipShow(ctx context.Context, pythonExec string, packageNames []string) (map[string]pipShowInfo, error) {
	if len(packageNames) == 0 {
		return nil, nil
	}

	// Batch into groups to avoid command line length limits
	const batchSize = 50
	result := make(map[string]pipShowInfo)

	for i := 0; i < len(packageNames); i += batchSize {
		end := min(i+batchSize, len(packageNames))
		batch := packageNames[i:end]

		args := append([]string{"-m", "pip", "show"}, batch...)
		cmd := r.execCommand(ctx, pythonExec, args...)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			log.Debug().Err(err).Msg("pip show batch failed")
			continue
		}

		infos := parsePipShowOutput(stdout.String())
		maps.Copy(result, infos)
	}

	return result, nil
}

// parsePipShowOutput parses the output of `pip show` for multiple packages.
// Packages are separated by "---" lines. Each package has Key: Value lines.
func parsePipShowOutput(output string) map[string]pipShowInfo {
	result := make(map[string]pipShowInfo)
	var current pipShowInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if line == "---" {
			if current.Name != "" {
				result[normalizePackageName(current.Name)] = current
			}
			current = pipShowInfo{}
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			current.Name = value
		case "Version":
			current.Version = value
		case "Location":
			current.Location = value
		case "Requires":
			current.Requires = value
		}
	}

	// Don't forget the last package
	if current.Name != "" {
		result[normalizePackageName(current.Name)] = current
	}

	return result
}

// skipReason describes why a package could not be resolved.
type skipReason int

const (
	skipReasonUnknown    skipReason = iota
	skipReasonSingleFile            // package is a single .py file, not a directory
	skipReasonNoSource              // no Python source on disk (C-extension or missing)
)

// resolvePackageDir finds the source directory for a Python package.
// It uses the distribution→import mapping from importlib.metadata as the primary
// strategy, falling back to heuristic name normalization for older Python environments.
func (r *PipResolver) resolvePackageDir(pkgName string, info pipShowInfo, distToImport map[string][]string) (string, skipReason) {
	if info.Location == "" {
		return "", skipReasonNoSource
	}

	// Strategy 1: Use importlib.metadata mapping (most reliable)
	if len(distToImport) > 0 {
		importNames := distToImport[normalizePackageName(pkgName)]
		for _, importName := range importNames {
			dir := filepath.Join(info.Location, importName)
			if isDir(dir) {
				return dir, 0
			}
			// Check for single-file module (e.g., six.py)
			if isFile(filepath.Join(info.Location, importName+".py")) {
				return "", skipReasonSingleFile
			}
		}
	}

	// Strategy 2: Heuristic — normalized name as directory
	importName := normalizePackageName(pkgName)
	dir := filepath.Join(info.Location, importName)
	if isDir(dir) {
		return dir, 0
	}

	// Strategy 3: Try lowercase variant
	lower := strings.ToLower(importName)
	if lower != importName {
		dir = filepath.Join(info.Location, lower)
		if isDir(dir) {
			return dir, 0
		}
	}

	return "", skipReasonNoSource
}

// pythonPackagesDistributions calls the selected interpreter's
// importlib.metadata.packages_distributions()
// (available in Python 3.10+) and inverts the mapping to: normalized_dist_name → []import_names.
func (r *PipResolver) pythonPackagesDistributions(ctx context.Context, pythonExec string) map[string][]string {
	cmd := r.execCommand(ctx, pythonExec, "-c",
		"import json,importlib.metadata as m; print(json.dumps(m.packages_distributions()))")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Debug().Err(err).Str("stderr", stderr.String()).
			Msg("importlib.metadata.packages_distributions() unavailable (requires Python 3.10+)")
		return nil
	}

	return parsePackagesDistributions(stdout.Bytes())
}

// parsePackagesDistributions parses the JSON output of packages_distributions()
// and inverts it from import_name→[]dist_names to normalized_dist_name→[]import_names.
func parsePackagesDistributions(data []byte) map[string][]string {
	// Raw format: {"import_name": ["dist-name1", "dist-name2"], ...}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Warn().Err(err).Msg("Failed to parse packages_distributions() output")
		return nil
	}

	// Invert: normalized dist name → import names
	result := make(map[string][]string, len(raw))
	for importName, distNames := range raw {
		for _, distName := range distNames {
			key := normalizePackageName(distName)
			result[key] = append(result[key], importName)
		}
	}

	return result
}

// collectUniqueLocations extracts the unique site-packages locations from pip show info.
func collectUniqueLocations(infoMap map[string]pipShowInfo) []string {
	seen := make(map[string]bool)
	var locations []string
	for _, info := range infoMap {
		if info.Location != "" && !seen[info.Location] {
			seen[info.Location] = true
			locations = append(locations, info.Location)
		}
	}
	return locations
}

// buildDistInfoMapping scans *.dist-info directories in the given site-packages
// locations and builds a normalized_dist_name → []import_names mapping.
// It first tries top_level.txt; if that file is absent, it falls back to parsing
// the RECORD file to infer import names.
// This is a filesystem-based fallback for Python < 3.10 where
// importlib.metadata.packages_distributions() is unavailable.
func buildDistInfoMapping(locations []string) map[string][]string {
	result := make(map[string][]string)

	for _, location := range locations {
		// Glob all dist-info directories
		pattern := filepath.Join(location, "*.dist-info")
		distInfoDirs, err := filepath.Glob(pattern)
		if err != nil {
			log.Debug().Err(err).Str("location", location).Msg("Failed to glob dist-info directories")
			continue
		}

		for _, distInfoDir := range distInfoDirs {
			// Extract dist name: .../Foo_Bar-1.2.3.dist-info → "Foo_Bar"
			dirBase := filepath.Base(distInfoDir)
			distName := strings.SplitN(dirBase, "-", 2)[0]
			key := normalizePackageName(distName)

			// Strategy 1: try top_level.txt
			topLevelPath := filepath.Join(distInfoDir, "top_level.txt")
			if data, readErr := os.ReadFile(topLevelPath); readErr == nil {
				scanner := bufio.NewScanner(bytes.NewReader(data))
				for scanner.Scan() {
					importName := strings.TrimSpace(scanner.Text())
					if importName != "" {
						result[key] = append(result[key], importName)
					}
				}
				continue
			}

			// Strategy 2: parse RECORD file
			recordPath := filepath.Join(distInfoDir, "RECORD")
			importNames := parseRecordImportNames(recordPath, dirBase)
			if len(importNames) > 0 {
				result[key] = append(result[key], importNames...)
			}
		}
	}

	return result
}

// parseRecordImportNames extracts top-level import names from a dist-info RECORD file.
// RECORD is a CSV file listing every installed file path. Import names are inferred by:
//   - {name}/__init__.py  (top-level package)
//   - {name}.py           (single-file module)
//
// Entries belonging to the dist-info directory itself are skipped.
//
//nolint:gocognit,gocyclo,nestif // RECORD parsing intentionally handles many path shapes in one pass.
func parseRecordImportNames(recordPath, distInfoDirName string) []string {
	f, err := os.Open(recordPath)
	if err != nil {
		return nil
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Str("path", recordPath).Msg("Failed to close dist-info RECORD file")
		}
	}()

	seen := make(map[string]bool)        // depth-1 matches: {name}/__init__.py or {name}.py
	nsCandidate := make(map[string]bool) // namespace package candidates from deeper __init__.py
	reader := csv.NewReader(f)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip malformed lines
		}
		if len(record) == 0 {
			continue
		}

		filePath := record[0]

		// Skip dist-info entries (e.g., "beautifulsoup4-4.12.3.dist-info/METADATA")
		if strings.HasPrefix(filePath, distInfoDirName+"/") || filePath == distInfoDirName {
			continue
		}

		// Check for __init__.py at any depth
		if strings.HasSuffix(filePath, "/__init__.py") {
			parts := strings.SplitN(filePath, "/", 3)
			if len(parts) == 2 { // depth-1: "bs4/__init__.py" → "bs4"
				name := parts[0]
				if name != "" {
					seen[name] = true
				}
			} else if len(parts) == 3 { // depth-2+: "opentelemetry/trace/__init__.py" → candidate "opentelemetry"
				name := parts[0]
				if name != "" {
					nsCandidate[name] = true
				}
			}
			continue
		}

		// Check for single-file module: "typing_extensions.py" → "typing_extensions"
		if !strings.Contains(filePath, "/") && strings.HasSuffix(filePath, ".py") {
			name := strings.TrimSuffix(filePath, ".py")
			if name != "" {
				seen[name] = true
			}
		}
	}

	// Add namespace candidates that weren't already found at depth-1.
	// E.g., opentelemetry/trace/__init__.py → "opentelemetry" (no opentelemetry/__init__.py exists).
	for name := range nsCandidate {
		if !seen[name] {
			seen[name] = true
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	return names
}

// normalizePackageName converts a Python package name to its import-style form.
// PEP 503: dashes and dots become underscores, lowercase.
func normalizePackageName(name string) string {
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return strings.ToLower(name)
}

// isDir checks if the given path exists and is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// isFile checks if the given path exists and is a regular file.
func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
