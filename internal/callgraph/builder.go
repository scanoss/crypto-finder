package callgraph

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// Parser extracts function declarations, calls, and imports from source files
// in a language-specific way. Each supported language implements this interface.
type Parser interface {
	// ParseDirectory parses all relevant source files in dir.
	// packagePath is the canonical namespace (Go import path, Java package, etc.).
	ParseDirectory(dir string, packagePath string) ([]*FileAnalysis, error)
	// SkipDirs returns directory names to skip during recursive traversal.
	SkipDirs() map[string]bool
	// SubPackagePath constructs a child package path from parent + directory name.
	SubPackagePath(parentPath, dirName string) string
	// PackageSeparator returns the separator used in package paths ("/" for Go, "." for Java).
	PackageSeparator() string
}

// PackageDir associates a filesystem directory with its package/module path.
type PackageDir struct {
	Dir        string // Absolute filesystem path
	ImportPath string // Package/module path (e.g., "crypto/aes" or "javax.crypto")
}

// Builder constructs a CallGraph from multiple packages using a language-specific parser.
type Builder struct {
	parser Parser
}

// NewBuilder creates a new call graph builder with the given parser.
func NewBuilder(parser Parser) *Builder {
	return &Builder{
		parser: parser,
	}
}

// PackageSeparator exposes the parser's package separator for use by the tracer.
func (b *Builder) PackageSeparator() string {
	return b.parser.PackageSeparator()
}

// BuildFromDirectories analyzes all source files in the given package directories
// and builds a unified call graph with a reverse caller index.
func (b *Builder) BuildFromDirectories(packages []PackageDir) (*CallGraph, error) {
	graph := &CallGraph{
		Functions: make(map[string]*FunctionDecl),
		Callers:   make(map[string][]string),
	}

	for _, pkg := range packages {
		if err := b.analyzePackage(pkg, graph); err != nil {
			log.Debug().Err(err).Str("package", pkg.ImportPath).Msg("Failed to analyze package")
			continue
		}
	}

	// Build the reverse caller index
	b.buildCallerIndex(graph)

	log.Info().
		Int("functions", len(graph.Functions)).
		Int("callees", len(graph.Callers)).
		Msg("Built call graph")

	return graph, nil
}

// analyzePackage parses all source files in a package directory,
// recursing into subdirectories to handle sub-packages.
func (b *Builder) analyzePackage(pkg PackageDir, graph *CallGraph) error {
	return b.analyzeDir(pkg.Dir, pkg.ImportPath, graph)
}

func (b *Builder) analyzeDir(dir, importPath string, graph *CallGraph) error {
	analyses, err := b.parser.ParseDirectory(dir, importPath)
	if err != nil {
		return err
	}

	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			key := fn.ID.String()
			graph.Functions[key] = fn
		}
	}

	// Recurse into subdirectories
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		log.Debug().Err(readErr).Str("dir", dir).Msg("Failed to read directory during call graph traversal")
	}

	skipDirs := b.parser.SkipDirs()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || skipDirs[name] {
			continue
		}
		subDir := filepath.Join(dir, name)
		subImportPath := b.parser.SubPackagePath(importPath, name)
		if err := b.analyzeDir(subDir, subImportPath, graph); err != nil {
			log.Debug().Err(err).Str("dir", subDir).Msg("Failed to analyze subdirectory")
		}
	}

	return nil
}

// buildCallerIndex builds the reverse index: for each callee, which functions call it.
func (b *Builder) buildCallerIndex(graph *CallGraph) {
	for callerKey, fn := range graph.Functions {
		for _, call := range fn.Calls {
			calleeKey := call.Callee.String()
			graph.Callers[calleeKey] = append(graph.Callers[calleeKey], callerKey)
		}
	}
}
