// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const ecosystemGo = "go"

// goModManifest is the manifest of a Go module.
const goModManifest = "go.mod"

// GoResolver reads a Go module's pinned closure from its go.mod, files only:
// since Go 1.17 a module's go.mod lists every module its build needs, at the
// version minimal version selection picks. A requirement marked `// indirect`
// is not direct. A module's own requirements, the closure's edges, come from
// the go.mod the module cache holds for it, when it holds one; the server
// supplies the edges it lacks. A module replaced by a directory outside the
// project (the scan root, else the module) is a local dependency
// (Dependency.Local), its edges read from that directory's go.mod. Nothing is
// downloaded and no go tool runs a build.
type GoResolver struct {
	modCache string
	scanRoot string
}

// SetScanRoot names the scanned tree: a replace directory inside it is the
// project's own code.
func (r *GoResolver) SetScanRoot(dir string) {
	r.scanRoot = dir
}

// NewGoResolver creates a Go resolver over the module cache GOMODCACHE names
// (else `go env GOMODCACHE`); without one, edges below the root are left out.
func NewGoResolver() *GoResolver {
	return &GoResolver{modCache: goModCache()}
}

// Ecosystem returns "go".
func (r *GoResolver) Ecosystem() string {
	return ecosystemGo
}

// CanResolve reports whether targetDir holds a go.mod.
func (r *GoResolver) CanResolve(targetDir string) bool {
	return fileExists(filepath.Join(targetDir, goModManifest))
}

// Resolve reads targetDir's go.mod into the pinned closure.
func (r *GoResolver) Resolve(_ context.Context, targetDir string) (*ResolveResult, error) {
	mod, err := readGoMod(filepath.Join(targetDir, goModManifest))
	if err != nil {
		return nil, failure.New(failure.CodeDependencyResolutionFailed, failure.StageDependency,
			fmt.Sprintf("read the go.mod of %s: %v", targetDir, err), failure.WithDetail("target_dir", targetDir))
	}
	result := &ResolveResult{
		RootModule:     mod.module,
		Source:         goModManifest,
		Graph:          map[string][]string{},
		VersionedGraph: map[string][]Ref{},
	}
	if goVersionBefore117(mod.goVer) {
		log.Warn().Str("module", mod.module).Str("go", mod.goVer).
			Msg("go.mod predates Go 1.17 and may not list every module the build needs: the dependency closure may be partial")
	}
	selected := map[string]Ref{}
	// local holds the source directory of each module a local directory
	// replaces outside the module: the code the build compiles.
	local := map[string]string{}
	var order []string
	project := projectDir(targetDir, r.scanRoot)
	for _, req := range mod.requires {
		ref, ok := mod.replaced(req.ref)
		if !ok {
			// A directory inside the project is its own code; one that does
			// not exist cannot be analyzed.
			dir := goLocalReplacement(targetDir, mod, req.ref)
			if dir == "" || isWithin(dir, project) {
				result.Unpinned = append(result.Unpinned, UnpinnedDependency{Module: req.ref.Module, Manifest: goModManifest})
				continue
			}
			ref = req.ref
			local[ref.Module] = absoluteScanRoot(dir)
		}
		selected[req.ref.Module] = ref
		order = append(order, req.ref.Module)
		if !req.indirect {
			result.DirectDependencies = append(result.DirectDependencies, ref.Module)
			result.Graph[mod.module] = append(result.Graph[mod.module], ref.Module)
		}
	}
	for _, path := range order {
		ref := selected[path]
		dep := Dependency{Module: ref.Module, Version: ref.Version, Dir: r.cacheDir(ref)}
		requires := r.cachedRequires
		if dir, ok := local[path]; ok {
			dep.Dir, dep.Local = dir, true
			requires = func(Ref) []string { return goModRequires(filepath.Join(dir, goModManifest)) }
		}
		result.Dependencies = append(result.Dependencies, dep)
		for _, child := range requires(ref) {
			target, ok := selected[child]
			if !ok || target.Module == ref.Module {
				continue
			}
			result.Graph[ref.Module] = appendUnique(result.Graph[ref.Module], target.Module)
			result.VersionedGraph[ref.Key()] = append(result.VersionedGraph[ref.Key()], target)
		}
	}
	log.Debug().Str("module", mod.module).Int("dependencies", len(result.Dependencies)).
		Int("unpinned", len(result.Unpinned)).Msg("Resolved the Go dependency closure")
	return result, nil
}

// cacheDir is a module version's extracted source in the module cache, or "".
func (r *GoResolver) cacheDir(ref Ref) string {
	if r.modCache == "" {
		return ""
	}
	dir := filepath.Join(r.modCache, goModCacheEscape(ref.Module)+"@"+ref.Version)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

// cachedRequires are the module paths a module version's own go.mod requires,
// read from the module cache's download cache; nil when it is not there.
func (r *GoResolver) cachedRequires(ref Ref) []string {
	if r.modCache == "" {
		return nil
	}
	return goModRequires(filepath.Join(r.modCache, "cache", "download", goModCacheEscape(ref.Module), "@v", ref.Version+".mod"))
}

// goModRequires are the module paths the go.mod at path requires, sorted;
// nil when it cannot be read.
func goModRequires(path string) []string {
	mod, err := readGoMod(path)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(mod.requires))
	for _, req := range mod.requires {
		out = append(out, req.ref.Module)
	}
	sort.Strings(out)
	return out
}

type goRequire struct {
	ref      Ref
	indirect bool
}

type goModFile struct {
	module   string
	goVer    string
	requires []goRequire
	// replaces maps `path` or `path@version` to the replacement: a module
	// version, or a local directory (Version "").
	replaces map[string]Ref
}

// replaced is ref after the go.mod's replace directives; ok is false for a
// replacement by a local directory.
func (m *goModFile) replaced(ref Ref) (Ref, bool) {
	to, hit := m.replaces[ref.Module+"@"+ref.Version]
	if !hit {
		to, hit = m.replaces[ref.Module]
	}
	if !hit {
		return ref, true
	}
	if to.Version == "" {
		return Ref{}, false
	}
	return to, true
}

// readGoMod reads the module, require and replace directives of a go.mod.
func readGoMod(path string) (*goModFile, error) {
	f, err := os.Open(path) // #nosec G304 -- the scan target's own go.mod, or the module cache's.
	if err != nil {
		return nil, err
	}
	defer func() { utils.Discard(f.Close()) }()
	mod := &goModFile{replaces: map[string]Ref{}}
	block := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			mod.directive(block, strings.Fields(line), indirect)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		if len(fields) >= 2 {
			mod.directive(fields[0], fields[1:], indirect)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mod, nil
}

func (m *goModFile) directive(verb string, args []string, indirect bool) {
	unquote := func(s string) string { return strings.Trim(s, `"`) }
	switch verb {
	case "module":
		if len(args) >= 1 {
			m.module = unquote(args[0])
		}
	case "go":
		if len(args) >= 1 {
			m.goVer = args[0]
		}
	case "require":
		if len(args) >= 2 {
			m.requires = append(m.requires, goRequire{Ref{Module: unquote(args[0]), Version: args[1]}, indirect})
		}
	case "replace":
		arrow := -1
		for i, a := range args {
			if a == "=>" {
				arrow = i
			}
		}
		if arrow < 1 || arrow+1 >= len(args) {
			return
		}
		from := unquote(args[0])
		if arrow == 2 {
			from += "@" + args[1]
		}
		to := Ref{Module: unquote(args[arrow+1])}
		if arrow+2 < len(args) {
			to.Version = args[arrow+2]
		}
		m.replaces[from] = to
	}
}

// goModCacheEscape writes a module path as the module cache stores it: an
// upper-case letter becomes `!` and its lower case.
func goModCacheEscape(path string) string {
	var b strings.Builder
	for _, r := range path {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// goModCache is GOMODCACHE, else what `go env GOMODCACHE` reports, else "".
func goModCache() string {
	return GoEnv("GOMODCACHE")
}

var goEnvCache sync.Map

// GoEnv is the environment variable name, else what `go env` reports for it,
// else "". `go env` runs once per name, outside any module and with the local
// toolchain, so it never downloads one.
func GoEnv(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if v, ok := goEnvCache.Load(name); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "env", name)
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=")
	out, err := cmd.Output()
	v := ""
	if err == nil {
		v = strings.TrimSpace(string(out))
	}
	goEnvCache.Store(name, v)
	return v
}

// goVersionBefore117 reports a go directive older than 1.17, from which go.mod
// lists the whole closure; none counts as older.
func goVersionBefore117(v string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(v, "%d.%d", &major, &minor); err != nil {
		return true
	}
	return major < 1 || (major == 1 && minor < 17)
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
