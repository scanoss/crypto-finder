package callgraph

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

var pythonProjectMarkers = []string{"pyproject.toml", "setup.py", "setup.cfg"}

// pythonAuxiliaryModules are top-level names every project of a monorepo has
// its own copy of and no import statement means to share (a project's tests
// or docs). They never make two projects collide.
var pythonAuxiliaryModules = map[string]bool{
	"tests": true, "test": true, "docs": true, "doc": true, "examples": true,
	"scripts": true, "benchmarks": true, "conftest": true, "setup": true,
	"noxfile": true, "tasks": true, "build": true, "dist": true,
}

var (
	// pythonManifestPackages matches a manifest line that declares where the
	// packages are (setuptools `packages`/`package-dir`, poetry and hatch
	// `packages`, setup.cfg `package_dir`, setup.py `package_dir=`).
	pythonManifestPackages = regexp.MustCompile(`(?m)^\s*(?:packages|package[-_]dir)\s*=`)
	pythonFromImport       = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b`)
	pythonPlainImport      = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([A-Za-z_][\w., \t]*)`)
)

func hasPythonProjectMarker(dir string) bool {
	for _, marker := range pythonProjectMarkers {
		if info, err := os.Stat(filepath.Join(dir, marker)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// declaresPythonPackageRoot reports whether a marker directory says where its
// importable packages are: a src or lib layout directory that holds Python, or
// a manifest that declares packages. A bare marker (a docs build, a vendored
// project, a tools directory) says nothing about how it is imported.
func declaresPythonPackageRoot(dir string) bool {
	for _, layout := range []string{"src", "lib"} {
		path := filepath.Join(dir, layout)
		if isPythonLayoutDir(path) && pythonDirHoldsSource(path) {
			return true
		}
	}
	for _, marker := range pythonProjectMarkers {
		if data, err := os.ReadFile(filepath.Join(dir, marker)); err == nil && pythonManifestPackages.Match(data) {
			return true
		}
	}
	return false
}

// pythonImportedModules is every module name a .py file under root imports,
// spelled as written. Hidden and skipped directories are not read.
func pythonImportedModules(root string, skipDir func(path, name string) bool) map[string]bool {
	imported := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if path != root && skipDir(path, entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".py") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, m := range pythonFromImport.FindAllSubmatch(data, -1) {
			imported[string(m[1])] = true
		}
		for _, m := range pythonPlainImport.FindAllSubmatch(data, -1) {
			for _, name := range strings.Split(string(m[1]), ",") {
				if fields := strings.Fields(name); len(fields) > 0 {
					imported[fields[0]] = true
				}
			}
		}
		return nil
	})
	return imported
}

// importsThroughPrefix reports whether any import spells prefix or a module
// below it.
func importsThroughPrefix(imported map[string]bool, prefix string) bool {
	for name := range imported {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

// discoverPythonProjectRoots finds the directories below root that are Python
// projects of their own, as in a monorepo's `packages/<name>/src/<import_name>`.
// Such a project is what `import` statements are relative to, so the
// directories between the scan root and the project name nothing and its
// modules are keyed from the project directory down.
//
// A marker directory (pyproject.toml, setup.py or setup.cfg) is re-rooted only
// when all of these hold; otherwise it keeps the directory-prefixed keys it
// has always had, which is what a root-level `from tools.x import mod` spells:
//   - it declares where its packages are (declaresPythonPackageRoot);
//   - no project file imports a module through the directory's own prefixed
//     path (`packages.app...`), the spelling re-rooting would break;
//   - every top-level module it exposes is unclaimed. Claims start from the
//     scan root's own modules and the dependencies' top-level names (taken),
//     and projects are visited in path order, so the first of two projects
//     defining the same name wins and the later keeps its prefix. A shared
//     name therefore links to the first-claimed project only.
//
// A directory that is itself a package (`__init__.py`) is never a project
// root, and the walk does not enter packages, hidden or skipped directories.
func discoverPythonProjectRoots(root string, taken map[string]bool, skipDir func(path, name string) bool) map[string]struct{} {
	claimed := pythonRootModuleNames(root, "")
	for name := range taken {
		claimed[name] = true
	}
	roots := map[string]struct{}{}
	var imported map[string]bool
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return filepath.SkipDir
		}
		if !entry.IsDir() || path == root {
			return nil
		}
		if skipDir(path, entry.Name()) || isPythonPackage(path) {
			return filepath.SkipDir
		}
		if !hasPythonProjectMarker(path) || !declaresPythonPackageRoot(path) {
			return nil
		}
		if imported == nil {
			imported = pythonImportedModules(root, skipDir)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || importsThroughPrefix(imported, strings.ReplaceAll(filepath.ToSlash(rel), "/", ".")) {
			return nil
		}
		if claimPythonProject(path, claimed) {
			roots[path] = struct{}{}
		}
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Str("dir", root).Msg("Python project discovery stopped early")
	}
	return roots
}

// claimPythonProject reports whether dir's top-level modules are all
// unclaimed, and if so records them as claimed.
func claimPythonProject(dir string, claimed map[string]bool) bool {
	names := pythonRootModuleNames(dir, "")
	if len(names) == 0 {
		return false
	}
	for name := range names {
		if claimed[name] && !pythonAuxiliaryModules[name] {
			return false
		}
	}
	for name := range names {
		claimed[name] = true
	}
	return true
}
