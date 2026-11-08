// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// entry_scope.go decides which application functions nothing calls are
// chain roots (no_callers).
//
// Scanned alone, a library's functions nothing calls are its public surface,
// and each is a root. An application is different: its program starts at a
// recognized entry point, and a function neither that entry point nor
// anything it calls reaches is dead code. Taking it as a root reports what it
// reaches as reachable.
//
// So an application function nothing calls is not a root when all of these
// hold:
//
//   - its module (the directory of the nearest build manifest above its file,
//     or the scan when there is none) has an establishing entry point: a
//     program entry (main, a __main__ guard, a console script, a package.json
//     main or bin target, require.main === module) or a framework entry the
//     entry-point catalog names. A module without one keeps the fallback, so a
//     library scanned alone, or an application whose framework the catalog
//     does not know, behaves as before. Scoping by module rather than by scan
//     keeps one application of a monorepo from turning the entry-less
//     libraries and services next to it into dead code;
//   - it is test code, a free function, a static method, or an instance
//     method of a Java class that is not live: nothing in the application
//     creates, registers or annotates the class, and it extends nothing
//     outside the application (entry_java_instances.go). Any other instance
//     method may be invoked through an interface, a trait or a framework the
//     graph has no edge for, so it stays a root;
//   - nothing in the application's source or its module's configuration
//     files refers to it by name besides its own declaration (a comment, a
//     longer string literal, or a qualified name whose qualifier the file
//     imports from another module does not: entry_mentions.go), and no
//     decorator, attribute or annotation other than a test marker or an inert
//     built-in (entry_markers.go) sits on it. A function handed out as a
//     value (a handler passed to a router, a thread target, a callback, a
//     handler a deployment file names) has no call edge, and a decorator or
//     an attribute macro registers its function with something that calls
//     it. Either keeps it a root. When its source cannot be read, it stays
//     one.
//
// A module's manifest is looked for no higher than the scanned project's
// root (SetProjectRoot), so a manifest in an enclosing directory never
// makes a module.
//
// Implicit roots the runtime runs without a call (Go init functions and
// package variable initializers, Java static initializers, Python and Node
// module bodies) are never dropped, and they do not establish an entry point:
// a library has them too.

// manifestFiles are the build manifests whose directory is a module.
var manifestFiles = []string{
	"go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
	"Cargo.toml", "pyproject.toml", "setup.py", "setup.cfg",
}

var identifierPattern = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

// rootScopeCache holds one rootScope per user package set. Forks of a tracer
// share it.
type rootScopeCache struct {
	mu     sync.Mutex
	scopes map[uintptr]*rootScope
}

// rootScope is what decides, for one user package set, whether an uncalled
// application function is a root.
type rootScope struct {
	// entryModules holds the modules with an establishing entry point.
	entryModules map[string]bool
	// moduleOf maps a user function key to its module.
	moduleOf map[string]string
	// dead holds the uncalled-candidate functions that are not roots once
	// their module has an entry point: no reference, no decorator, readable
	// source.
	dead map[string]bool
}

// rootScopeFor returns the scope for userPackages, building it on first use.
func (t *Tracer) rootScopeFor(userPackages map[string]bool) *rootScope {
	if t.roots == nil || userPackages == nil {
		return nil
	}
	key := reflect.ValueOf(userPackages).Pointer()
	t.roots.mu.Lock()
	defer t.roots.mu.Unlock()
	if scope, ok := t.roots.scopes[key]; ok {
		return scope
	}
	scope := t.buildRootScope(userPackages)
	if t.roots.scopes == nil {
		t.roots.scopes = make(map[uintptr]*rootScope)
	}
	t.roots.scopes[key] = scope
	return scope
}

// uncalledIsRoot reports whether key, an application function no application
// code calls, is a chain root.
func (t *Tracer) uncalledIsRoot(key string, userPackages map[string]bool) bool {
	scope := t.rootScopeFor(userPackages)
	if scope == nil || !scope.dead[key] {
		return true
	}
	return !scope.entryModules[scope.moduleOf[key]]
}

func (t *Tracer) buildRootScope(userPackages map[string]bool) *rootScope {
	scope := &rootScope{entryModules: map[string]bool{}, moduleOf: map[string]string{}, dead: map[string]bool{}}
	isUserType := func(typeName string) bool { return t.isUserType(typeName, userPackages) }
	modules := map[string]string{}
	stop := t.moduleSearchRoot(userPackages)
	candidates := map[string][]*FunctionDecl{}
	declared := map[string]int{}
	var instanceMethods []*FunctionDecl
	for key, decl := range t.graph.Functions {
		if decl == nil || !t.isUserFunction(key, userPackages) {
			continue
		}
		module := moduleDir(decl.FilePath, stop, modules)
		scope.moduleOf[key] = module
		declared[BaseFunctionName(decl.ID.Name)]++
		mark, isEntry := t.entryMark(decl, isUserType)
		switch {
		case isEntry && establishesEntry(decl, mark):
			scope.entryModules[module] = true
		case !isEntry && droppableShape(decl) && decl.FilePath != "":
			candidates[decl.FilePath] = append(candidates[decl.FilePath], decl)
		case !isEntry && javaInstanceShape(decl):
			instanceMethods = append(instanceMethods, decl)
		}
	}
	if len(scope.entryModules) == 0 {
		return scope
	}
	scope.addUnliveInstanceMethods(candidates, instanceMethods, stop)
	if len(candidates) == 0 {
		return scope
	}

	t.markDead(scope, candidates, declared, userPackages)
	return scope
}

// markDead records the candidates that are not roots once their module has
// an entry point: test code, or code whose name nothing else in the source
// mentions and that carries no decorator. A candidate whose file cannot be
// read is never recorded.
func (t *Tracer) markDead(scope *rootScope, candidates map[string][]*FunctionDecl, declared map[string]int, userPackages map[string]bool) {
	names := map[string]bool{}
	for _, decls := range candidates {
		for _, decl := range decls {
			names[BaseFunctionName(decl.ID.Name)] = true
		}
	}
	mentions, readable := t.countMentions(names, userPackages, scope.entryModuleDirs())
	for file, decls := range candidates {
		lines, ok := readable[file]
		if !ok {
			continue
		}
		for _, decl := range decls {
			name := BaseFunctionName(decl.ID.Name)
			if !isTestDeclaration(decl) && (mentions[name] > declared[name] || decorated(lines, decl.StartLine)) {
				continue
			}
			scope.dead[decl.ID.String()] = true
		}
	}
}

// entryModuleDirs lists the manifest directories of the modules with an
// entry point: only their candidates can stop being roots.
func (s *rootScope) entryModuleDirs() []string {
	out := make([]string, 0, len(s.entryModules))
	for module := range s.entryModules {
		if module != "" {
			out = append(out, module)
		}
	}
	sort.Strings(out)
	return out
}

// establishesEntry reports whether an entry point shows that its module is a
// program: a program entry, or a framework entry the catalog names. Implicit
// roots and the callback heuristics (an @Override of a library method, a
// library's exports) occur in libraries too.
func establishesEntry(decl *FunctionDecl, mark EntryMark) bool {
	if implicitRoot(decl) && decl.ID.Name != moduleInitMethodName {
		return false
	}
	switch mark.Kind {
	case RootKindMain:
		return true
	case RootKindFrameworkEntry:
		return mark.Rule != ""
	case RootKindNoCallers, RootKindDepthLimit:
		return false
	default:
		return false
	}
}

// implicitRoot reports a declaration the runtime runs without a call: the
// synthetic <module>, <clinit>, <init:...> and <varinit:...> declarations.
func implicitRoot(decl *FunctionDecl) bool {
	return strings.HasPrefix(decl.ID.Name, "<")
}

// droppableShape reports a declaration that may stop being a root: test code,
// a free function or a static method, never an implicit root.
func droppableShape(decl *FunctionDecl) bool {
	if implicitRoot(decl) {
		return false
	}
	return isTestDeclaration(decl) || decl.ID.Type == "" || decl.Static
}

// countMentions counts, over the application's source files and the
// configuration files of its modules, how often each of names is referred
// to, and returns the lines of every source file it read. Source counts the
// references its parser reads in code (entry_mentions.go). A configuration
// file is read word by word, strings included: it names a function inside a
// string by design (a serverless handler, a Spring XML factory method).
func (t *Tracer) countMentions(names, userPackages map[string]bool, modules []string) (map[string]int, map[string][][]byte) {
	files := map[string]bool{}
	var decls []*FunctionDecl
	for key, decl := range t.graph.Functions {
		if decl != nil && decl.FilePath != "" && t.isUserFunction(key, userPackages) {
			files[decl.FilePath] = true
			decls = append(decls, decl)
		}
	}
	counter := newMentionCounter(names, decls)
	readable := map[string][][]byte{}
	for file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		readable[file] = bytes.Split(src, []byte("\n"))
		counter.countSource(file, src)
	}
	for _, file := range configFiles(modules) {
		if src, err := os.ReadFile(file); err == nil {
			counter.countRaw(src)
		}
	}
	return counter.mentions, readable
}

// configExtensions are the files a framework or a deployment names a
// function or a class in: deployment and framework files, Spring
// spring.factories and AutoConfiguration.imports, and (configFile) the
// META-INF/services files of the Java service loader, which have none.
var configExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".xml": true, ".json": true, ".toml": true,
	".cfg": true, ".ini": true, ".properties": true, ".conf": true,
	".factories": true, ".imports": true,
}

// configSkipDirs are directories that hold dependencies or build output, not
// the module's own configuration.
var configSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "target": true, "build": true, "dist": true,
	"out": true, "venv": true, "__pycache__": true, "site-packages": true,
}

// configFiles lists the configuration files under the module directories,
// each once, skipping hidden, dependency and build directories and files
// over 1 MiB.
func configFiles(modules []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, root := range modules {
		if err := filepath.WalkDir(root, configVisitor(root, seen, &out)); err != nil {
			continue // a module that cannot be walked only means fewer mentions
		}
	}
	return out
}

// configVisitor collects the configuration files of one module walk.
func configVisitor(root string, seen map[string]bool, out *[]string) fs.WalkDirFunc {
	const maxConfigBytes = 1 << 20
	return func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry only means fewer mentions
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || configSkipDirs[name]) {
				return filepath.SkipDir
			}
			return nil
		}
		if seen[path] || !configFile(path) {
			return nil
		}
		seen[path] = true
		if info, infoErr := entry.Info(); infoErr == nil && info.Size() <= maxConfigBytes {
			*out = append(*out, path)
		}
		return nil
	}
}

// configFile reports a configuration file by its extension, or a Java
// service-loader registration (META-INF/services/<interface>).
func configFile(path string) bool {
	if configExtensions[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	dir := filepath.Dir(path)
	return filepath.Base(dir) == "services" && filepath.Base(filepath.Dir(dir)) == "META-INF"
}

// decorated reports whether a decorator (@x), an attribute (#[x]) or an
// annotation sits on the declaration starting at line (1-based), on its own
// line or on the lines above it. A test marker (#[test], @Test,
// @pytest.mark.x, #[cfg(test)]) does not count, since a test runner is not
// the application, and neither does an inert built-in (#[allow(dead_code)],
// @functools.cache, @Deprecated: entry_markers.go), but a registering
// decorator above or beside one still does.
func decorated(lines [][]byte, line int) bool {
	const maxDecoratorLines = 20
	for i := line - 1; i >= 0 && i < len(lines) && i >= line-1-maxDecoratorLines; i-- {
		text := strings.TrimSpace(string(lines[i]))
		isDecorator := strings.HasPrefix(text, "@") || strings.HasPrefix(text, "#[")
		switch {
		case isDecorator && !registeringLine(text):
			continue
		case isDecorator:
			return true
		case i == line-1:
			// The declaration line itself.
		case text == "" || strings.HasSuffix(text, "}") || strings.HasSuffix(text, ";"):
			return false
		}
	}
	return false
}

// testMarker reports whether a decorator or attribute line marks test code,
// by its name and never its arguments: @routes.post("/attestation") is not
// one.
func testMarker(text string) bool {
	name := strings.TrimPrefix(strings.TrimPrefix(text, "#["), "@")
	args := ""
	if cut := strings.IndexAny(name, "( ]"); cut >= 0 {
		name, args = name[:cut], name[cut:]
	}
	last := name
	if cut := strings.LastIndexAny(last, ".:"); cut >= 0 {
		last = last[cut+1:]
	}
	switch {
	case testAnnotations[last], strings.EqualFold(last, "test"):
		return true
	case name == "pytest" || strings.HasPrefix(name, "pytest."):
		return true
	case name == "cfg" || name == "cfg_attr":
		return strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(args, "(")), "test")
	default:
		return false
	}
}

// moduleDir returns the directory of the nearest build manifest above file,
// no higher than stop, or "" when there is none. cache memoizes
// directories.
func moduleDir(file, stop string, cache map[string]string) string {
	if file == "" {
		return ""
	}
	dir := filepath.Dir(absPath(file))
	var visited []string
	module := ""
	for {
		if cached, ok := cache[dir]; ok {
			module = cached
			break
		}
		visited = append(visited, dir)
		if hasManifest(dir) {
			module = dir
			break
		}
		parent := filepath.Dir(dir)
		if dir == stop || parent == dir {
			break
		}
		dir = parent
	}
	for _, d := range visited {
		cache[d] = module
	}
	return module
}

// moduleSearchRoot is the highest directory a module lookup may reach: the
// scanned project's root when the producer set it (SetProjectRoot) and it
// holds the application's sources, else the deepest directory holding every
// application source file. A manifest above it belongs to something else (a
// home directory, an enclosing checkout).
func (t *Tracer) moduleSearchRoot(userPackages map[string]bool) string {
	root := t.userRoot(userPackages)
	if t.projectRoot != "" && (root == t.projectRoot || strings.HasPrefix(root, t.projectRoot+string(filepath.Separator))) {
		return t.projectRoot
	}
	return root
}

// SetProjectRoot names the scanned project's directory, the highest place a
// module's build manifest is looked for (entry_scope.go). Without it the
// lookup stops at the deepest directory holding every application source
// file, which misses a manifest above a src/ layout.
func (t *Tracer) SetProjectRoot(dir string) {
	if dir != "" {
		t.projectRoot = absPath(dir)
	}
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// userRoot is the deepest directory holding every application source file.
// A manifest above it belongs to something else (a home directory, an
// enclosing checkout), so module lookup stops there.
func (t *Tracer) userRoot(userPackages map[string]bool) string {
	root := ""
	first := true
	for key, decl := range t.graph.Functions {
		if decl == nil || decl.FilePath == "" || !t.isUserFunction(key, userPackages) {
			continue
		}
		dir := filepath.Dir(absPath(decl.FilePath))
		if first {
			root, first = dir, false
			continue
		}
		for root != dir && !strings.HasPrefix(dir, root+string(filepath.Separator)) {
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			root = parent
		}
	}
	return root
}

func hasManifest(dir string) bool {
	for _, name := range manifestFiles {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
