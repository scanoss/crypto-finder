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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
//   - it is test code, or it is a free function or a static method. An
//     instance method may be invoked through an interface, a trait or a
//     framework the graph has no edge for, so it stays a root;
//   - nothing in the application's source refers to it by name besides its
//     own declaration, and no decorator, attribute or annotation sits on it.
//     A function handed out as a value (a handler passed to a router, a
//     thread target, a callback) has no call edge, and a decorator or an
//     attribute macro registers its function with something that calls it.
//     Either keeps it a root. When its source cannot be read, it stays one.
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
	candidates := map[string][]*FunctionDecl{}
	declared := map[string]int{}
	for key, decl := range t.graph.Functions {
		if decl == nil || !t.isUserFunction(key, userPackages) {
			continue
		}
		module := moduleDir(decl.FilePath, modules)
		scope.moduleOf[key] = module
		declared[BaseFunctionName(decl.ID.Name)]++
		mark, isEntry := t.entryMark(decl, isUserType)
		switch {
		case isEntry && establishesEntry(decl, mark):
			scope.entryModules[module] = true
		case !isEntry && droppableShape(decl) && decl.FilePath != "":
			candidates[decl.FilePath] = append(candidates[decl.FilePath], decl)
		}
	}
	if len(scope.entryModules) == 0 || len(candidates) == 0 {
		return scope
	}

	names := map[string]bool{}
	for _, decls := range candidates {
		for _, decl := range decls {
			names[BaseFunctionName(decl.ID.Name)] = true
		}
	}
	mentions, readable := t.countMentions(names, userPackages)
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
	return scope
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

// countMentions counts, over the application's source files, how often each
// of names occurs as an identifier, and returns the lines of every file it
// read.
func (t *Tracer) countMentions(names map[string]bool, userPackages map[string]bool) (map[string]int, map[string][][]byte) {
	files := map[string]bool{}
	for key, decl := range t.graph.Functions {
		if decl != nil && decl.FilePath != "" && t.isUserFunction(key, userPackages) {
			files[decl.FilePath] = true
		}
	}
	mentions := map[string]int{}
	readable := map[string][][]byte{}
	for file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		readable[file] = bytes.Split(src, []byte("\n"))
		for _, word := range identifierPattern.FindAll(src, -1) {
			if names[string(word)] {
				mentions[string(word)]++
			}
		}
	}
	return mentions, readable
}

// decorated reports whether a decorator (@x), an attribute (#[x]) or an
// annotation sits on the declaration starting at line (1-based), on its own
// line or on the lines above it. One that names a test (#[test], @Test) does
// not count: a test runner is not the application.
func decorated(lines [][]byte, line int) bool {
	const maxDecoratorLines = 20
	for i := line - 1; i >= 0 && i < len(lines) && i >= line-1-maxDecoratorLines; i-- {
		text := strings.TrimSpace(string(lines[i]))
		isDecorator := strings.HasPrefix(text, "@") || strings.HasPrefix(text, "#[")
		switch {
		case isDecorator && strings.Contains(strings.ToLower(text), "test"):
			return false
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

// moduleDir returns the directory of the nearest build manifest above file,
// or "" when there is none. cache memoizes directories.
func moduleDir(file string, cache map[string]string) string {
	if file == "" {
		return ""
	}
	dir := filepath.Dir(file)
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
		if parent == dir {
			break
		}
		dir = parent
	}
	for _, d := range visited {
		cache[d] = module
	}
	return module
}

func hasManifest(dir string) bool {
	for _, name := range manifestFiles {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
