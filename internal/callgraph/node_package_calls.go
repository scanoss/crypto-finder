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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// nodeExportConditions are the package.json "exports" conditions a call
// through a package name resolves, in the order tried.
var nodeExportConditions = []string{"require", "import", "default", "node"}

// nodeBuiltinModules are the modules Node loads before any package of the same
// name: `require('crypto')` is the runtime's crypto even when node_modules
// holds an npm package called crypto.
var nodeBuiltinModules = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true, "cluster": true,
	"console": true, "constants": true, "crypto": true, "dgram": true, "diagnostics_channel": true,
	"dns": true, "domain": true, "events": true, "fs": true, "http": true, "http2": true, "https": true,
	"inspector": true, "module": true, "net": true, "os": true, "path": true, "perf_hooks": true,
	"process": true, "punycode": true, "querystring": true, "readline": true, "repl": true,
	"stream": true, "string_decoder": true, "sys": true, "timers": true, "tls": true,
	"trace_events": true, "tty": true, "url": true, "util": true, "v8": true, "vm": true,
	"wasi": true, "worker_threads": true, "zlib": true,
}

// nodePackageDirs maps each package of a Node build, by import path, to its
// directory.
func nodePackageDirs(ecosystem string, packages []PackageDir) map[string]string {
	if ecosystem != ecosystemNode {
		return nil
	}
	dirs := make(map[string]string, len(packages))
	for i := range packages {
		if packages[i].ImportPath != "" {
			dirs[packages[i].ImportPath] = filepath.Clean(packages[i].Dir)
		}
	}
	return dirs
}

// nodeDeclSite is where a function is declared.
type nodeDeclSite struct {
	file string
	line int
}

// nodePackageCalls links a call written through a package name, such as
// `require('liba').used()` or `import { used } from 'liba'`, to the function
// the package's entry module exports under that name. The parser keys such a
// call by the specifier (liba.used) while the package declares the function
// under its module path (liba/index.used), so without this the call graph
// never crosses from a caller into an npm package.
type nodePackageCalls struct {
	graph *CallGraph
	// dirs maps each package's import path to its directory.
	dirs   map[string]string
	shapes *NodeShapes
	// decls maps a declaration site to its function key, "" when two
	// functions share it.
	decls map[nodeDeclSite]string
	// contracted holds the callees the KB has a contract for, which keep the
	// name the contract is keyed by.
	contracted map[string]bool
	entries    map[string]string
}

// linkNodePackageCalls retargets the Node calls made through a package name to
// the function they reach. A call is left as written when its package is not
// in the build, the entry module or the export cannot be followed statically,
// no function of the graph is declared where the export is defined, or the KB
// models the call under its written name.
func (b *Builder) linkNodePackageCalls(graph *CallGraph) {
	if b.ecosystem != ecosystemNode || len(b.nodePackageDirs) == 0 {
		return
	}
	kb, err := contracts.LoadEmbedded(b.ecosystem)
	if err != nil {
		return
	}
	r := &nodePackageCalls{
		graph:      graph,
		dirs:       b.nodePackageDirs,
		shapes:     NewNodeShapes(),
		decls:      make(map[nodeDeclSite]string),
		contracted: make(map[string]bool, len(kb.Contracts)),
		entries:    make(map[string]string),
	}
	defer r.shapes.Close()
	for key := range kb.Contracts {
		method, _, _ := strings.Cut(key, "#")
		r.contracted[method] = true
	}
	for key, decl := range graph.Functions {
		site := nodeDeclSite{file: filepath.Clean(decl.FilePath), line: decl.StartLine}
		if _, taken := r.decls[site]; taken {
			r.decls[site] = ""
			continue
		}
		r.decls[site] = key
	}
	for _, decl := range graph.Functions {
		for i := range decl.Calls {
			if target, ok := r.resolve(&decl.Calls[i]); ok {
				decl.Calls[i].Callee = target
			}
		}
	}
}

func (r *nodePackageCalls) resolve(call *FunctionCall) (FunctionID, bool) {
	callee := call.Callee
	if callee.Type != "" || callee.Package == "" || r.graph.Functions[callee.String()] != nil || r.contracted[callee.String()] {
		return FunctionID{}, false
	}
	pkg, rest, ok := r.packageOf(callee.Package)
	if !ok {
		return FunctionID{}, false
	}
	file, members, ok := r.entryAndMembers(pkg, rest)
	if !ok {
		return FunctionID{}, false
	}
	name := callee.Name
	if call.nodeModuleValue {
		if len(members) > 0 {
			return FunctionID{}, false
		}
		name = nodeDefaultExport
	}
	path := append(append([]string{}, members...), name)
	defFile, line, ok := r.shapes.Definition(file, path[0], path[1:])
	if !ok {
		return FunctionID{}, false
	}
	key := r.decls[nodeDeclSite{file: filepath.Clean(defFile), line: line}]
	if key == "" {
		return FunctionID{}, false
	}
	return r.graph.Functions[key].ID, true
}

// packageOf splits a callee package written through a specifier into the
// longest build package it starts with and the rest: "/sub" for a subpath,
// ".a.b" for members of the module, or both.
func (r *nodePackageCalls) packageOf(written string) (pkg, rest string, ok bool) {
	for candidate := range r.dirs {
		if len(candidate) <= len(pkg) || nodeBuiltinModules[candidate] {
			continue
		}
		if written == candidate || strings.HasPrefix(written, candidate+"/") || strings.HasPrefix(written, candidate+".") {
			pkg = candidate
		}
	}
	return pkg, strings.TrimPrefix(written, pkg), pkg != ""
}

// entryAndMembers resolves rest, the part of a callee package after the
// package name, into the module file it loads and the member path below that
// module's exports. A subpath may itself contain dots ("pkg/sub.js"), so each
// split is tried from the longest subpath down.
func (r *nodePackageCalls) entryAndMembers(pkg, rest string) (string, []string, bool) {
	if !strings.HasPrefix(rest, "/") {
		file := r.entry(pkg, ".")
		return file, nodeMemberPath(rest), file != ""
	}
	for cut := len(rest); cut > 1; cut = strings.LastIndex(rest[:cut], ".") {
		if file := r.entry(pkg, "."+rest[:cut]); file != "" {
			return file, nodeMemberPath(rest[cut:]), true
		}
	}
	return "", nil, false
}

func nodeMemberPath(rest string) []string {
	rest = strings.TrimPrefix(rest, ".")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, ".")
}

// entry returns the source file that importing subpath ("." or "./sub") of
// pkg loads, or "" when it cannot be found.
func (r *nodePackageCalls) entry(pkg, subpath string) string {
	key := pkg + "\x00" + subpath
	if file, ok := r.entries[key]; ok {
		return file
	}
	file := nodePackageEntry(r.dirs[pkg], subpath)
	r.entries[key] = file
	return file
}

// nodePackageEntry resolves subpath of the package in dir the way Node does
// for the files a package ships: through package.json "exports" when it is
// declared, otherwise "main" (or index) for the package itself and the file
// the subpath names for any other.
func nodePackageEntry(dir, subpath string) string {
	var manifest struct {
		Main    string          `json:"main"`
		Exports json.RawMessage `json:"exports"`
	}
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil && json.Unmarshal(data, &manifest) != nil {
		return "" // Node refuses a package whose manifest does not parse
	}
	if len(manifest.Exports) > 0 && string(manifest.Exports) != nodeLiteralNull {
		target, ok := nodeExportTarget(manifest.Exports, subpath)
		if !ok {
			return ""
		}
		return nodeSourceFile(dir, target)
	}
	if subpath == "." {
		if manifest.Main != "" {
			if file := nodeSourceFile(dir, manifest.Main); file != "" {
				return UnminifiedNodeFile("", file)
			}
		}
		return nodeSourceFile(dir, "index.js")
	}
	return nodeSourceFile(dir, subpath)
}

// UnminifiedNodeFile returns file's unminified sibling (a.min.js -> a.js) when
// root ships one, else file: minifying renames the definitions exports name.
func UnminifiedNodeFile(root, file string) string {
	dir, base := filepath.Split(file)
	plain := filepath.Join(dir, strings.Replace(base, ".min.", ".", 1))
	if plain == filepath.Clean(file) {
		return file
	}
	if info, err := os.Stat(filepath.Join(root, plain)); err != nil || info.IsDir() {
		return file
	}
	return plain
}

// nodeExportTarget reads the target "exports" maps subpath to. The value is a
// target string, a condition object, a subpath object, or an array of
// alternatives.
func nodeExportTarget(exports json.RawMessage, subpath string) (string, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(exports, &object) == nil {
		for key := range object {
			if !strings.HasPrefix(key, ".") {
				continue
			}
			// A subpath object: only the subpaths it lists can be imported.
			value, found := object[subpath]
			if !found {
				return "", false
			}
			return nodeConditionTarget(value)
		}
	}
	if subpath != "." {
		return "", false
	}
	return nodeConditionTarget(exports)
}

func nodeConditionTarget(value json.RawMessage) (string, bool) {
	var target string
	if json.Unmarshal(value, &target) == nil {
		return target, target != ""
	}
	var alternatives []json.RawMessage
	if json.Unmarshal(value, &alternatives) == nil {
		for _, alternative := range alternatives {
			if target, ok := nodeConditionTarget(alternative); ok {
				return target, true
			}
		}
		return "", false
	}
	var conditions map[string]json.RawMessage
	if json.Unmarshal(value, &conditions) != nil {
		return "", false
	}
	for _, condition := range nodeExportConditions {
		if nested, ok := conditions[condition]; ok {
			if target, ok := nodeConditionTarget(nested); ok {
				return target, true
			}
		}
	}
	return "", false
}

// nodeSourceFile returns the file target, relative to dir, names: the file
// itself, the file with a source extension added, or the directory's index.
func nodeSourceFile(dir, target string) string {
	if strings.Contains(target, "*") {
		return ""
	}
	base := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(target, "./")))
	if rel, err := filepath.Rel(dir, base); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	candidates := []string{base}
	for _, ext := range nodeSourceExtensions {
		candidates = append(candidates, base+ext)
	}
	for _, ext := range nodeSourceExtensions {
		candidates = append(candidates, filepath.Join(base, "index"+ext))
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
