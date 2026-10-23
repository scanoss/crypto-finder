// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

const (
	ecosystemNode  = "node"
	nodeModulesDir = "node_modules"
)

// nodeConditionOrder ranks package.json export conditions. When one subpath
// publishes several builds of a module (ESM and CommonJS), the first ranked
// one is indexed, so each api is surfaced once.
var nodeConditionOrder = []string{"import", "module", "default", "require", "node", "browser"}

// addNodeExportDeclarations indexes every export of the mined npm package under
// the specifiers a consumer imports it by, so a rule api written
// "@noble/curves/secp256k1.secp256k1.sign" meets the `secp256k1` export even
// though that export is a value built by a factory, not a function. A key the
// graph already declares keeps its function definition. It returns the
// identifiers the package's code declares or uses, for nodeExportDecls.
func addNodeExportDeclarations(root string, declsByFQN map[string][]*callgraph.FunctionDecl, graph *callgraph.CallGraph) *nodeMembers {
	members := &nodeMembers{shapes: callgraph.NewNodeShapes(), root: root, byFile: nodeDeclsByFile(root, graph)}
	pkg, ok := readNodePackage(root)
	if !ok {
		return members
	}
	for spec, rels := range nodeModuleFiles(root, pkg) {
		for _, rel := range rels {
			indexNodeModuleExports(spec, filepath.Join(root, filepath.FromSlash(rel)), declsByFQN, map[string]bool{}, 0)
		}
	}
	members.idents = nodePackageIdentifiers(root)
	return members
}

// nodeMembers decides whether an export has a member a rule api names.
type nodeMembers struct {
	idents map[string]bool // names the package's runtime code defines or uses
	shapes *callgraph.NodeShapes
	root   string
	byFile map[string][]*callgraph.FunctionDecl // the call graph's declarations, by absolute file
}

func nodeDeclsByFile(root string, graph *callgraph.CallGraph) map[string][]*callgraph.FunctionDecl {
	out := make(map[string][]*callgraph.FunctionDecl)
	if graph == nil {
		return out
	}
	for _, fn := range graph.Functions {
		file := fn.FilePath
		if !filepath.IsAbs(file) {
			file = filepath.Join(root, file)
		}
		out[filepath.Clean(file)] = append(out[filepath.Clean(file)], fn)
	}
	return out
}

// anchor moves each export-line declaration of api to the function, method or
// class that defines it, as the call graph declares it when it can, so the
// entry point is the function a consumer's call reaches.
func (m *nodeMembers) anchor(api string, decls []*callgraph.FunctionDecl) []*callgraph.FunctionDecl {
	if m == nil {
		return decls
	}
	out := make([]*callgraph.FunctionDecl, 0, len(decls))
	for _, d := range decls {
		out = append(out, m.anchorOne(api, d))
	}
	return out
}

func (m *nodeMembers) anchorOne(api string, d *callgraph.FunctionDecl) *callgraph.FunctionDecl {
	key, name := d.ID.Package, d.ID.Name
	if name != nodeDefaultExportName {
		key += "." + name
	}
	if !strings.HasPrefix(api, key) || len(m.byFile[filepath.Clean(d.FilePath)]) > 0 && d.StartLine != d.EndLine {
		return d // a call graph declaration already is the definition
	}
	var members []string
	for _, p := range strings.Split(strings.TrimPrefix(api[len(key):], "."), ".") {
		if p != "" && p != nodeConstructorMember {
			members = append(members, p)
		}
	}
	file, line, ok := m.shapes.Definition(d.FilePath, name, members)
	if !ok {
		return d
	}
	if strings.HasSuffix(api, "."+nodeConstructorMember) {
		if ctor, found := m.shapes.Constructor(file, line); found {
			line = ctor
		}
	}
	last := name
	if len(members) > 0 {
		last = members[len(members)-1]
	}
	if g := m.graphDecl(file, line, last); g != nil {
		return g
	}
	return &callgraph.FunctionDecl{ID: d.ID, FilePath: file, StartLine: line, EndLine: line}
}

// graphDecl returns the call graph's declaration of the function at file:line,
// or, when the graph indexes the package's TypeScript source rather than its
// build, the declaration named name in that source file.
func (m *nodeMembers) graphDecl(file string, line int, name string) *callgraph.FunctionDecl {
	if decls := m.byFile[filepath.Clean(file)]; len(decls) > 0 {
		var best *callgraph.FunctionDecl
		for _, d := range decls {
			if d.StartLine <= line && line <= d.EndLine && (best == nil || d.EndLine-d.StartLine < best.EndLine-best.StartLine) {
				best = d
			}
		}
		return best
	}
	for _, src := range nodeSourceFiles(m.root, file) {
		for _, d := range m.byFile[src] {
			if d.ID.Name == name {
				return d
			}
		}
	}
	return nil
}

// nodeSourceFiles returns the TypeScript sources a built file may come from:
// dist/src/a/b.js -> src/a/b.ts, lib/a.js -> src/a.ts.
func nodeSourceFiles(root, file string) []string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return nil
	}
	rel = strings.TrimSuffix(filepath.ToSlash(rel), path.Ext(rel))
	var stems []string
	for first, rest, ok := strings.Cut(rel, "/"); ok && nodeBuildDirs[first]; first, rest, ok = strings.Cut(rest, "/") {
		stems = append(stems, rest, "src/"+rest)
	}
	var out []string
	for _, stem := range stems {
		for _, ext := range []string{".ts", ".mts", ".cts", ".tsx"} {
			out = append(out, filepath.Join(root, filepath.FromSlash(stem+ext)))
		}
	}
	return out
}

// nodeBuildDirs are the directories a package ships its compiled output in.
var nodeBuildDirs = map[string]bool{"dist": true, "build": true, "lib": true, "esm": true, "cjs": true, "out": true, "es": true}

// has reports whether the export decl names has every member in members. The
// first member must belong to that export when its shape is known; deeper
// members, and exports whose shape is not, fall back to the package's names.
func (m *nodeMembers) has(decl *callgraph.FunctionDecl, members string) bool {
	if m == nil {
		return false
	}
	parts := strings.Split(members, ".")
	if parts[0] == nodeConstructorMember {
		callable, known := m.shapes.ExportIsCallable(decl.FilePath, decl.ID.Name)
		return callable || !known
	}
	if keys, known := m.shapes.ExportMembers(decl.FilePath, decl.ID.Name); known && !keys[parts[0]] {
		return false
	}
	for _, p := range parts {
		if !m.idents[p] && p != nodeConstructorMember {
			return false
		}
	}
	return true
}

const (
	nodeConstructorMember = "<init>"
	nodeDefaultExportName = "default"
)

// nodeStarDepth bounds how many `export *` hops are followed from one module.
const nodeStarDepth = 8

// indexNodeModuleExports indexes the exports of file under spec, then the
// exports of every module it re-exports wholesale, each anchored in the file
// that defines it. A module's own export wins over a re-exported one. A module
// re-exported under a name (`export * as ns`) is indexed under spec.ns.
func indexNodeModuleExports(spec, file string, declsByFQN map[string][]*callgraph.FunctionDecl, seen map[string]bool, depth int) {
	if seen[spec+"\x00"+file] || depth > nodeStarDepth {
		return
	}
	seen[spec+"\x00"+file] = true
	exports, err := callgraph.NodeModuleExports(file)
	if err != nil {
		log.Debug().Err(err).Str("file", file).Msg("node export index skipped a module")
		return
	}
	addNodeExportLines(spec, file, exports.Lines, depth > 0, declsByFQN)
	for _, from := range exports.StarFrom {
		if target := resolveNodeRelative(file, from); target != "" {
			indexNodeModuleExports(spec, target, declsByFQN, seen, depth+1)
		}
	}
	// A module that exports a function as itself is an api by its specifier.
	if exports.Self > 0 && len(declsByFQN[spec]) == 0 {
		declsByFQN[spec] = []*callgraph.FunctionDecl{{
			ID:       callgraph.FunctionID{Package: spec, Name: "default"},
			FilePath: file, StartLine: exports.Self, EndLine: exports.Self,
		}}
	}
	for _, from := range exports.FactoryFrom {
		if target := resolveNodeRelative(file, from); target != "" {
			indexNodeFactoryReturn(spec, target, declsByFQN)
		}
	}
	for ns, from := range exports.NamespaceOf {
		if target := resolveNodeRelative(file, from); target != "" {
			indexNodeModuleExports(spec+"."+ns, target, declsByFQN, seen, depth+1)
		}
	}
}

// indexNodeFactoryReturn indexes what the factory file exports returns, for a
// package that exports the factory's result.
func indexNodeFactoryReturn(spec, file string, declsByFQN map[string][]*callgraph.FunctionDecl) {
	exports, err := callgraph.NodeModuleExports(file)
	if err != nil {
		log.Debug().Err(err).Str("file", file).Msg("node export index skipped a factory")
		return
	}
	for name, line := range exports.Returned {
		if key := spec + "." + name; len(declsByFQN[key]) == 0 {
			declsByFQN[key] = []*callgraph.FunctionDecl{{
				ID:       callgraph.FunctionID{Package: spec, Name: name},
				FilePath: file, StartLine: line, EndLine: line,
			}}
		}
	}
}

// addNodeExportLines indexes a module's own export names; a re-exported module
// does not pass on its default, which `export *` never re-exports.
func addNodeExportLines(spec, file string, lines map[string]int, reexported bool, declsByFQN map[string][]*callgraph.FunctionDecl) {
	for name, line := range lines {
		key := spec + "." + name
		if (reexported && name == nodeDefaultExportName) || len(declsByFQN[key]) > 0 {
			continue
		}
		declsByFQN[key] = []*callgraph.FunctionDecl{{
			ID:       callgraph.FunctionID{Package: spec, Name: name},
			FilePath: file, StartLine: line, EndLine: line,
		}}
	}
}

// resolveNodeRelative resolves a relative module specifier the way Node and
// TypeScript output do: as written, with an added extension, or as a directory index.
func resolveNodeRelative(from, spec string) string {
	if !strings.HasPrefix(spec, ".") {
		return "" // another package's exports are not this package's API
	}
	base := filepath.Join(filepath.Dir(from), filepath.FromSlash(spec))
	candidates := []string{base}
	for _, ext := range []string{".js", ".ts", ".mjs", ".cjs"} {
		candidates = append(candidates, base+ext, filepath.Join(base, "index"+ext))
	}
	// tsc output keeps the .js the source imported, beside a .ts source of the same name.
	if strings.HasSuffix(base, ".js") {
		candidates = append(candidates, strings.TrimSuffix(base, ".js")+".ts")
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && isNodeSourceFile(filepath.ToSlash(c)) {
			return c
		}
	}
	return ""
}

// nodeExportDecls resolves a rule api to the export that owns it: the api
// itself when it names an export, else its longest dotted prefix that does
// ("...secp256k1.secp256k1.sign" -> "...secp256k1.secp256k1", "X.<init>" -> "X"). A rule covers
// every release, so a member must appear in this release's code: 0.9 has the
// `ed25519` export but no `ed25519.keygen`.
func nodeExportDecls(api string, declsByFQN map[string][]*callgraph.FunctionDecl, members *nodeMembers) []*callgraph.FunctionDecl {
	for key := api; ; {
		if decls := declsByFQN[key]; len(decls) > 0 {
			if key != api && !members.has(decls[0], api[len(key)+1:]) {
				return nil
			}
			return decls
		}
		i := strings.LastIndex(key, ".")
		if i <= strings.LastIndex(key, "/") {
			return nil
		}
		key = key[:i]
	}
}

// nodePackageIdentifiers collects the names the package's runtime code uses:
// not comments or strings, type declarations, or tests.
func nodePackageIdentifiers(root string) map[string]bool {
	idents := make(map[string]bool)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if p != root && (d.Name() == nodeModulesDir || nodeTestDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isNodeRuntimeSource(d.Name()) {
			return nil
		}
		names, err := callgraph.NodeCodeNames(p)
		if err != nil {
			return nil //nolint:nilerr // an unparsable file contributes no identifiers
		}
		for n := range names {
			idents[n] = true
		}
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Str("root", root).Msg("node identifier walk stopped early")
	}
	return idents
}

var nodeTestDirs = map[string]bool{"test": true, "tests": true, "__tests__": true, "spec": true}

// isNodeRuntimeSource reports a source file that ships code, not types or tests.
func isNodeRuntimeSource(name string) bool {
	if strings.HasSuffix(name, ".d.ts") || strings.HasSuffix(name, ".d.mts") || strings.HasSuffix(name, ".d.cts") ||
		strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
		return false
	}
	return isNodeSourceFile(name) || strings.HasSuffix(name, ".ts")
}

type nodePackage struct {
	Name    string          `json:"name"`
	Main    string          `json:"main"`
	Exports json.RawMessage `json:"exports"`
}

func readNodePackage(root string) (nodePackage, bool) {
	var pkg nodePackage
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil || json.Unmarshal(data, &pkg) != nil || pkg.Name == "" {
		return pkg, false
	}
	return pkg, true
}

// nodeModuleFiles maps each specifier the package publishes to the source
// files that back it, relative to root, in the order an import resolves them:
// an ESM wrapper first, then the build it re-exports. Subpaths are also written
// without a ".js" suffix, because rules name the bare form.
func nodeModuleFiles(root string, pkg nodePackage) map[string][]string {
	files := nodeSpecifierFiles{name: pkg.Name, out: make(map[string][]string)}
	if len(pkg.Exports) > 0 {
		subpaths := nodeExportSubpaths(pkg.Exports)
		for _, sub := range subpaths {
			for _, target := range sub.targets {
				for _, m := range expandNodeExportTarget(root, sub.subpath, target) {
					if !nodeSubpathExcluded(m.subpath, subpaths) {
						files.add(m.subpath, m.rel)
					}
				}
			}
		}
		return files.out
	}
	if main := nodeMainFile(root, pkg.Main); main != "" {
		files.add(".", main)
	}
	if err := filepath.WalkDir(root, files.walk(root)); err != nil {
		log.Debug().Err(err).Str("root", root).Msg("node export index walk stopped early")
	}
	return files.out
}

// nodeSubpathExcluded reports whether a subpath matches an exports entry mapped
// to null ("./internal/*": null), which Node refuses to import.
func nodeSubpathExcluded(subpath string, subpaths []nodeSubpath) bool {
	for _, sub := range subpaths {
		if len(sub.targets) > 0 {
			continue
		}
		prefix, suffix, pattern := strings.Cut(sub.subpath, "*")
		if subpath == sub.subpath || (pattern && strings.HasPrefix(subpath, prefix) && strings.HasSuffix(subpath, suffix)) {
			return true
		}
	}
	return false
}

// nodeSpecifierFiles collects the files registered for each specifier.
type nodeSpecifierFiles struct {
	name string
	out  map[string][]string
}

func (f nodeSpecifierFiles) add(subpath, rel string) {
	rel = strings.TrimPrefix(path.Clean(rel), "./")
	if !isNodeSourceFile(rel) {
		return
	}
	specs := []string{f.name}
	if subpath != "." {
		spec := f.name + "/" + strings.TrimPrefix(subpath, "./")
		specs = []string{spec, strings.TrimSuffix(spec, ".js")}
	}
	for _, s := range slices.Compact(specs) {
		if !slices.Contains(f.out[s], rel) {
			f.out[s] = append(f.out[s], rel)
		}
	}
}

// walk registers every module of a package without an exports map under the
// path Node resolves it by.
func (f nodeSpecifierFiles) walk(root string) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if p != root && (d.Name() == nodeModulesDir || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr // a path outside root is not part of the package
		}
		rel = filepath.ToSlash(rel)
		if isNodeSourceFile(rel) {
			f.add("./"+strings.TrimSuffix(rel, path.Ext(rel)), rel)
		}
		return nil
	}
}

// nodeMainFile resolves the package root the way Node does without an exports
// map: main as written, with an extension or as a directory index, else index.js.
func nodeMainFile(root, main string) string {
	main = strings.TrimPrefix(path.Clean(main), "./")
	var candidates []string
	if main != "" && main != "." {
		candidates = append(candidates, main, main+".js", main+".cjs", main+".mjs", main+"/index.js")
	}
	candidates = append(candidates, "index.js")
	for _, c := range candidates {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(c))); err == nil && !info.IsDir() && isNodeSourceFile(c) {
			return c
		}
	}
	return ""
}

func isNodeSourceFile(rel string) bool {
	for _, suffix := range []string{".d.ts", ".d.mts", ".d.cts"} {
		if strings.HasSuffix(rel, suffix) {
			return false
		}
	}
	switch path.Ext(rel) {
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return true
	}
	return false
}

type nodeSubpath struct {
	subpath string
	targets []string // ranked by nodeConditionOrder
}

// nodeExportSubpaths flattens a package.json exports field into its subpaths
// and their file targets.
func nodeExportSubpaths(raw json.RawMessage) []nodeSubpath {
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return []nodeSubpath{{subpath: ".", targets: []string{asString}}}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	isSubpathMap := false
	for k := range obj {
		isSubpathMap = isSubpathMap || strings.HasPrefix(k, ".")
	}
	if !isSubpathMap {
		return []nodeSubpath{{subpath: ".", targets: nodeExportTargets(raw)}}
	}
	var out []nodeSubpath
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		if strings.HasPrefix(k, ".") {
			out = append(out, nodeSubpath{subpath: k, targets: nodeExportTargets(obj[k])})
		}
	}
	return out
}

// nodeExportTargets returns the file targets of one exports value, ranked so
// the first is the build that gets indexed. Type declarations are skipped.
func nodeExportTargets(raw json.RawMessage) []string {
	if strings.TrimSpace(string(raw)) == "null" {
		return nil // an excluded subpath
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var out []string
		for _, v := range arr {
			out = append(out, nodeExportTargets(v)...)
		}
		return out
	}
	var conds map[string]json.RawMessage
	if json.Unmarshal(raw, &conds) != nil {
		return nil
	}
	rank := func(k string) int {
		if i := slices.Index(nodeConditionOrder, k); i >= 0 {
			return i
		}
		return len(nodeConditionOrder)
	}
	keys := make([]string, 0, len(conds))
	for k := range conds {
		if k != "types" {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b string) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a, b)
	})
	var out []string
	for _, k := range keys {
		out = append(out, nodeExportTargets(conds[k])...)
	}
	return out
}

type nodeSubpathFile struct{ subpath, rel string }

// expandNodeExportTarget resolves one target to files. A "*" pattern
// ("./*": "./esm/*.js") expands to every file it matches, in any subdirectory.
func expandNodeExportTarget(root, subpath, target string) []nodeSubpathFile {
	if !strings.Contains(target, "*") {
		return []nodeSubpathFile{{subpath, target}}
	}
	prefix, suffix, _ := strings.Cut(strings.TrimPrefix(target, "./"), "*")
	var out []nodeSubpathFile
	walkRoot := filepath.Join(root, filepath.FromSlash(path.Dir(prefix+"x")))
	err := filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip unreadable entries and directories
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr // a path outside root is not part of the package
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, prefix) && strings.HasSuffix(rel, suffix) && len(rel) >= len(prefix)+len(suffix) {
			star := strings.TrimSuffix(strings.TrimPrefix(rel, prefix), suffix)
			out = append(out, nodeSubpathFile{strings.Replace(subpath, "*", star, 1), rel})
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return out
}
