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
	"regexp"
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

// nodeLayoutDirs are build-output directories a package without an exports map
// publishes its modules under; the module's path drops them.
var nodeLayoutDirs = map[string]bool{"esm": true, "lib": true, "dist": true, "cjs": true, "build": true}

// addNodeExportDeclarations indexes every export of the mined npm package under
// the specifiers a consumer imports it by, so a rule api written
// "@noble/curves/secp256k1.secp256k1.sign" meets the `secp256k1` export even
// though that export is a value built by a factory, not a function. A key the
// graph already declares keeps its function definition. It returns the
// identifiers the package's code declares or uses, for nodeExportDecls.
func addNodeExportDeclarations(root string, declsByFQN map[string][]*callgraph.FunctionDecl) map[string]bool {
	pkg, ok := readNodePackage(root)
	if !ok {
		return nil
	}
	for spec, rel := range nodeModuleFiles(root, pkg) {
		indexNodeModuleExports(spec, filepath.Join(root, filepath.FromSlash(rel)), declsByFQN, map[string]bool{}, 0)
	}
	return nodePackageIdentifiers(root)
}

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
	for name, line := range exports.Lines {
		key := spec + "." + name
		if len(declsByFQN[key]) > 0 {
			continue
		}
		declsByFQN[key] = []*callgraph.FunctionDecl{{
			ID:       callgraph.FunctionID{Package: spec, Name: name},
			FilePath: file, StartLine: line, EndLine: line,
		}}
	}
	for _, from := range exports.StarFrom {
		if target := resolveNodeRelative(file, from); target != "" {
			indexNodeModuleExports(spec, target, declsByFQN, seen, depth+1)
		}
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
// ("...secp256k1.secp256k1.sign" -> "...secp256k1.secp256k1"). A rule covers
// every release, so a member must appear in this release's code: 0.9 has the
// `ed25519` export but no `ed25519.keygen`.
func nodeExportDecls(api string, declsByFQN map[string][]*callgraph.FunctionDecl, idents map[string]bool) []*callgraph.FunctionDecl {
	for key := api; ; {
		if decls := declsByFQN[key]; len(decls) > 0 {
			if key != api && !allNodeMembersPresent(api[len(key)+1:], idents) {
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

func allNodeMembersPresent(members string, idents map[string]bool) bool {
	for _, m := range strings.Split(members, ".") {
		if !idents[m] {
			return false
		}
	}
	return true
}

var nodeIdentifierRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// nodePackageIdentifiers collects every identifier in the package's own
// JavaScript, TypeScript and declaration files.
func nodePackageIdentifiers(root string) map[string]bool {
	idents := make(map[string]bool)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if p != root && d.Name() == nodeModulesDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !isNodeSourceFile(d.Name()) && !strings.HasSuffix(d.Name(), ".ts") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil //nolint:nilerr // an unreadable file contributes no identifiers
		}
		for _, id := range nodeIdentifierRe.FindAll(data, -1) {
			idents[string(id)] = true
		}
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Str("root", root).Msg("node identifier walk stopped early")
	}
	return idents
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

// nodeModuleFiles maps each specifier the package publishes to the one source
// file that backs it, relative to root. Specifiers are written both with and
// without a ".js" suffix, because rules name the bare form.
func nodeModuleFiles(root string, pkg nodePackage) map[string]string {
	files := nodeSpecifierFiles{name: pkg.Name, out: make(map[string]string)}
	if len(pkg.Exports) > 0 {
		for _, sub := range nodeExportSubpaths(pkg.Exports) {
			for _, target := range sub.targets {
				for _, m := range expandNodeExportTarget(root, sub.subpath, target) {
					files.add(m.subpath, m.rel)
				}
			}
		}
		return files.out
	}
	if err := filepath.WalkDir(root, files.walk(root, pkg.Main)); err != nil {
		log.Debug().Err(err).Str("root", root).Msg("node export index walk stopped early")
	}
	return files.out
}

// nodeSpecifierFiles collects the first file registered for each specifier.
type nodeSpecifierFiles struct {
	name string
	out  map[string]string
}

func (f nodeSpecifierFiles) add(subpath, rel string) {
	rel = strings.TrimPrefix(path.Clean(rel), "./")
	if !isNodeSourceFile(rel) {
		return
	}
	spec := f.name
	if subpath != "." {
		spec += "/" + strings.TrimPrefix(subpath, "./")
	}
	for _, s := range []string{spec, strings.TrimSuffix(spec, ".js")} {
		if _, taken := f.out[s]; !taken {
			f.out[s] = rel
		}
	}
}

// walk registers every module of a package without an exports map under its
// path, and its main file and index under the package name.
func (f nodeSpecifierFiles) walk(root, main string) fs.WalkDirFunc {
	main = strings.TrimPrefix(path.Clean(main), "./")
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
		if !isNodeSourceFile(rel) {
			return nil
		}
		mod := strings.TrimSuffix(rel, path.Ext(rel))
		if first, rest, ok := strings.Cut(mod, "/"); ok && nodeLayoutDirs[first] {
			mod = rest
		}
		if mod == "index" || isNodeMainFile(rel, main) {
			f.add(".", rel)
		}
		f.add("./"+mod, rel)
		return nil
	}
}

// isNodeMainFile reports whether rel is the file a package.json main names.
// Node resolves main with or without its extension, and as a directory index:
// bcrypt's main is "./bcrypt" for bcrypt.js.
func isNodeMainFile(rel, main string) bool {
	if main == "" || main == "." {
		return false
	}
	noExt := strings.TrimSuffix(rel, path.Ext(rel))
	return rel == main || noExt == main || noExt == main+"/index"
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
// ("./*": "./esm/*.js") expands to every file it matches.
func expandNodeExportTarget(root, subpath, target string) []nodeSubpathFile {
	if !strings.Contains(target, "*") {
		return []nodeSubpathFile{{subpath, target}}
	}
	matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(target, "./"))))
	if err != nil {
		return nil
	}
	prefix, suffix, _ := strings.Cut(strings.TrimPrefix(target, "./"), "*")
	var out []nodeSubpathFile
	for _, m := range matches {
		rel, err := filepath.Rel(root, m)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		star := strings.TrimSuffix(strings.TrimPrefix(rel, prefix), suffix)
		out = append(out, nodeSubpathFile{strings.Replace(subpath, "*", star, 1), rel})
	}
	return out
}
