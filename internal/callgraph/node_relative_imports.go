// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// nodeSourceExtensions are the file extensions a Node resolver tries, in order,
// for a specifier written without one.
var nodeSourceExtensions = []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}

// resolveNodeRelativeImports rewrites every relative module specifier in
// bindings to the module path nodeModulePath gives the file it names, so a
// call through `import { f } from '../lib/a'` targets the same identity that
// lib/a.ts declares f under. A specifier kept verbatim names no declared
// module, and every cross-file call in a first-party tree was left without a
// callee: reachability then stopped at the file boundary.
func resolveNodeRelativeImports(bindings nodeBindings, filePath, packagePath string) {
	for name, binding := range bindings {
		if resolved, ok := resolveNodeRelativeModule(filePath, packagePath, binding.module); ok {
			binding.module = resolved
			bindings[name] = binding
		}
	}
}

// resolveNodeRelativeModule maps a relative specifier written in filePath, a
// file of the package at packagePath, to a module path. It reports false for a
// bare specifier (a package such as 'crypto') and for one that climbs above the
// scanned tree, which keep their written form.
func resolveNodeRelativeModule(filePath, packagePath, specifier string) (string, bool) {
	if specifier != "." && specifier != ".." && !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
		return "", false
	}
	modulePath := path.Clean(path.Join(packagePath, specifier))
	if modulePath == ".." || strings.HasPrefix(modulePath, "../") {
		return "", false
	}
	if modulePath == "." {
		modulePath = ""
	}
	target := filepath.Join(filepath.Dir(filePath), filepath.FromSlash(specifier))
	if resolved, ok := resolveWrittenNodeExtension(modulePath, target); ok {
		return resolved, true
	}
	// A file wins over a directory of the same name, as in Node's resolver;
	// a directory resolves to its index module.
	if !nodeSourceFileExists(target) && nodeSourceFileExists(filepath.Join(target, "index")) {
		if modulePath == "" {
			return "index", true
		}
		return modulePath + "/index", true
	}
	return modulePath, true
}

// resolveWrittenNodeExtension resolves a specifier that carries a source
// extension. One naming a file as it stands is that file: './run.mjs' beside
// run.ts is run.mjs, which nodeModulePath keys apart from run.ts. Otherwise
// './a.js' in TypeScript names a.ts, and the written extension is dropped the
// way nodeModulePath drops it from the declaring file.
//
// modulePath is the specifier joined onto the importer's package path, so the
// package of the file it names is modulePath's own directory, not the
// importer's.
func resolveWrittenNodeExtension(modulePath, target string) (string, bool) {
	ext := path.Ext(modulePath)
	if ext == "" || !isNodeSourceExtension(ext) {
		return "", false
	}
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		dir := path.Dir(modulePath)
		if dir == "." {
			dir = ""
		}
		return nodeModulePath(dir, target), true
	}
	return strings.TrimSuffix(modulePath, ext), true
}

func isNodeSourceExtension(ext string) bool {
	for _, candidate := range nodeSourceExtensions {
		if strings.EqualFold(ext, candidate) {
			return true
		}
	}
	return false
}

// nodeSourceFileExists reports whether withoutExt names a source file under any
// of the extensions a Node resolver tries.
func nodeSourceFileExists(withoutExt string) bool {
	for _, ext := range nodeSourceExtensions {
		if info, err := os.Stat(withoutExt + ext); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
