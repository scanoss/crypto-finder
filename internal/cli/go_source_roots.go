// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"path/filepath"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/dependency"
)

// goSourceRoots are the Go sources that type a Go target's calls: the
// standard library of the installed toolchain and each module the target's
// go.mod files require, after replace, that the module cache or a local
// replacement holds. A call into a missing module is exported name_only.
func goSourceRoots(targetDir string) []callgraph.GoSourceRoot {
	var roots []callgraph.GoSourceRoot
	if goroot := dependency.GoEnv("GOROOT"); goroot != "" {
		roots = append(roots, callgraph.GoSourceRoot{Dir: filepath.Join(goroot, "src")})
	}
	for _, m := range dependency.GoSourceModules(targetDir, nil) {
		roots = append(roots, callgraph.GoSourceRoot{Dir: m.Dir, Module: m.Module})
	}
	return roots
}
