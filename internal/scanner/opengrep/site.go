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

package opengrep

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// site is where the engine scans one root: in the root itself, with
// targets relative to it, so the paths the engine sees are the same
// wherever the root lies. OpenGrep's results depend on those path strings:
// opengrep 1.30.2 orders a class's constructors by a hash of a function key
// holding the file's path, and the order decides whether taint a
// constructor leaves in a field reaches the class's methods. Scanning a
// root through its absolute path made findings depend on the home
// directory, the checkout location or the job's workspace path.
//
// Every path the engine reports is named again as the caller names the
// root (named), so reports read as before.
type site struct {
	// root is the scanned root as the caller names it.
	root scanner.Root
	// dir is the root's physical directory, the engine's working
	// directory. Empty runs the engine in crypto-finder's working
	// directory over the root as named, as before: when extra scanner
	// arguments may name paths relative to it, or the root is no
	// directory the engine could run in.
	dir string
	// configs are the rule paths the CLI receives: absolute, since its
	// working directory is not crypto-finder's.
	configs []string
	// excludes are the scan's exclude patterns as the engine in dir
	// matches them (rootExcludes).
	excludes []string
	// rewriteID names a rule id the CLI reports in dir as the CLI names it
	// in crypto-finder's working directory, where a config file's
	// directory below it prefixes the id relative to it. Nil when no id
	// changes.
	rewriteID func(string) string
}

// siteFor plans the scan of root with rulePaths.
func (s *Scanner) siteFor(root scanner.Root, rulePaths []string) site {
	legacy := site{root: root, configs: rulePaths, excludes: s.skipPatterns}
	if len(s.extraArgs) > 0 || root.Dir == "" {
		return legacy
	}
	dir, err := physicalDir(fsPath(s.workDir, root.Dir))
	if err == nil {
		var info os.FileInfo
		if info, err = os.Stat(dir); err == nil && !info.IsDir() {
			err = fmt.Errorf("opengrep: target %s is not a directory", root.Dir)
		}
	}
	var cwd string
	if err == nil {
		cwd, err = physicalDir(s.workDir)
	}
	configs := make([]string, len(rulePaths))
	for i, rulePath := range rulePaths {
		if err != nil {
			break
		}
		configs[i], err = filepath.Abs(fsPath(s.workDir, rulePath))
	}
	var rewrite func(string) string
	if err == nil {
		rewrite, err = cliIDRewrite(rulePaths, configs, cwd, dir)
	}
	var excludes []string
	if err == nil {
		var named string
		if named, err = filepath.Abs(fsPath(s.workDir, root.Dir)); err == nil {
			excludes, err = rootExcludes(s.skipPatterns, pyPath(filepath.ToSlash(named)), filepath.ToSlash(dir))
		}
	}
	if err != nil {
		log.Debug().Err(err).Str("target", root.Dir).Msg("OpenGrep scans the target by its path as given")
		return legacy
	}
	return site{root: root, dir: dir, configs: configs, excludes: excludes, rewriteID: rewrite}
}

// rootExcludes returns the exclude patterns for an engine running in the
// root, which matches them against paths relative to it. A pattern naming
// an absolute path below the root, as the npm dependency scan anchors the
// dependency's own node_modules, names it relative to the root; it then
// also matches below other directories of that name in the root. Other
// patterns are kept: matched against the paths the engine reports, now
// relative to the root, they no longer match the root's ancestors, as they
// did when a directory named like one of them (build, test, vendor...)
// held the root. A pattern naming an absolute path elsewhere fails: it
// would match nothing, where it excluded the whole root or nothing before.
func rootExcludes(patterns []string, named, dir string) ([]string, error) {
	out := make([]string, len(patterns))
	for i, pattern := range patterns {
		out[i] = pattern
		if !strings.HasPrefix(pattern, "/") {
			continue
		}
		translated := false
		for _, base := range []string{named, dir} {
			if rest, ok := strings.CutPrefix(pattern, strings.TrimSuffix(base, "/")+"/"); ok && strings.Trim(rest, "/") != "" {
				out[i], translated = rest, true
				break
			}
		}
		if !translated {
			return nil, fmt.Errorf("opengrep: exclude pattern %s lies outside the target", pattern)
		}
	}
	return out, nil
}

// workDir is the engine process's working directory.
func (st *site) workDir(s *Scanner) string {
	if st.dir != "" {
		return st.dir
	}
	return s.workDir
}

// targets are the root's targets as the engine in workDir names them.
func (st *site) targets() []scanner.Root {
	if st.dir == "" {
		return []scanner.Root{st.root}
	}
	return []scanner.Root{{Dir: ".", Scope: st.root.Scope}}
}

// named is path, as the engine reported it, named as the caller names
// the root: the path a scan of the root by that name reports.
func (st *site) named(path string) string {
	if st.dir == "" || path == "" || filepath.IsAbs(path) {
		return path
	}
	return pyJoin(st.root.Dir, path)
}

// relative is the inverse of named: path, named as the caller names the
// root, as the engine in dir names it.
func (st *site) relative(path string) string {
	if st.dir == "" {
		return path
	}
	base := pyPath(st.root.Dir)
	if base == "." {
		return path
	}
	if holds(base, path) {
		if rel := strings.TrimLeft(path[len(base):], "/"); rel != "" {
			return rel
		}
		return "."
	}
	return path
}

// nameOutput names the paths of output, as the engine reported them, as the
// caller names the root.
func (st *site) nameOutput(output *entities.SemgrepOutput) {
	if st.dir == "" || output == nil {
		return
	}
	for i := range output.Results {
		output.Results[i].Path = st.named(output.Results[i].Path)
	}
	for i := range output.Errors {
		output.Errors[i].Path = st.named(output.Errors[i].Path)
		for j := range output.Errors[i].Spans {
			output.Errors[i].Spans[j].File = st.named(output.Errors[i].Spans[j].File)
		}
	}
}

// cliIDRewrite maps the rule ids the CLI reports running in dir with
// configs to the ids it reports running in cwd with rulePaths. The CLI
// prefixes each rule id with its config file's directory, relative to its
// working directory when the file lies below it (configPrefix), so only
// config files below dir or cwd change their prefix. Nil when none does.
func cliIDRewrite(rulePaths, configs []string, cwd, dir string) (func(string) string, error) {
	prefixes, err := ruleIDPrefixes(rulePaths, configs, cwd, dir)
	if err != nil || prefixes == nil {
		return nil, err
	}
	// The longest prefix wins: the ids of a config file below another's
	// directory start with both prefixes.
	order := make([]string, 0, len(prefixes))
	for from := range prefixes {
		order = append(order, from)
	}
	sort.Slice(order, func(i, j int) bool {
		if len(order[i]) != len(order[j]) {
			return len(order[i]) > len(order[j])
		}
		return order[i] < order[j]
	})
	return func(id string) string {
		for _, from := range order {
			if strings.HasPrefix(id, from) {
				return prefixes[from] + id[len(from):]
			}
		}
		return id
	}, nil
}

// ruleIDPrefixes maps each config file's rule id prefix in dir to its
// prefix in cwd, or returns nil when every prefix is the same in both.
func ruleIDPrefixes(rulePaths, configs []string, cwd, dir string) (map[string]string, error) {
	prefixes := make(map[string]string)
	differs := false
	for i, rulePath := range rulePaths {
		given, err := configFiles(rulePath)
		if err != nil {
			return nil, err
		}
		passed, err := configFiles(configs[i])
		if err != nil {
			return nil, err
		}
		if len(given) != len(passed) {
			return nil, fmt.Errorf("opengrep: rule path %s lists %d config files as %s and %d as given", rulePath, len(passed), configs[i], len(given))
		}
		for j := range given {
			from, to := configPrefix(passed[j], dir), configPrefix(given[j], cwd)
			if seen, ok := prefixes[from]; ok && seen != to {
				return nil, fmt.Errorf("opengrep: rule id prefix %q stands for both %q and %q", from, seen, to)
			}
			prefixes[from] = to
			differs = differs || from != to
		}
	}
	if !differs {
		return nil, nil
	}
	return prefixes, nil
}
