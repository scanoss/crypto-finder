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

package dependency

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// RubyResolver resolves a Ruby project's dependencies from its Gemfile.lock,
// the file bundler writes with the exact version of every gem the project
// resolved to. A Gemfile alone states ranges, not versions, so it is not read:
// mining the wrong version of a gem is worse than mining none.
type RubyResolver struct {
	gemHome string
}

// NewRubyResolver returns a resolver that reads a project's Gemfile.lock and
// finds each gem's source under the local gem installation.
func NewRubyResolver() *RubyResolver {
	return &RubyResolver{gemHome: os.Getenv("GEM_HOME")}
}

// The Ruby ecosystem, as the call graph and the resolvers name it.
const ecosystemRuby = "ruby"

// Ecosystem implements Resolver.
func (r *RubyResolver) Ecosystem() string { return ecosystemRuby }

// CanResolve implements Resolver: a project with a Gemfile.lock.
func (r *RubyResolver) CanResolve(targetDir string) bool {
	_, err := os.Stat(filepath.Join(targetDir, rubyLockFile))
	return err == nil
}

// rubyLockFile is the file bundler writes with the resolved versions.
const rubyLockFile = "Gemfile.lock"

// rubySpecLine is one resolved gem in the GEM/specs section: two levels of
// indentation, a name, and a version in parentheses. A gem's own dependencies
// are indented one level further and carry a RANGE rather than a version,
// which is why only this depth is read.
var rubySpecLine = regexp.MustCompile(`^ {4}([A-Za-z0-9_.\-]+) \(([^()]+)\)$`)

// rubyGemVersion drops the platform bundler appends to a native gem's
// version (`1.15.4-x86_64-linux`). A lock writes `Gem::Version#to_s`, which
// spells a prerelease with dots, so a hyphen here only ever starts the
// platform -- and the purl the server resolves carries the version alone.
func rubyGemVersion(v string) string {
	version, _, _ := strings.Cut(v, "-")
	return version
}

// Resolve implements Resolver.
func (r *RubyResolver) Resolve(_ context.Context, targetDir string) (*ResolveResult, error) {
	gems, err := parseGemfileLock(filepath.Join(targetDir, rubyLockFile))
	if err != nil {
		return nil, err
	}
	result := &ResolveResult{RootModule: filepath.Base(targetDir)}
	for _, g := range gems {
		dep := Dependency{Module: g.name, Version: g.version}
		if dir := r.gemDir(g.name, g.version); dir != "" {
			dep.Dir = dir
		}
		result.Dependencies = append(result.Dependencies, dep)
	}
	return result, nil
}

// gemDir is where a gem's source sits in the local installation, or "" when
// it is not installed: a dependency with no directory is still reported, so
// the scan can say which gems it could not read rather than omit them.
func (r *RubyResolver) gemDir(name, version string) string {
	if r.gemHome == "" {
		return ""
	}
	dir := filepath.Join(r.gemHome, "gems", name+"-"+version)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

// gemSpec is one resolved gem of a Gemfile.lock.
type gemSpec struct{ name, version string }

// parseGemfileLock reads the resolved gems of a Gemfile.lock.
//
// The file is sectioned: GEM holds the gems from a remote, and under its
// `specs:` each gem sits at four spaces with its exact version. PATH and GIT
// sections name gems resolved from elsewhere and follow the same shape, so
// they are read too. DEPENDENCIES lists what the Gemfile asked for, without
// versions, and is skipped.
func parseGemfileLock(path string) ([]gemSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { utils.Discard(f.Close()) }()

	var gems []gemSpec
	seen := map[string]bool{}
	inSpecs := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		switch {
		case line == "":
			continue
		case !strings.HasPrefix(line, " "):
			// A section header (GEM, PATH, GIT, PLATFORMS, DEPENDENCIES...).
			inSpecs = false
			continue
		case strings.TrimSpace(line) == "specs:":
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		m := rubySpecLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1] + "@" + rubyGemVersion(m[2])
		if seen[key] {
			continue
		}
		seen[key] = true
		gems = append(gems, gemSpec{name: m[1], version: rubyGemVersion(m[2])})
	}
	return gems, scanner.Err()
}
