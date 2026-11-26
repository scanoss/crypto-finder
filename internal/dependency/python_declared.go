// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"cmp"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// pyDeclared is a runtime requirement a project manifest declares.
type pyDeclared struct {
	req      pyRequirement
	manifest string
}

// version returns the version the requirement pins, if it pins one.
func (d pyDeclared) version() (string, bool) {
	if d.req.URL != "" {
		return "", false
	}
	return pinnedPyVersion(d.req.Specifier)
}

// declaredPyRequirements reads the runtime requirements of dir's
// pyproject.toml ([project] dependencies and every optional-dependencies
// extra, recorded as extra == "<name>"; [tool.poetry.dependencies]) and
// Pipfile ([packages]). Development groups are left out, as the Java
// closure leaves out test scope. A manifest that does not parse declares
// nothing.
func declaredPyRequirements(dir string) []pyDeclared {
	var out []pyDeclared
	if data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil {
		out = append(out, pyprojectRequirements(data)...)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "Pipfile")); err == nil {
		var pipfile struct {
			Packages map[string]any `toml:"packages"`
		}
		if toml.Unmarshal(data, &pipfile) == nil {
			out = append(out, tableRequirements(pipfile.Packages, "Pipfile", pipfileSpecifier)...)
		}
	}
	return out
}

func pyprojectRequirements(data []byte) []pyDeclared {
	var py struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &py) != nil {
		return nil
	}
	var out []pyDeclared
	add := func(raw, extra string) {
		if req, ok := parsePyRequirement(raw); ok {
			req.Marker = pyExtraMarker(extra, req.Marker)
			out = append(out, pyDeclared{req: req, manifest: "pyproject.toml"})
		}
	}
	for _, raw := range py.Project.Dependencies {
		add(raw, "")
	}
	for _, extra := range slices.Sorted(maps.Keys(py.Project.OptionalDependencies)) {
		for _, raw := range py.Project.OptionalDependencies[extra] {
			add(raw, purl.PyPIName(extra))
		}
	}
	deps := py.Tool.Poetry.Dependencies
	delete(deps, "python")
	return append(out, tableRequirements(deps, "pyproject.toml", poetrySpecifier)...)
}

// tableRequirements reads a Poetry or Pipfile dependency table: name to a
// version string, a table (version, markers, extras; path, git or url for a
// direct reference) or, for Poetry, an array of tables for different
// markers.
func tableRequirements(deps map[string]any, manifest string, specifier func(string) string) []pyDeclared {
	var out []pyDeclared
	for _, name := range slices.Sorted(maps.Keys(deps)) {
		for _, t := range poetryDependencyTables(deps[name]) {
			req := pyRequirement{Name: purl.PyPIName(name), Extras: poetryExtras(t["extras"])}
			if s, ok := deps[name].(string); ok {
				req.Specifier = specifier(s)
			}
			if s, ok := t["version"].(string); ok {
				req.Specifier = specifier(s)
			}
			req.Marker = utils.AsOr[string](t["markers"])
			for _, ref := range []string{"path", "git", "url", "file"} {
				if s, ok := t[ref].(string); ok {
					req.URL = s
				}
			}
			out = append(out, pyDeclared{req: req, manifest: manifest})
		}
	}
	return out
}

// poetrySpecifier writes a Poetry constraint as a PEP 440 specifier as far
// as pinning goes: a bare version is exact in Poetry, "*" is none, and
// anything else (^, ~, ranges) stays as written.
func poetrySpecifier(s string) string {
	s = strings.Join(strings.Fields(s), "")
	switch {
	case s == "*" || s == "":
		return ""
	case strings.IndexAny(s[:1], "0123456789") == 0 && !strings.ContainsAny(s, ",*|"):
		return "==" + s
	}
	return s
}

// pipfileSpecifier is a Pipfile version: "*" or a PEP 440 specifier.
func pipfileSpecifier(s string) string {
	s = strings.Join(strings.Fields(s), "")
	if s == "*" {
		return ""
	}
	return s
}

// readDeclaredPy is the last resort: the project only declares its
// requirements. A requirement pinned with == is a dependency at that version
// (without its own requirements, which the server's component data knows);
// any other is unpinned and has no closure. It reports false when dir
// declares nothing.
func readDeclaredPy(dir string) (*pyGraph, bool) {
	declared := append(declaredPyRequirements(dir), declaredRequirementsFiles(dir)...)
	if len(declared) == 0 {
		return nil, false
	}
	g := newPyGraph("declared")
	g.directKnown = true
	for _, d := range declared {
		version, pinned := d.version()
		if !pinned {
			g.unpinned = append(g.unpinned, UnpinnedDependency{
				Module: d.req.Name, Specifier: cmp.Or(d.req.Specifier, d.req.URL), Marker: d.req.Marker, Manifest: d.manifest,
			})
			continue
		}
		n := g.add(d.req.Name, version)
		n.extras = addSorted(n.extras, d.req.Extras...)
		g.declare(n.ref.Key(), d.req.Marker)
	}
	return g, true
}
