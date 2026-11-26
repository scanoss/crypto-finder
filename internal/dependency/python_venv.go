// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/utils"
	"github.com/scanoss/crypto-finder/pkg/appreach"
)

// An installed environment is read from its files, never by running pip or
// Python: each *.dist-info's METADATA (Name, Version, Requires-Dist) and
// RECORD (the files it installed).

// pyEnvironmentDirs lists the virtual environments to look in, in order: the
// project's own .venv and venv, then the active one (VIRTUAL_ENV). The
// project's come first so an environment activated for another project does
// not stand in for the target's.
func pyEnvironmentDirs(dir string) []string {
	var out []string
	for _, name := range []string{".venv", "venv"} {
		if isDir(filepath.Join(dir, name)) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	if env := os.Getenv("VIRTUAL_ENV"); env != "" && isDir(env) {
		out = append(out, env)
	}
	return out
}

// sitePackages returns the site-packages directory of the environment at
// venv: lib/python3.X/site-packages (or pypy) on POSIX, Lib/site-packages
// on Windows. With several Python versions installed, the lexically last.
func sitePackages(venv string) string {
	var found []string
	for _, pattern := range []string{"lib/python*/site-packages", "lib/pypy*/site-packages", "Lib/site-packages"} {
		matches := utils.Lenient(filepath.Glob(filepath.Join(venv, filepath.FromSlash(pattern))))
		for _, m := range matches {
			if isDir(m) {
				found = append(found, m)
			}
		}
	}
	if len(found) == 0 {
		return ""
	}
	slices.Sort(found)
	return found[len(found)-1]
}

// pyDistribution is one installed distribution.
type pyDistribution struct {
	name, version string
	requires      []pyRequirement
	files         []string
	// editable is the project itself installed in development mode
	// (direct_url.json dir_info.editable): its requirements are the
	// application's.
	editable bool
}

// readPyEnvironment reads the first environment of pyEnvironmentDirs that
// has a site-packages directory. Each distribution's Requires-Dist becomes
// an edge to the installed distribution of that name, whatever its marker
// (union; the marker, extra == "x" included, is kept). The application's
// requirements are an editable install's Requires-Dist and what the
// project's manifests declare; with any, the closure is what they reach,
// else every installed distribution but pip. It reports false when there is
// no environment.
func readPyEnvironment(dir string) (*pyGraph, bool) {
	site := pyEnvironmentSite(dir)
	if site == "" {
		return nil, false
	}
	dists := readDistributions(site)
	g := newPyGraph(site)
	keys := make([]string, len(dists))
	for i, d := range dists {
		if d.editable {
			continue
		}
		n := g.add(purl.PyPIName(d.name), d.version)
		n.dir, n.files = site, d.files
		keys[i] = n.ref.Key()
	}
	var declared []pyRequirement
	for i, d := range dists {
		if d.editable {
			declared = append(declared, d.requires...)
			continue
		}
		for _, req := range d.requires {
			g.requireName(keys[i], req, req.Marker)
		}
	}
	for _, d := range append(declaredPyRequirements(dir), declaredRequirementsFiles(dir)...) {
		declared = append(declared, d.req)
	}
	for _, req := range declared {
		g.requireName("", req, req.Marker)
	}
	if g.directKnown {
		g.trimToDeclared()
	} else {
		for key, n := range g.nodes {
			if n.ref.Module == "pip" {
				delete(g.nodes, key)
			}
		}
	}
	return g, true
}

// pyEnvironmentSite is the site-packages directory of the first environment
// of pyEnvironmentDirs that has one, or "".
func pyEnvironmentSite(dir string) string {
	for _, venv := range pyEnvironmentDirs(dir) {
		if site := sitePackages(venv); site != "" {
			return site
		}
	}
	return ""
}

// completeFromEnvironment adds to g, a closure read from pinned requirements,
// what its distributions require in the installed environment of dir,
// transitively, and returns how many distributions it added: requirements
// that pin only the project's direct dependencies leave the rest to the
// environment pip installed from them. A pin keeps its version. A pin the
// environment holds at another version gets no edges from it, as the
// installed requirements are another release's. A requirement installed
// nowhere is left out: its marker or extra does not hold there. site is the
// environment's site-packages directory (pyEnvironmentSite), "" for none.
func completeFromEnvironment(g *pyGraph, site string) int {
	if site == "" {
		return 0
	}
	installed := map[string]pyDistribution{}
	for _, d := range readDistributions(site) {
		if !d.editable {
			installed[purl.PyPIName(d.name)] = d
		}
	}
	queue := make([]string, 0, len(g.nodes))
	for key := range g.nodes {
		queue = append(queue, key)
	}
	slices.Sort(queue)
	added := 0
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		n := g.nodes[key]
		d, ok := installed[n.ref.Module]
		if !ok {
			continue
		}
		if !appreach.PyPIVersionsEqual(d.version, n.ref.Version) {
			log.Warn().Str("dependency", n.ref.Module).Str("pinned", n.ref.Version).Str("installed", d.version).
				Msg("The installed environment holds another version of a pinned requirement; what it requires is not added to the closure")
			continue
		}
		n.dir, n.files = site, d.files
		for _, req := range d.requires {
			if child, ok := installed[req.Name]; ok && len(g.named(req.Name)) == 0 {
				queue = append(queue, g.add(req.Name, child.version).ref.Key())
				added++
			}
			g.requireName(key, req, req.Marker)
		}
	}
	return added
}

// readDistributions reads every *.dist-info directory of site, sorted by
// name.
func readDistributions(site string) []pyDistribution {
	infos := utils.Lenient(filepath.Glob(filepath.Join(site, "*.dist-info")))
	slices.Sort(infos)
	var out []pyDistribution
	for _, info := range infos {
		data, err := os.ReadFile(filepath.Join(info, "METADATA"))
		if err != nil {
			continue
		}
		d := parseDistMetadata(data)
		if d.name == "" || d.version == "" {
			continue
		}
		d.editable = distEditable(info)
		d.files = distRecordFiles(site, info)
		out = append(out, d)
	}
	return out
}

// parseDistMetadata reads the header of a core metadata file (an RFC 822
// style header ended by a blank line).
func parseDistMetadata(data []byte) pyDistribution {
	var d pyDistribution
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "name":
			d.name = value
		case "version":
			d.version = value
		case "requires-dist":
			if req, ok := parsePyRequirement(value); ok {
				d.requires = append(d.requires, req)
			}
		}
	}
	return d
}

func distEditable(info string) bool {
	data, err := os.ReadFile(filepath.Join(info, "direct_url.json"))
	if err != nil {
		return false
	}
	var direct struct {
		DirInfo struct {
			Editable bool `json:"editable"`
		} `json:"dir_info"`
	}
	return json.Unmarshal(data, &direct) == nil && direct.DirInfo.Editable
}

// distRecordFiles returns the absolute, clean, sorted files RECORD lists
// under site, other than the dist-info directory's own and bytecode. A
// path that leaves site (a console script in bin/) is not the
// distribution's importable code. It is never nil: the distributions share
// site-packages as their Dir, where nil Files would mean every file.
func distRecordFiles(site, info string) []string {
	files := []string{}
	f, err := os.Open(filepath.Join(info, "RECORD"))
	if err != nil {
		return files
	}
	defer func() { utils.Discard(f.Close()) }()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	infoName := filepath.Base(info)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return []string{}
		}
		if len(row) == 0 || row[0] == "" {
			continue
		}
		rel := filepath.Clean(filepath.FromSlash(row[0]))
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
			strings.HasPrefix(rel, infoName+string(filepath.Separator)) ||
			strings.HasSuffix(rel, ".pyc") {
			continue
		}
		files = append(files, filepath.Join(site, rel))
	}
	slices.Sort(files)
	return slices.Compact(files)
}

// PythonDistribution is one installed distribution: its PEP 503 name,
// version, the directory it is installed in (site-packages, the root its
// import packages sit under) and the files its RECORD installed there
// (absolute; never nil).
type PythonDistribution struct {
	Name    string
	Version string
	Dir     string
	Files   []string
}

// InstalledPythonDistributions reads the *.dist-info directories of dir (a
// site-packages directory, or an unpacked wheel), from their files only,
// sorted by name. An environment root (a venv) is read through its
// site-packages. None when dir holds no distribution metadata.
func InstalledPythonDistributions(dir string) []PythonDistribution {
	if site := sitePackages(dir); site != "" {
		dir = site
	}
	dists := readDistributions(dir)
	if len(dists) == 0 {
		return nil
	}
	out := make([]PythonDistribution, 0, len(dists))
	for _, d := range dists {
		out = append(out, PythonDistribution{Name: purl.PyPIName(d.name), Version: d.version, Dir: dir, Files: d.files})
	}
	return out
}

// PythonEnvironmentDirs lists the virtual environments of the project at dir
// the resolver reads, in its order: the project's .venv and venv, then the
// active one (VIRTUAL_ENV).
func PythonEnvironmentDirs(dir string) []string {
	return pyEnvironmentDirs(dir)
}
