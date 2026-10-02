package dependency

import (
	"encoding/csv"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// ListsFile reports whether files, a dependency's Files, include path, an
// absolute clean path below the dependency's Dir. Nil files include every
// path.
func ListsFile(files []string, path string) bool {
	if files == nil {
		return true
	}
	_, found := slices.BinarySearch(files, path)
	return found
}

// installedDistribution is where a distribution installed its source: the
// site-packages directory, and the top-level packages (directories) and
// modules (name.py files) it put there, relative to it, sorted.
type installedDistribution struct {
	location string
	roots    []string
}

func (d *installedDistribution) path(root string) string {
	return filepath.Join(d.location, root)
}

// placeDistributions gives deps[i], installed as installs[i], its Dir,
// ImportPath and Files. A distribution with one top-level package keeps that
// directory as its root and import path, as it always had. Any other one
// (several packages, or a module file) is rooted at site-packages, the one
// directory holding all of its roots, and lists their files: so its finding
// paths name the package (validate/__init__.py), and its scope names nothing
// of another distribution's roots below it. A package directory another
// distribution also installed into (a namespace such as google/) is shared:
// each holder owns the files under it its dist-info RECORD lists, and one
// without a RECORD the files no holder's RECORD lists.
func placeDistributions(deps []Dependency, installs []installedDistribution) {
	p := placement{deps: deps, installs: installs, holders: make(map[string][]int), records: make(map[int][]string)}
	for i := range installs {
		for _, root := range installs[i].roots {
			p.holders[installs[i].path(root)] = append(p.holders[installs[i].path(root)], i)
		}
	}
	for i := range deps {
		install := &installs[i]
		if len(install.roots) == 1 && isDir(install.path(install.roots[0])) {
			dir := install.path(install.roots[0])
			deps[i].Dir, deps[i].ImportPath = dir, install.roots[0]
			if len(p.holders[dir]) > 1 {
				deps[i].Files = p.shared(i, dir)
			}
			continue
		}
		deps[i].Dir = filepath.Clean(install.location)
		files := make([]string, 0, len(install.roots))
		for _, root := range install.roots {
			files = append(files, p.rootFiles(i, install.path(root))...)
		}
		slices.Sort(files)
		deps[i].Files = slices.Compact(files)
	}
}

// placement is the state placeDistributions shares between distributions:
// the distributions holding each root, and each one's RECORD, read once.
type placement struct {
	deps     []Dependency
	installs []installedDistribution
	holders  map[string][]int
	records  map[int][]string
}

// rootFiles returns the files distribution i owns of its root at path: the
// module file itself, its share of a directory another distribution also
// installed into, or every file of a directory of its own.
func (p *placement) rootFiles(i int, path string) []string {
	switch {
	case !isDir(path):
		return []string{path}
	case len(p.holders[path]) > 1:
		return p.shared(i, path)
	default:
		return unclaimedFiles(path, nil)
	}
}

// shared returns the files under dir that distribution i owns: those its
// RECORD lists, or without a RECORD those no holder's RECORD lists.
func (p *placement) shared(i int, dir string) []string {
	if files, ok := p.recorded(i); ok {
		return filesUnder(dir, files)
	}
	claimed := make(map[string]bool)
	for _, j := range p.holders[dir] {
		files, _ := p.recorded(j)
		for _, file := range filesUnder(dir, files) {
			claimed[file] = true
		}
	}
	return unclaimedFiles(dir, claimed)
}

func (p *placement) recorded(i int) ([]string, bool) {
	if files, ok := p.records[i]; ok {
		return files, files != nil
	}
	files, ok := recordedFiles(&p.installs[i], p.deps[i].Module, p.deps[i].Version)
	if !ok {
		files = nil
	}
	p.records[i] = files
	return files, ok
}

// recordedFiles returns the regular files below install's package
// directories that the RECORD of the distribution module at version lists,
// sorted, and false when the distribution has no readable RECORD there.
func recordedFiles(install *installedDistribution, module, version string) ([]string, bool) {
	location := install.location
	distInfo := findDistInfo(location, module, version)
	if distInfo == "" {
		return nil, false
	}
	f, err := os.Open(filepath.Join(distInfo, "RECORD"))
	if err != nil {
		return nil, false
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Str("dist_info", distInfo).Msg("Failed to close dist-info RECORD file")
		}
	}()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	files := make([]string, 0)
	for {
		row, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || len(row) == 0 || row[0] == "" {
			continue
		}
		path := filepath.Join(location, filepath.FromSlash(row[0]))
		if !slices.ContainsFunc(install.roots, func(root string) bool { return underDir(install.path(root), path) }) {
			continue
		}
		//nolint:gosec // G703: a RECORD entry is only stat'ed, and only when it lies below one of the distribution's package directories.
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), true
}

// filesUnder returns the files, sorted, that lie below dir.
func filesUnder(dir string, files []string) []string {
	under := make([]string, 0)
	for _, file := range files {
		if underDir(dir, file) {
			under = append(under, file)
		}
	}
	return under
}

// findDistInfo returns the dist-info directory of module in location,
// preferring the one of version, or "" when there is none. Its name is
// <name>-<version>.dist-info, name normalized as the distribution's.
func findDistInfo(location, module, version string) string {
	candidates, err := filepath.Glob(filepath.Join(location, "*.dist-info"))
	if err != nil {
		return ""
	}
	match := ""
	for _, candidate := range candidates {
		name, candidateVersion, _ := strings.Cut(strings.TrimSuffix(filepath.Base(candidate), ".dist-info"), "-")
		if normalizePackageName(name) != normalizePackageName(module) {
			continue
		}
		if candidateVersion == version {
			return candidate
		}
		if match == "" {
			match = candidate
		}
	}
	return match
}

// unclaimedFiles returns the regular files below dir that claimed does not
// hold, sorted.
func unclaimedFiles(dir string, claimed map[string]bool) []string {
	files := make([]string, 0)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && !claimed[path] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Str("dir", dir).Msg("Failed to list the files no distribution's RECORD claims")
	}
	return files
}

// underDir reports whether path lies strictly below dir.
func underDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
