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

// ownSharedRoots gives each distribution whose Dir another distribution
// shares the files it installed there. Namespace packages do this: protobuf,
// google-auth and google-api-core all install into google/. A distribution
// owns the files under Dir its dist-info RECORD lists; one without a RECORD
// owns the files no sibling's RECORD lists. A distribution with a Dir of its
// own keeps the whole directory. locations[i] is the site-packages directory
// of deps[i], which RECORD paths are relative to.
func ownSharedRoots(deps []Dependency, locations []string) {
	byDir := make(map[string][]int)
	var dirs []string
	for i := range deps {
		dir := filepath.Clean(deps[i].Dir)
		if byDir[dir] == nil {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], i)
	}
	for _, dir := range dirs {
		siblings := byDir[dir]
		if len(siblings) < 2 {
			continue
		}
		claimed := make(map[string]bool)
		var unrecorded []int
		for _, i := range siblings {
			files, ok := recordedFiles(locations[i], deps[i].Module, deps[i].Version, dir)
			if !ok {
				unrecorded = append(unrecorded, i)
				continue
			}
			deps[i].Files = files
			for _, file := range files {
				claimed[file] = true
			}
		}
		if len(unrecorded) == 0 {
			continue
		}
		remainder := unclaimedFiles(dir, claimed)
		for _, i := range unrecorded {
			deps[i].Files = slices.Clone(remainder)
		}
	}
}

// recordedFiles returns the regular files below dir that the RECORD of the
// distribution module at version lists, sorted, and false when the
// distribution has no readable RECORD in location.
func recordedFiles(location, module, version, dir string) ([]string, bool) {
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
		if !underDir(dir, path) {
			continue
		}
		//nolint:gosec // G703: a RECORD entry is only stat'ed, and only when it lies below the distribution's directory.
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), true
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
