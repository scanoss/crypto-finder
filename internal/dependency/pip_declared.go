package dependency

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// pep508Name is the distribution name a PEP 508 requirement starts with
// (requests in `requests[socks]>=2; python_version>"3.8"`).
var pep508Name = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`)

// maxRequirementIncludes bounds how deep `-r other.txt` includes are followed.
const maxRequirementIncludes = 8

// declaredPythonRequirements returns the normalized names of the
// distributions the Python project in targetDir declares: the requirements
// of requirements.txt, with the files it includes through -r, and the
// dependencies of pyproject.toml ([project] dependencies and
// [tool.poetry.dependencies]). It returns nil when the project declares
// none.
func declaredPythonRequirements(targetDir string) []string {
	names := slices.Concat(
		requirementsFileNames(filepath.Join(targetDir, "requirements.txt"), 0, map[string]bool{}),
		pyprojectDependencyNames(filepath.Join(targetDir, "pyproject.toml")),
	)
	for i, name := range names {
		names[i] = normalizePackageName(name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// requirementsFileNames reads the requirement names of a pip requirements
// file. Options are skipped except -r and --requirement, whose file is read
// relative to this one; constraints (-c) declare nothing.
func requirementsFileNames(path string, depth int, seen map[string]bool) []string {
	if depth > maxRequirementIncludes || seen[path] {
		return nil
	}
	seen[path] = true
	//nolint:gosec // G304: the requirements file of the scanned project, or one it includes.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if include, ok := requirementInclude(line); ok {
			names = append(names, requirementsFileNames(filepath.Join(filepath.Dir(path), include), depth+1, seen)...)
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		name := pep508Name.FindString(line)
		// A URL requirement names its distribution only as `name @ url`;
		// a bare URL or VCS reference does not name one this can read.
		if name == "" || strings.Contains(line, "://") && !strings.HasPrefix(strings.TrimSpace(line[len(name):]), "@") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// requirementInclude returns the file a `-r FILE` or `--requirement FILE`
// line includes.
func requirementInclude(line string) (string, bool) {
	for _, flag := range []string{"--requirement", "-r"} {
		rest, ok := strings.CutPrefix(line, flag)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
		if rest != "" && rest != line {
			return rest, true
		}
	}
	return "", false
}

// pyprojectDependencyNames reads the dependency names of a pyproject.toml:
// the PEP 621 [project] dependencies and the [tool.poetry.dependencies]
// keys other than python.
func pyprojectDependencyNames(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &doc) != nil {
		return nil
	}
	var names []string
	for _, requirement := range doc.Project.Dependencies {
		if name := pep508Name.FindString(strings.TrimSpace(requirement)); name != "" {
			names = append(names, name)
		}
	}
	for name := range doc.Tool.Poetry.Dependencies {
		if !strings.EqualFold(name, "python") {
			names = append(names, name)
		}
	}
	return names
}

// declaredInstalled returns the modules of deps whose normalized name is in
// declared, in deps order: the declared requirements the environment holds.
func declaredInstalled(declared []string, deps []Dependency) []string {
	var direct []string
	for _, dep := range deps {
		if _, found := slices.BinarySearch(declared, normalizePackageName(dep.Module)); found {
			direct = append(direct, dep.Module)
		}
	}
	return direct
}
