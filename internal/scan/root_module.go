package scan

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type pomRootModule struct {
	XMLName    xml.Name      `xml:"project"`
	GroupID    string        `xml:"groupId"`
	ArtifactID string        `xml:"artifactId"`
	Parent     pomRootParent `xml:"parent"`
}

type pomRootParent struct {
	GroupID string `xml:"groupId"`
}

// DetectRootModule returns a best-effort root module/package name for callgraph export.
// It is manifest-based when possible and falls back to the target directory name.
func DetectRootModule(targetDir, ecosystem string) string {
	if ecosystem == "" {
		return filepath.Base(targetDir)
	}

	switch ecosystem {
	case ecosystemGo:
		if name := detectGoRootModule(targetDir); name != "" {
			return name
		}
	case ecosystemJava:
		if name := detectJavaRootModule(targetDir); name != "" {
			return name
		}
	case ecosystemRust:
		// Cargo lets a manifest's package name use hyphens, but the crate
		// identifier code actually references is the underscore form (Cargo
		// itself makes this substitution) -- yielding the same identity a
		// consumer's `use aes_gcm::...` resolves to, instead of one no
		// contract can ever match.
		if name := detectSectionName(filepath.Join(targetDir, "Cargo.toml"), "[package]"); name != "" {
			return strings.ReplaceAll(name, "-", "_")
		}
	case ecosystemPython:
		// A SINGLE TOP-LEVEL PACKAGE DIRECTORY ALREADY SUPPLIES THE PREFIX, so
		// this check comes BEFORE the manifest one. An sdist laid out as
		// `<root>/<pkg>/__init__.py` yields declaration FQNs that already start
		// with `<pkg>`; returning a root module as well prepends it a second
		// time, and every contract key and rule `api` then fails to join.
		//
		// This ordering used to be the other way round, and the manifest branch
		// won for any project carrying a PEP 621 `pyproject.toml` -- which is
		// most modern Python packages. Measured on fastecdsa, which migrated
		// from setup.py to pyproject.toml at 2.3.0 and changed nothing else
		// about its layout: with the manifest branch first, 2.3.0, 3.0.0 and
		// 3.0.1 synthesized ZERO crypto API entry points while 1.6.2 - 2.2.3
		// synthesized 8 to 12. Deleting pyproject.toml from the 2.3.0 tree and
		// changing nothing else restored all 12, with byte-identical
		// function_count (64) and edge_count (318) -- so the call graph was
		// never the problem, only the prefix.
		//
		// The manifest is still consulted for the layouts where the path does
		// NOT carry the package name: a src-layout project (`src/<pkg>/`) has
		// no top-level package directory, and a distribution shipping several
		// top-level packages has no unique one.
		if hasUniquePythonPackageDir(targetDir) {
			return ""
		}
		if name := detectSectionName(filepath.Join(targetDir, "pyproject.toml"), "[project]", "[tool.poetry]"); name != "" {
			return name
		}
	}

	return filepath.Base(targetDir)
}

func detectGoRootModule(targetDir string) string {
	file, err := os.Open(filepath.Join(targetDir, "go.mod"))
	if err != nil {
		return ""
	}
	defer closeRootModuleFile(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}

	return ""
}

func detectJavaRootModule(targetDir string) string {
	if pomName := detectPomRootModule(targetDir); pomName != "" {
		return pomName
	}

	return detectGradleRootModule(targetDir)
}

func detectPomRootModule(targetDir string) string {
	data, err := os.ReadFile(filepath.Join(targetDir, "pom.xml"))
	if err != nil {
		return ""
	}

	var pom pomRootModule
	if err := xml.Unmarshal(data, &pom); err != nil {
		return ""
	}

	switch {
	case pom.GroupID != "":
		return pom.GroupID
	case pom.Parent.GroupID != "":
		return pom.Parent.GroupID
	default:
		return pom.ArtifactID
	}
}

var gradleRootNamePattern = regexp.MustCompile(`(?m)^\s*rootProject\.name\s*=\s*["']([^"']+)["']`)

func detectGradleRootModule(targetDir string) string {
	for _, candidate := range []string{"settings.gradle", "settings.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(targetDir, candidate))
		if err != nil {
			continue
		}
		matches := gradleRootNamePattern.FindStringSubmatch(string(data))
		if len(matches) == 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func detectSectionName(path string, sections ...string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer closeRootModuleFile(file)

	allowed := make(map[string]bool, len(sections))
	for _, section := range sections {
		allowed[section] = true
	}

	inSection := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if allowed[line] {
			inSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = false
			continue
		}
		if !inSection || !strings.HasPrefix(line, "name") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		return strings.Trim(strings.TrimSpace(parts[1]), "\"'")
	}

	return ""
}

func closeRootModuleFile(file *os.File) {
	if err := file.Close(); err != nil {
		_ = err
	}
}

func hasUniquePythonPackageDir(targetDir string) bool {
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return false
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(targetDir, e.Name(), "__init__.py")); err == nil {
			count++
			if count > 1 {
				return false
			}
		}
	}
	return count == 1
}
