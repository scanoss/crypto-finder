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
		if name := detectSectionName(filepath.Join(targetDir, "Cargo.toml"), "[package]"); name != "" {
			return name
		}
	case ecosystemPython:
		if name := detectSectionName(filepath.Join(targetDir, "pyproject.toml"), "[project]", "[tool.poetry]"); name != "" {
			return name
		}
		if hasUniquePythonPackageDir(targetDir) {
			return ""
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
