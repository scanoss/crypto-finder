package scan

import (
	"bufio"
	"encoding/json"
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

// DetectRootModule returns the module name a manifest at targetDir declares
// for the scan root: the go.mod module path, the Cargo [package] name as the
// crate identifier, the Maven groupId:artifactId or Gradle rootProject.name,
// the pyproject [project] or [tool.poetry] name, or the package.json name.
//
// It is empty when no manifest names the module. An empty root module is a
// state, not a failure: symbols are then rooted at the scan root itself, with
// no prefix, and two scans of the same tree from differently named
// directories emit identical keys. The directory name is never used: a scan
// run from a temporary directory named after the package and a random suffix
// leaked that name into every exported symbol.
func DetectRootModule(targetDir, ecosystem string) string {
	switch ecosystem {
	case ecosystemGo:
		return detectGoRootModule(targetDir)
	case ecosystemJava:
		return detectJavaRootModule(targetDir)
	case ecosystemRust:
		// Cargo lets a manifest's package name use hyphens, but the crate
		// identifier code actually references is the underscore form (Cargo
		// itself makes this substitution) -- yielding the same identity a
		// consumer's `use aes_gcm::...` resolves to, instead of one no
		// contract can ever match.
		return strings.ReplaceAll(detectSectionName(filepath.Join(targetDir, "Cargo.toml"), "[package]"), "-", "_")
	case ecosystemPython:
		return detectSectionName(filepath.Join(targetDir, "pyproject.toml"), "[project]", "[tool.poetry]")
	case ecosystemNode:
		// The package.json name is the prefix a consumer's `require("name/sub")`
		// resolves to, and the same root NpmResolver reports on a dependency
		// scan, so a library scanned on its own keys its functions the way its
		// consumers call them.
		return detectPackageJSONName(targetDir)
	}
	return ""
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

	groupID := pom.GroupID
	if groupID == "" {
		groupID = pom.Parent.GroupID
	}
	if groupID == "" || pom.ArtifactID == "" {
		return pom.ArtifactID
	}
	return groupID + ":" + pom.ArtifactID
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

func detectPackageJSONName(targetDir string) string {
	data, err := os.ReadFile(filepath.Join(targetDir, "package.json"))
	if err != nil {
		return ""
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ""
	}
	return strings.TrimSpace(manifest.Name)
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
