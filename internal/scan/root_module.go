package scan

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
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
		if name := detectSectionName(filepath.Join(targetDir, "pyproject.toml"), "[project]"); name != "" {
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
	data, err := os.ReadFile(filepath.Join(targetDir, "pom.xml"))
	if err != nil {
		return ""
	}

	var pom pomRootModule
	if err := xml.Unmarshal(data, &pom); err != nil {
		return ""
	}
	if pom.GroupID != "" {
		return pom.GroupID
	}
	if pom.Parent.GroupID != "" {
		return pom.Parent.GroupID
	}
	return pom.ArtifactID
}

func detectSectionName(path, section string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer closeRootModuleFile(file)

	inSection := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == section {
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
