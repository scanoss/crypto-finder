package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectRootModule(t *testing.T) {
	t.Parallel()

	t.Run("go", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n"), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		if got := DetectRootModule(dir, "go"); got != "example.com/app" {
			t.Fatalf("DetectRootModule(go) = %q, want example.com/app", got)
		}
	})

	t.Run("go-missing-module-falls-back", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "go-repo")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir repo: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("require example.com/lib v1.0.0\n"), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		if got := DetectRootModule(dir, "go"); got != "go-repo" {
			t.Fatalf("DetectRootModule(go fallback) = %q, want go-repo", got)
		}
	})

	t.Run("java-group-id", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><groupId>com.acme</groupId><artifactId>demo</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "com.acme" {
			t.Fatalf("DetectRootModule(java) = %q, want com.acme", got)
		}
	})

	t.Run("java-parent-group-id", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><parent><groupId>org.parent</groupId></parent><artifactId>demo</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "org.parent" {
			t.Fatalf("DetectRootModule(java parent) = %q, want org.parent", got)
		}
	})

	t.Run("java-artifact-id-fallback", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><artifactId>demo-artifact</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "demo-artifact" {
			t.Fatalf("DetectRootModule(java artifact) = %q, want demo-artifact", got)
		}
	})

	t.Run("java-invalid-xml-fallback", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "java-repo")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir repo: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project>"), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "java-repo" {
			t.Fatalf("DetectRootModule(java invalid xml) = %q, want java-repo", got)
		}
	})

	t.Run("java-gradle-settings", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "settings.gradle"), []byte(`rootProject.name = 'gradle-demo'`), 0o600); err != nil {
			t.Fatalf("write settings.gradle: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "gradle-demo" {
			t.Fatalf("DetectRootModule(java gradle) = %q, want gradle-demo", got)
		}
	})

	t.Run("java-gradle-kts-settings", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "settings.gradle.kts"), []byte(`rootProject.name = "gradle-kts-demo"`), 0o600); err != nil {
			t.Fatalf("write settings.gradle.kts: %v", err)
		}
		if got := DetectRootModule(dir, "java"); got != "gradle-kts-demo" {
			t.Fatalf("DetectRootModule(java gradle kts) = %q, want gradle-kts-demo", got)
		}
	})

	t.Run("rust", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname = \"rust-demo\"\n"), 0o600); err != nil {
			t.Fatalf("write Cargo.toml: %v", err)
		}
		if got := DetectRootModule(dir, "rust"); got != "rust-demo" {
			t.Fatalf("DetectRootModule(rust) = %q, want rust-demo", got)
		}
	})

	t.Run("python", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname = 'py-demo'\n"), 0o600); err != nil {
			t.Fatalf("write pyproject.toml: %v", err)
		}
		if got := DetectRootModule(dir, "python"); got != "py-demo" {
			t.Fatalf("DetectRootModule(python) = %q, want py-demo", got)
		}
	})

	t.Run("empty-ecosystem-fallback", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "plain-repo")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir repo: %v", err)
		}
		if got := DetectRootModule(dir, ""); got != "plain-repo" {
			t.Fatalf("DetectRootModule(empty ecosystem) = %q, want plain-repo", got)
		}
	})

	t.Run("fallback", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "repo-name")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir repo: %v", err)
		}
		if got := DetectRootModule(dir, "python"); got != "repo-name" {
			t.Fatalf("DetectRootModule(fallback) = %q, want repo-name", got)
		}
	})
}
