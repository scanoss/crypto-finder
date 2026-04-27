package dependency

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

func TestDetectJavaBuildTool(t *testing.T) {
	t.Run("maven", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		tool, err := DetectJavaBuildTool(dir)
		if err != nil {
			t.Fatalf("DetectJavaBuildTool: %v", err)
		}
		if tool != javaBuildToolMaven {
			t.Fatalf("tool = %q, want %q", tool, javaBuildToolMaven)
		}
	})

	t.Run("gradle-groovy", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
			t.Fatalf("write build.gradle: %v", err)
		}
		tool, err := DetectJavaBuildTool(dir)
		if err != nil {
			t.Fatalf("DetectJavaBuildTool: %v", err)
		}
		if tool != javaBuildToolGradle {
			t.Fatalf("tool = %q, want %q", tool, javaBuildToolGradle)
		}
	})

	t.Run("gradle-kotlin-settings-only", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "settings.gradle.kts"), []byte(`rootProject.name = "demo"`), 0o600); err != nil {
			t.Fatalf("write settings.gradle.kts: %v", err)
		}
		tool, err := DetectJavaBuildTool(dir)
		if err != nil {
			t.Fatalf("DetectJavaBuildTool: %v", err)
		}
		if tool != javaBuildToolGradle {
			t.Fatalf("tool = %q, want %q", tool, javaBuildToolGradle)
		}
	})

	t.Run("mixed-manifests-fail-clearly", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
			t.Fatalf("write build.gradle: %v", err)
		}
		_, err := DetectJavaBuildTool(dir)
		if err == nil || !strings.Contains(err.Error(), "ambiguous Java build tool") {
			t.Fatalf("expected clear ambiguity error, got %v", err)
		}
		structured, ok := failure.As(err)
		if !ok {
			t.Fatalf("expected structured failure, got %T", err)
		}
		if structured.Code != failure.CodeJavaBuildToolAmbiguous {
			t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeJavaBuildToolAmbiguous)
		}
	})
}

func TestJavaResolver_Resolve_FailsClearlyForMixedManifests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	resolver := NewJavaResolver()
	_, err := resolver.Resolve(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "ambiguous Java build tool") {
		t.Fatalf("expected clear ambiguity error, got %v", err)
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("expected structured failure, got %T", err)
	}
	if structured.Code != failure.CodeJavaBuildToolAmbiguous {
		t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeJavaBuildToolAmbiguous)
	}
}

func TestJavaResolver_ConfigurationAndManifestHelpers(t *testing.T) {
	t.Parallel()

	resolver := NewJavaResolver()
	if got := resolver.Ecosystem(); got != ecosystemJava {
		t.Fatalf("Ecosystem() = %q, want %q", got, ecosystemJava)
	}

	cfg := javaruntime.Config{
		RequestedMajor: "21",
		Homes:          map[string]string{"21": "/tmp/fake-jdk-21"},
	}
	resolver.SetJavaRuntime(cfg)

	if !reflect.DeepEqual(resolver.javaRuntime, cfg) {
		t.Fatalf("resolver.javaRuntime = %#v, want %#v", resolver.javaRuntime, cfg)
	}
	if resolver.maven == nil || !reflect.DeepEqual(resolver.maven.javaRuntime, cfg) {
		t.Fatalf("resolver.maven.javaRuntime = %#v, want %#v", resolver.maven.javaRuntime, cfg)
	}
	if resolver.gradle == nil || !reflect.DeepEqual(resolver.gradle.javaRuntime, cfg) {
		t.Fatalf("resolver.gradle.javaRuntime = %#v, want %#v", resolver.gradle.javaRuntime, cfg)
	}

	dir := t.TempDir()
	if HasJavaManifest(dir) {
		t.Fatal("HasJavaManifest() = true, want false for empty directory")
	}

	subdir := filepath.Join(dir, "nested")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if fileExists(subdir) {
		t.Fatal("fileExists() = true for directory, want false")
	}
}

func TestDetectJavaBuildTool_UnknownAndGradleVariants(t *testing.T) {
	t.Parallel()

	t.Run("unknown-with-no-manifests", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		tool, err := DetectJavaBuildTool(dir)
		if err == nil {
			t.Fatal("expected DetectJavaBuildTool to fail for missing manifests")
		}
		if tool != "" {
			t.Fatalf("tool = %q, want empty string", tool)
		}

		structured, ok := failure.As(err)
		if !ok {
			t.Fatalf("expected structured failure, got %T", err)
		}
		if structured.Code != failure.CodeDependencyBuildToolUnknown {
			t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeDependencyBuildToolUnknown)
		}
	})

	tests := []struct {
		name     string
		filename string
	}{
		{name: "gradle kotlin build file", filename: "build.gradle.kts"},
		{name: "gradle groovy settings file", filename: "settings.gradle"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tt.filename), []byte("rootProject.name = \"demo\""), 0o600); err != nil {
				t.Fatalf("write %s: %v", tt.filename, err)
			}

			tool, err := DetectJavaBuildTool(dir)
			if err != nil {
				t.Fatalf("DetectJavaBuildTool: %v", err)
			}
			if tool != javaBuildToolGradle {
				t.Fatalf("tool = %q, want %q", tool, javaBuildToolGradle)
			}
			if !HasJavaManifest(dir) {
				t.Fatal("HasJavaManifest() = false, want true")
			}
		})
	}
}

func TestJavaResolver_Resolve_DelegatesToDetectedBuildTool(t *testing.T) {
	t.Parallel()

	t.Run("maven branch", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project>"), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}

		resolver := NewJavaResolver()
		_, err := resolver.Resolve(context.Background(), dir)
		if err == nil {
			t.Fatal("expected Resolve() to fail for invalid pom.xml")
		}
		if !strings.Contains(err.Error(), "failed to parse pom.xml") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("gradle branch", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
			t.Fatalf("write build.gradle: %v", err)
		}

		resolver := NewJavaResolver()
		resolver.gradle.lookPath = func(string) (string, error) {
			return "", exec.ErrNotFound
		}

		_, err := resolver.Resolve(context.Background(), dir)
		if err == nil {
			t.Fatal("expected Resolve() to fail when gradle is unavailable")
		}

		structured, ok := failure.As(err)
		if !ok {
			t.Fatalf("expected structured failure, got %T", err)
		}
		if structured.Code != failure.CodeGradleToolMissing {
			t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeGradleToolMissing)
		}
	})
}
