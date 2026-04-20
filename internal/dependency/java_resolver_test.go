package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
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
