package dependency

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

func TestGradleResolver_Resolve_PrefersWrapperAndExtractsSources(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	compiledJar := filepath.Join(t.TempDir(), "lib-1.2.3.jar")
	if err := os.WriteFile(compiledJar, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write compiled jar: %v", err)
	}
	sourceJar := filepath.Join(t.TempDir(), "lib-1.2.3-sources.jar")
	createZipArchive(t, sourceJar, map[string]string{"src/main/java/org/example/Lib.java": "class Lib {}"})

	pathGradleCalled := filepath.Join(t.TempDir(), "path-gradle-called")
	binDir := t.TempDir()
	writeExecutable(t, binDir, "gradle", fmt.Sprintf(`#!/bin/sh
 touch %q
 exit 1
`, pathGradleCalled))
	prependPath(t, binDir)

	wrapperCalled := filepath.Join(t.TempDir(), "wrapper-called")
	writeExecutable(t, project, "gradlew", fmt.Sprintf(`#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -Dscanoss.crypto.finder.output=*) out="${arg#-Dscanoss.crypto.finder.output=}" ;;
  esac
done
touch %q
cat > "$out" <<'JSON'
{
  "rootModule": "com.acme",
  "workspaceMembers": [],
  "dependencies": [
    {
      "module": "org.example:lib",
      "version": "1.2.3",
      "binaryPath": %q,
      "sourceArchivePath": %q
    }
  ],
  "versionedGraph": {
    "com.acme": [
      {"module": "org.example:lib", "version": "1.2.3"}
    ]
  }
}
JSON
exit 0
`, wrapperCalled, compiledJar, sourceJar))

	resolver := NewGradleResolver()
	result, err := resolver.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if _, err := os.Stat(wrapperCalled); err != nil {
		t.Fatalf("expected wrapper to be used: %v", err)
	}
	if _, err := os.Stat(pathGradleCalled); !os.IsNotExist(err) {
		t.Fatalf("expected PATH gradle to be ignored, got err=%v", err)
	}
	if result.RootModule != "com.acme" {
		t.Fatalf("RootModule = %q, want com.acme", result.RootModule)
	}
	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	dep := result.Dependencies[0]
	if dep.CompiledArtifactPath != compiledJar {
		t.Fatalf("CompiledArtifactPath = %q, want %q", dep.CompiledArtifactPath, compiledJar)
	}
	if dep.SourceArchivePath != sourceJar {
		t.Fatalf("SourceArchivePath = %q, want %q", dep.SourceArchivePath, sourceJar)
	}
	if dep.Dir == "" {
		t.Fatal("expected extracted source directory")
	}
	if _, err := os.Stat(filepath.Join(dep.Dir, "src", "main", "java", "org", "example", "Lib.java")); err != nil {
		t.Fatalf("expected extracted source file: %v", err)
	}
}

func TestGradleResolver_Resolve_DisablesParallelExecution(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	argsCapture := filepath.Join(t.TempDir(), "gradle-args.txt")
	writeExecutable(t, project, "gradlew", fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
out=""
for arg in "$@"; do
  case "$arg" in
    -Dscanoss.crypto.finder.output=*) out="${arg#-Dscanoss.crypto.finder.output=}" ;;
  esac
done
cat > "$out" <<'JSON'
{
  "rootModule": "demo",
  "workspaceMembers": [],
  "dependencies": [],
  "versionedGraph": {}
}
JSON
exit 0
`, argsCapture))

	resolver := NewGradleResolver()
	if _, err := resolver.Resolve(context.Background(), project); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	data, err := os.ReadFile(argsCapture)
	if err != nil {
		t.Fatalf("read args capture: %v", err)
	}
	if !strings.Contains(string(data), "--no-parallel\n") {
		t.Fatalf("expected --no-parallel in Gradle args, got:\n%s", data)
	}
}

func TestGradleResolver_ConfigureGradleCommand_UsesHomeCacheUnlessConfigured(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	override := filepath.Join(t.TempDir(), "gradle-cache")
	previous, wasConfigured := os.LookupEnv("GRADLE_USER_HOME")
	if err := os.Unsetenv("GRADLE_USER_HOME"); err != nil {
		t.Fatalf("unset GRADLE_USER_HOME: %v", err)
	}
	t.Cleanup(func() {
		if wasConfigured {
			_ = os.Setenv("GRADLE_USER_HOME", previous)
			return
		}
		_ = os.Unsetenv("GRADLE_USER_HOME")
	})

	tests := []struct {
		name       string
		set        bool
		configured string
		want       string
	}{
		{
			name: "defaults under HOME",
			want: filepath.Join(home, ".gradle"),
		},
		{
			name:       "preserves caller override",
			set:        true,
			configured: override,
			want:       override,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv("GRADLE_USER_HOME", tt.configured)
			}
			cmd := exec.Command("gradle")
			if err := NewGradleResolver().configureGradleCommand(cmd, t.TempDir()); err != nil {
				t.Fatalf("configureGradleCommand: %v", err)
			}

			var got string
			for _, entry := range cmd.Environ() {
				if strings.HasPrefix(entry, "GRADLE_USER_HOME=") {
					got = strings.TrimPrefix(entry, "GRADLE_USER_HOME=")
				}
			}
			if got != tt.want {
				t.Fatalf("GRADLE_USER_HOME = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGradleResolver_Resolve_FallsBackToPathGradle(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle.kts"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle.kts: %v", err)
	}

	compiledJar := filepath.Join(t.TempDir(), "util-3.0.0.jar")
	if err := os.WriteFile(compiledJar, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write compiled jar: %v", err)
	}

	binDir := t.TempDir()
	writeExecutable(t, binDir, "gradle", fmt.Sprintf(`#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -Dscanoss.crypto.finder.output=*) out="${arg#-Dscanoss.crypto.finder.output=}" ;;
  esac
done
cat > "$out" <<'JSON'
{
  "rootModule": "gradle-app",
  "workspaceMembers": [],
  "dependencies": [
    {
      "module": "org.other:util",
      "version": "3.0.0",
      "binaryPath": %q,
      "sourceArchivePath": ""
    }
  ],
  "versionedGraph": {
    "gradle-app": [
      {"module": "org.other:util", "version": "3.0.0"}
    ]
  }
}
JSON
exit 0
`, compiledJar))
	prependPath(t, binDir)

	resolver := NewGradleResolver()
	result, err := resolver.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	dep := result.Dependencies[0]
	if dep.Dir != "" {
		t.Fatalf("expected no source dir when no source archive exists, got %q", dep.Dir)
	}
	if dep.CompiledArtifactPath != compiledJar {
		t.Fatalf("CompiledArtifactPath = %q, want %q", dep.CompiledArtifactPath, compiledJar)
	}
}

func TestCompareJavaMajors_FallsBackForNonNumericInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  string
		right string
		want  int
	}{
		{name: "shorter string is lower", left: "9a", right: "10b", want: -1},
		{name: "same length lexical compare", left: "21a", right: "21b", want: -1},
		{name: "same fallback value", left: "17x", right: "17x", want: 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := compareJavaMajors(tt.left, tt.right); got != tt.want {
				t.Fatalf("compareJavaMajors(%q, %q) = %d, want %d", tt.left, tt.right, got, tt.want)
			}
		})
	}
}

func TestGradleResolver_Resolve_MultiProjectWorkspaceMembers(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	project := t.TempDir()
	appDir := filepath.Join(project, "app")
	libDir := filepath.Join(project, "lib")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir lib: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "settings.gradle"), []byte(`rootProject.name = 'demo'`), 0o600); err != nil {
		t.Fatalf("write settings.gradle: %v", err)
	}

	writeExecutable(t, project, "gradlew", fmt.Sprintf(`#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -Dscanoss.crypto.finder.output=*) out="${arg#-Dscanoss.crypto.finder.output=}" ;;
  esac
done
cat > "$out" <<'JSON'
{
  "rootModule": "com.acme",
  "workspaceMembers": [
    {"name": "com.acme:app", "dir": %q},
    {"name": "com.acme:lib", "dir": %q}
  ],
  "dependencies": [
    {
      "module": "org.example:external",
      "version": "9.1.0",
      "binaryPath": "",
      "sourceArchivePath": ""
    }
  ],
  "versionedGraph": {
    "com.acme:app": [
      {"module": "com.acme:lib", "version": ""},
      {"module": "org.example:external", "version": "9.1.0"}
    ]
  }
}
JSON
exit 0
`, appDir, libDir))

	resolver := NewGradleResolver()
	result, err := resolver.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(result.WorkspaceMembers) != 2 {
		t.Fatalf("WorkspaceMembers len = %d, want 2", len(result.WorkspaceMembers))
	}
	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "org.example:external" {
		t.Fatalf("unexpected dependency: %#v", result.Dependencies[0])
	}
	if len(result.VersionedGraph["com.acme:app"]) != 2 {
		t.Fatalf("VersionedGraph[com.acme:app] len = %d, want 2", len(result.VersionedGraph["com.acme:app"]))
	}
}

func TestGradleResolver_Resolve_MissingGradleToolingFailsClearly(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	resolver := NewGradleResolver()
	resolver.lookPath = func(string) (string, error) {
		return "", exec.ErrNotFound
	}

	_, err := resolver.Resolve(context.Background(), project)
	if err == nil || !strings.Contains(err.Error(), "requires ./gradlew or gradle in PATH") {
		t.Fatalf("expected clear tooling error, got %v", err)
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("expected structured failure, got %T", err)
	}
	if structured.Code != failure.CodeGradleToolMissing {
		t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeGradleToolMissing)
	}
}

func TestGradleResolver_Resolve_LookPathNonNotFoundErrorIsNotClassifiedAsToolMissing(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte("plugins {}"), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}

	resolver := NewGradleResolver()
	resolver.lookPath = func(string) (string, error) {
		return "", os.ErrPermission
	}

	_, err := resolver.Resolve(context.Background(), project)
	if err == nil {
		t.Fatal("expected Resolve to fail on non-ErrNotFound lookPath error")
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("expected structured failure, got %T", err)
	}
	if structured.Code == failure.CodeGradleToolMissing {
		t.Fatalf("Code = %q, did not want %q", structured.Code, failure.CodeGradleToolMissing)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected error to preserve os.ErrPermission, got %v", err)
	}
}

func TestGradleResolver_ResolveJavaSelection_AutoChoosesWrapperCompatibleJDK(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "gradle", "wrapper"), 0o755); err != nil {
		t.Fatalf("mkdir gradle wrapper: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(project, "gradle", "wrapper", "gradle-wrapper.properties"),
		[]byte("distributionUrl=https\\://services.gradle.org/distributions/gradle-6.9.2-bin.zip\n"),
		0o600,
	); err != nil {
		t.Fatalf("write gradle-wrapper.properties: %v", err)
	}

	jdk21 := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdk21, "release"), []byte("JAVA_VERSION=\"21.0.5\"\n"), 0o600); err != nil {
		t.Fatalf("write jdk21 release: %v", err)
	}
	jdk11 := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdk11, "release"), []byte("JAVA_VERSION=\"11.0.27\"\n"), 0o600); err != nil {
		t.Fatalf("write jdk11 release: %v", err)
	}

	t.Setenv("JAVA_HOME", jdk21)

	cfg, err := javaruntime.NewConfig("", map[string]string{"11": jdk11, "21": jdk21})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	resolver := NewGradleResolver()
	resolver.SetJavaRuntime(cfg)

	selection, err := resolver.resolveJavaSelection(project)
	if err != nil {
		t.Fatalf("resolveJavaSelection: %v", err)
	}
	if selection == nil {
		t.Fatal("expected automatic JDK selection")
	}
	if selection.JavaHome != jdk11 {
		t.Fatalf("JavaHome = %q, want %q", selection.JavaHome, jdk11)
	}
	if selection.EffectiveMajor != "11" {
		t.Fatalf("EffectiveMajor = %q, want 11", selection.EffectiveMajor)
	}
}

func TestGradleResolver_ResolveJavaSelection_ExplicitIncompatibleJDKFailsClearly(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "gradle", "wrapper"), 0o755); err != nil {
		t.Fatalf("mkdir gradle wrapper: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(project, "gradle", "wrapper", "gradle-wrapper.properties"),
		[]byte("distributionUrl=https\\://services.gradle.org/distributions/gradle-6.9.2-bin.zip\n"),
		0o600,
	); err != nil {
		t.Fatalf("write gradle-wrapper.properties: %v", err)
	}

	jdk21 := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdk21, "release"), []byte("JAVA_VERSION=\"21.0.5\"\n"), 0o600); err != nil {
		t.Fatalf("write jdk21 release: %v", err)
	}

	cfg, err := javaruntime.NewConfig("21", map[string]string{"21": jdk21})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	resolver := NewGradleResolver()
	resolver.SetJavaRuntime(cfg)

	_, err = resolver.resolveJavaSelection(project)
	if err == nil || !strings.Contains(err.Error(), "Gradle 6.9.2 cannot run on Java 21") {
		t.Fatalf("expected clear compatibility error, got %v", err)
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("expected structured failure, got %T", err)
	}
	if structured.Code != failure.CodeGradleJavaIncompatible {
		t.Fatalf("Code = %q, want %q", structured.Code, failure.CodeGradleJavaIncompatible)
	}
}
