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
)

// TestGradleResolver_Resolve_IncludesRuntimeClasspath runs the export init
// script through a real Gradle over a project whose dependencies span the
// Java plugin's configurations, from a file repository so no network is
// needed. runtimeOnly jars are on runtimeClasspath, not compileClasspath, and
// are loaded when the application runs, so their crypto is real exposure and
// they must be resolved and graphed; testImplementation jars must stay out.
// A module the two classpaths select at different versions (shared: 1.0 under
// the compileOnly container, 2.0 under the runtimeOnly driver) is reported
// once, at the runtime version, which is the one that runs.
// It skips when no gradle is on PATH (CI has none) or with -short.
func TestGradleResolver_Resolve_IncludesRuntimeClasspath(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Gradle")
	}
	if _, err := exec.LookPath("gradle"); err != nil {
		t.Skip("gradle not on PATH")
	}

	repo := t.TempDir()
	publishFixtureArtifact(t, repo, "compiled", "1.0.0", nil)
	publishFixtureArtifact(t, repo, "shared", "1.0", nil)
	publishFixtureArtifact(t, repo, "shared", "2.0", nil)
	publishFixtureArtifact(t, repo, "container", "2.0.0", []string{"shared:1.0"})
	publishFixtureArtifact(t, repo, "driver-support", "3.1.0", nil)
	publishFixtureArtifact(t, repo, "driver", "3.0.0", []string{"driver-support:3.1.0", "shared:2.0"})
	publishFixtureArtifact(t, repo, "testkit", "4.0.0", nil)

	project := t.TempDir()
	build := fmt.Sprintf(`plugins { id 'java' }
group = 'com.acme'
version = '1.0.0'
repositories { maven { url = uri(%q) } }
dependencies {
    implementation 'org.example:compiled:1.0.0'
    compileOnly 'org.example:container:2.0.0'
    runtimeOnly 'org.example:driver:3.0.0'
    testImplementation 'org.example:testkit:4.0.0'
}
`, repo)
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte(build), 0o600); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "settings.gradle"), []byte("rootProject.name = 'app'\n"), 0o600); err != nil {
		t.Fatalf("write settings.gradle: %v", err)
	}

	result, err := NewGradleResolver().Resolve(context.Background(), project)
	if err != nil {
		var fe *failure.Error
		if errors.As(err, &fe) {
			t.Fatalf("Resolve: %v: %s", err, fe.Details["output"])
		}
		t.Fatalf("Resolve: %v", err)
	}

	got := make(map[string]Dependency)
	for _, dep := range result.Dependencies {
		got[dep.Module+"@"+dep.Version] = dep
	}
	for _, want := range []string{
		"org.example:compiled@1.0.0",
		"org.example:container@2.0.0",
		"org.example:driver@3.0.0",
		"org.example:driver-support@3.1.0",
		"org.example:shared@2.0",
	} {
		dep, ok := got[want]
		if !ok {
			t.Errorf("dependency %s not resolved; got %v", want, result.Dependencies)
			continue
		}
		if dep.CompiledArtifactPath == "" {
			t.Errorf("dependency %s has no compiled jar", want)
		}
	}
	if _, ok := got["org.example:shared@1.0"]; ok {
		t.Errorf("compile-only version of shared resolved; got %v", result.Dependencies)
	}
	if !containsDependencyRef(result.VersionedGraph["org.example:container@2.0.0"], Ref{Module: "org.example:shared", Version: "2.0"}) {
		t.Errorf("container children = %v, want shared at its runtime version", result.VersionedGraph["org.example:container@2.0.0"])
	}
	if _, ok := got["org.example:testkit@4.0.0"]; ok {
		t.Errorf("test dependency resolved; got %v", result.Dependencies)
	}
	if !containsDependencyRef(result.VersionedGraph["com.acme"], Ref{Module: "org.example:driver", Version: "3.0.0"}) {
		t.Errorf("root children = %v, want the runtimeOnly dependency", result.VersionedGraph["com.acme"])
	}
	if !containsDependencyRef(result.VersionedGraph["org.example:driver@3.0.0"], Ref{Module: "org.example:driver-support", Version: "3.1.0"}) {
		t.Errorf("driver children = %v, want driver-support", result.VersionedGraph["org.example:driver@3.0.0"])
	}
}

// publishFixtureArtifact writes org.example:<artifact>:<version> (a POM and a
// jar) into a Maven file repository, depending on org.example:<a>:<v> deps.
func publishFixtureArtifact(t *testing.T, repo, artifact, version string, deps []string) {
	t.Helper()
	dir := filepath.Join(repo, "org", "example", artifact, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	var depXML string
	for _, dep := range deps {
		a, v, _ := strings.Cut(dep, ":")
		depXML += fmt.Sprintf(`<dependency><groupId>org.example</groupId><artifactId>%s</artifactId><version>%s</version></dependency>`, a, v)
	}
	pom := fmt.Sprintf(`<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>%s</artifactId><version>%s</version><dependencies>%s</dependencies></project>`, artifact, version, depXML)
	base := filepath.Join(dir, artifact+"-"+version)
	if err := os.WriteFile(base+".pom", []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom: %v", err)
	}
	createZipArchive(t, base+".jar", map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
}
