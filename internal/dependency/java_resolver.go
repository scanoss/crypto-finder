package dependency

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	javaBuildToolMaven  = "maven"
	javaBuildToolGradle = "gradle"
)

// JavaRuntimeConfigurer configures which Java runtime a resolver should use for
// dependency resolution and artifact/type enrichment.
type JavaRuntimeConfigurer interface {
	SetJavaRuntime(cfg javaruntime.Config)
}

// CompiledArtifactsConfigurer is a resolver that can resolve a project's
// dependencies to their compiled artifacts only: no source is fetched or
// extracted. The application reachability client needs nothing else, since the
// server holds every dependency's graph.
type CompiledArtifactsConfigurer interface {
	SetCompiledArtifactsOnly(only bool)
}

// JavaResolver delegates Java dependency resolution to the build-tool-specific
// resolver detected at the project root.
type JavaResolver struct {
	maven       *MavenResolver
	gradle      *GradleResolver
	javaRuntime javaruntime.Config
}

// NewJavaResolver creates a Java resolver that auto-detects Maven vs Gradle.
func NewJavaResolver() *JavaResolver {
	return &JavaResolver{
		maven:  NewMavenResolver(),
		gradle: NewGradleResolver(),
	}
}

// Ecosystem returns "java".
func (r *JavaResolver) Ecosystem() string {
	return ecosystemJava
}

// CanResolve reports whether either build-tool resolver can run on targetDir.
// A root holding both manifests answers true so Resolve runs and reports the
// ambiguity as a fatal java_build_tool_ambiguous, as it did before the gate.
func (r *JavaResolver) CanResolve(targetDir string) bool {
	return r.maven.CanResolve(targetDir) || r.gradle.CanResolve(targetDir)
}

// SetJavaRuntime configures which Java runtime Java build-tool resolvers should use.
func (r *JavaResolver) SetJavaRuntime(cfg javaruntime.Config) {
	r.javaRuntime = cfg
	if r.maven != nil {
		r.maven.SetJavaRuntime(cfg)
	}
	if r.gradle != nil {
		r.gradle.SetJavaRuntime(cfg)
	}
}

// SetCompiledArtifactsOnly makes the Maven resolver resolve each dependency to
// its compiled JAR only, without sources. Gradle resolution is unchanged.
func (r *JavaResolver) SetCompiledArtifactsOnly(only bool) {
	if r.maven != nil {
		r.maven.SetCompiledArtifactsOnly(only)
	}
}

// Resolve delegates to the Java build-tool-specific resolver selected for targetDir.
func (r *JavaResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	tool, err := DetectJavaBuildTool(targetDir)
	if err != nil {
		return nil, err
	}

	switch tool {
	case javaBuildToolMaven:
		return r.maven.Resolve(ctx, targetDir)
	case javaBuildToolGradle:
		return r.gradle.Resolve(ctx, targetDir)
	default:
		return nil, failure.New(
			failure.CodeDependencyBuildToolUnknown,
			failure.StageDependency,
			fmt.Sprintf("unsupported Java build tool %q", tool),
			failure.WithDetail("build_tool", tool),
		)
	}
}

// DetectJavaBuildTool inspects the repository root and chooses the Java build tool.
// It fails clearly if both Maven and Gradle manifests are present at the root.
func DetectJavaBuildTool(targetDir string) (string, error) {
	hasPom := fileExists(filepath.Join(targetDir, "pom.xml"))
	hasGradle := hasGradleManifest(targetDir)

	switch {
	case hasPom && hasGradle:
		return "", failure.New(
			failure.CodeJavaBuildToolAmbiguous,
			failure.StageDependency,
			fmt.Sprintf("ambiguous Java build tool: found both pom.xml and Gradle manifests in %s", targetDir),
			failure.WithDetail("target_dir", targetDir),
		)
	case hasPom:
		return javaBuildToolMaven, nil
	case hasGradle:
		return javaBuildToolGradle, nil
	default:
		return "", failure.New(
			failure.CodeDependencyBuildToolUnknown,
			failure.StageDependency,
			fmt.Sprintf("could not detect a supported Java build tool in %s", targetDir),
			failure.WithDetail("target_dir", targetDir),
		)
	}
}

// HasJavaManifest reports whether the target root contains a supported Java build manifest.
func HasJavaManifest(targetDir string) bool {
	return fileExists(filepath.Join(targetDir, "pom.xml")) || hasGradleManifest(targetDir)
}

func hasGradleManifest(targetDir string) bool {
	return fileExists(filepath.Join(targetDir, "build.gradle")) ||
		fileExists(filepath.Join(targetDir, "build.gradle.kts")) ||
		fileExists(filepath.Join(targetDir, "settings.gradle")) ||
		fileExists(filepath.Join(targetDir, "settings.gradle.kts"))
}

func fileExists(path string) bool {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return true
	}
	return false
}

// SourcesJAR returns the path of dep's Maven sources JAR (classifier
// sources), the source the offline mode mines a dependency from. It looks
// beside dep's compiled JAR (the local Maven repository, or the Gradle cache,
// which keeps each file of a version in its own directory) and, for a Maven
// project resolved by this resolver, asks Maven to fetch it into the local
// repository when it is missing (Maven's own repositories and settings apply;
// an offline Maven fetches nothing). It returns an error naming the
// dependency when there is none.
func (r *JavaResolver) SourcesJAR(ctx context.Context, dep Dependency) (string, error) {
	if found := siblingSourcesJAR(dep.CompiledArtifactPath); found != "" {
		return found, nil
	}
	if r.maven != nil && r.maven.localRepo != "" { //nolint:nestif // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
		if path := r.maven.sourceJarPath(dep, r.maven.localRepo); path != "" {
			if fileExists(path) {
				return path, nil
			}
			if _, err := r.maven.fetchDependencySource(ctx, dep, r.maven.localRepo); err == nil && fileExists(path) {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("no sources JAR for %s:%s", dep.Module, dep.Version)
}

// siblingSourcesJAR finds a-v-sources.jar next to the compiled a-v.jar, or in
// another directory of the same version (Gradle's files-2.1 layout keeps each
// file under its own hash directory).
func siblingSourcesJAR(compiled string) string {
	if compiled == "" || !strings.HasSuffix(compiled, ".jar") {
		return ""
	}
	name := strings.TrimSuffix(filepath.Base(compiled), ".jar") + "-sources.jar"
	if path := filepath.Join(filepath.Dir(compiled), name); fileExists(path) {
		return path
	}
	matches := utils.Lenient(filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(compiled)), "*", name)))
	sort.Strings(matches)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}
