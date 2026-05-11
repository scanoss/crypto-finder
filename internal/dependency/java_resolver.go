package dependency

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
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
