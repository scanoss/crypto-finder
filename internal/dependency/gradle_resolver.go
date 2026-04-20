package dependency

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

const gradleExportTaskName = "scanossCryptoFinderExport"

//go:embed gradle_export.init.gradle
var gradleExportInitScript string

type gradleDependencyRecord struct {
	Module            string `json:"module"`
	Version           string `json:"version"`
	BinaryPath        string `json:"binaryPath"`
	SourceArchivePath string `json:"sourceArchivePath"`
}

type gradleWorkspaceMember struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
}

type gradleResolveOutput struct {
	RootModule       string                   `json:"rootModule"`
	WorkspaceMembers []gradleWorkspaceMember  `json:"workspaceMembers"`
	Dependencies     []gradleDependencyRecord `json:"dependencies"`
	VersionedGraph   map[string][]Ref         `json:"versionedGraph"`
}

// GradleResolver resolves Java/Gradle dependencies using the Gradle wrapper or Gradle CLI.
type GradleResolver struct {
	javaRuntime javaruntime.Config
	lookPath    func(string) (string, error)
}

// NewGradleResolver creates a new Gradle dependency resolver.
func NewGradleResolver() *GradleResolver {
	return &GradleResolver{lookPath: exec.LookPath}
}

// SetJavaRuntime configures which Java runtime Gradle commands should use.
func (r *GradleResolver) SetJavaRuntime(cfg javaruntime.Config) {
	r.javaRuntime = cfg
}

// Ecosystem returns "java".
func (r *GradleResolver) Ecosystem() string {
	return "java"
}

// Resolve uses Gradle itself to export a machine-readable dependency model.
func (r *GradleResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	command, err := r.selectGradleCommand(targetDir)
	if err != nil {
		return nil, err
	}

	output, err := r.exportDependencyModel(ctx, targetDir, command)
	if err != nil {
		return nil, err
	}

	result := &ResolveResult{
		RootModule:     output.RootModule,
		Dependencies:   make([]Dependency, 0, len(output.Dependencies)),
		Graph:          legacyGraphFromVersioned(output.VersionedGraph),
		VersionedGraph: output.VersionedGraph,
	}

	if len(output.WorkspaceMembers) > 1 {
		result.WorkspaceMembers = make([]WorkspaceMember, 0, len(output.WorkspaceMembers))
		for _, member := range output.WorkspaceMembers {
			result.WorkspaceMembers = append(result.WorkspaceMembers, WorkspaceMember{Name: member.Name, Dir: member.Dir})
		}
	}

	cache, err := NewSourceCache()
	if err != nil {
		return nil, failure.WrapUnknown(
			err,
			failure.CodeDependencyResolutionFailed,
			failure.StageDependency,
			"failed to create source cache",
		)
	}

	withSources := 0
	for _, dep := range output.Dependencies {
		resolved := Dependency{
			Module:               dep.Module,
			Version:              dep.Version,
			CompiledArtifactPath: dep.BinaryPath,
			SourceArchivePath:    dep.SourceArchivePath,
		}

		if dep.SourceArchivePath != "" {
			dir, extractErr := cache.ExtractZip(dep.SourceArchivePath, dep.Module, dep.Version, []string{".java"})
			if extractErr != nil {
				log.Debug().Err(extractErr).Str("module", dep.Module).Str("archive", dep.SourceArchivePath).Msg("Failed to extract Gradle source archive")
			} else {
				resolved.Dir = dir
				withSources++
			}
		}

		result.Dependencies = append(result.Dependencies, resolved)
	}

	log.Info().
		Int("total", len(result.Dependencies)).
		Int("withSources", withSources).
		Str("root", result.RootModule).
		Msg("Resolved Gradle dependencies")

	return result, nil
}

func (r *GradleResolver) exportDependencyModel(ctx context.Context, targetDir, command string) (*gradleResolveOutput, error) {
	initPath, err := r.writeInitScript()
	if err != nil {
		return nil, failure.WrapUnknown(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"failed to prepare Gradle init script",
		)
	}
	defer func() {
		if removeErr := os.Remove(initPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", initPath).Msg("Failed to remove temporary Gradle init script")
		}
	}()

	outFile, err := os.CreateTemp("", "crypto-finder-gradle-export-*.json")
	if err != nil {
		return nil, failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"create Gradle export file",
		)
	}
	outPath := outFile.Name()
	if closeErr := outFile.Close(); closeErr != nil {
		return nil, failure.Wrap(
			closeErr,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"close Gradle export file",
		)
	}
	defer func() {
		if removeErr := os.Remove(outPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Debug().Err(removeErr).Str("path", outPath).Msg("Failed to remove temporary Gradle export file")
		}
	}()

	args := []string{
		"--init-script", initPath,
		"-q",
		"--no-parallel",
		"--console=plain",
		"-Dscanoss.crypto.finder.output=" + outPath,
		gradleExportTaskName,
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = targetDir
	if err := r.configureGradleCommand(cmd, targetDir); err != nil {
		return nil, err
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"Gradle dependency export failed",
			failure.WithDetail("target_dir", targetDir),
			failure.WithDetail("output", truncateForFailure(strings.TrimSpace(string(output)), 4000)),
		)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"read Gradle dependency export",
			failure.WithDetail("target_dir", targetDir),
		)
	}

	var result gradleResolveOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"parse Gradle dependency export",
			failure.WithDetail("target_dir", targetDir),
		)
	}

	result.Dependencies = canonicalGradleDependencies(result.Dependencies)
	if result.VersionedGraph == nil {
		result.VersionedGraph = make(map[string][]Ref)
	}
	return &result, nil
}

func (r *GradleResolver) configureGradleCommand(cmd *exec.Cmd, targetDir string) error {
	selection, err := r.resolveJavaSelection(targetDir)
	if err != nil {
		return err
	}
	if selection == nil {
		return nil
	}

	cmd.Env = javaruntime.EnvWithJavaHome(os.Environ(), selection.JavaHome)
	return nil
}

type gradleVersion struct {
	raw   string
	major int
	minor int
	patch int
}

var gradleDistributionVersionPattern = regexp.MustCompile(`gradle-([0-9]+(?:\.[0-9]+){1,2})-`)

func (r *GradleResolver) resolveJavaSelection(targetDir string) (*javaruntime.Selection, error) {
	wrapperVersion, hasWrapperVersion, err := detectGradleWrapperVersion(targetDir)
	if err != nil {
		return nil, err
	}

	if r.javaRuntime.IsExplicitMajor() {
		selection, err := javaruntime.ResolveExplicitSelection(r.javaRuntime)
		if err != nil {
			return nil, failure.WrapUnknown(
				err,
				failure.CodeJavaRuntimeConfigInvalid,
				failure.StageConfig,
				"resolve explicit Java runtime selection",
			)
		}
		if !hasWrapperVersion || selection == nil {
			return selection, nil
		}
		return validateGradleJavaCompatibility(wrapperVersion, selection)
	}

	if !hasWrapperVersion {
		return nil, nil
	}

	maxMajor := wrapperVersion.maxSupportedRuntimeMajor()
	if maxMajor == "" {
		return nil, nil
	}

	if ambient := resolveAmbientCompatibleSelection(maxMajor); ambient != nil {
		return ambient, nil
	}

	for _, major := range compatibleJavaMajors(maxMajor) {
		javaHome := strings.TrimSpace(r.javaRuntime.Homes[major])
		if javaHome == "" {
			continue
		}
		runtimeVersion, err := javaruntime.RuntimeVersion(javaHome)
		if err != nil {
			return nil, failure.Wrap(
				err,
				failure.CodeJavaRuntimeConfigInvalid,
				failure.StageConfig,
				fmt.Sprintf("read Java runtime metadata for major %s", major),
				failure.WithDetail("requested_jdk", major),
				failure.WithDetail("java_home", javaHome),
			)
		}
		effectiveMajor := javaruntime.MajorFromVersion(runtimeVersion)
		if effectiveMajor != major {
			return nil, failure.New(
				failure.CodeJavaRuntimeConfigInvalid,
				failure.StageConfig,
				fmt.Sprintf("configured JDK home %q reports Java %s, expected %s", javaHome, effectiveMajor, major),
				failure.WithDetail("java_home", javaHome),
				failure.WithDetail("reported_jdk", effectiveMajor),
				failure.WithDetail("requested_jdk", major),
			)
		}
		return &javaruntime.Selection{
			RequestedMajor: major,
			JavaHome:       javaHome,
			RuntimeVersion: runtimeVersion,
			EffectiveMajor: effectiveMajor,
		}, nil
	}

	if strings.TrimSpace(os.Getenv("JAVA_HOME")) != "" {
		return nil, failure.New(
			failure.CodeGradleJavaIncompatible,
			failure.StageDependency,
			fmt.Sprintf(
				"Gradle %s cannot run on the current Java runtime; configure a compatible JDK (%s) via --java-jdk-home / SCANOSS_JAVA_JDK_HOMES or set JAVA_HOME accordingly",
				wrapperVersion.raw,
				compatibleJavaMajorsLabel(maxMajor),
			),
			failure.WithDetail("gradle_version", wrapperVersion.raw),
			failure.WithDetail("supported_jdks", compatibleJavaMajorsLabel(maxMajor)),
		)
	}

	return nil, nil
}

func validateGradleJavaCompatibility(version *gradleVersion, selection *javaruntime.Selection) (*javaruntime.Selection, error) {
	if version == nil || selection == nil {
		return selection, nil
	}

	maxMajor := version.maxSupportedRuntimeMajor()
	if maxMajor == "" {
		return selection, nil
	}

	if compareJavaMajors(selection.EffectiveMajor, maxMajor) <= 0 {
		return selection, nil
	}

	return nil, failure.New(
		failure.CodeGradleJavaIncompatible,
		failure.StageDependency,
		fmt.Sprintf(
			"Gradle %s cannot run on Java %s; configure a compatible JDK (%s)",
			version.raw,
			selection.EffectiveMajor,
			compatibleJavaMajorsLabel(maxMajor),
		),
		failure.WithDetail("gradle_version", version.raw),
		failure.WithDetail("requested_jdk", selection.EffectiveMajor),
		failure.WithDetail("supported_jdks", compatibleJavaMajorsLabel(maxMajor)),
	)
}

func resolveAmbientCompatibleSelection(maxMajor string) *javaruntime.Selection {
	javaHome := strings.TrimSpace(os.Getenv("JAVA_HOME"))
	if javaHome == "" {
		return nil
	}

	runtimeVersion, err := javaruntime.RuntimeVersion(javaHome)
	if err != nil {
		return nil
	}

	effectiveMajor := javaruntime.MajorFromVersion(runtimeVersion)
	if !javaruntime.IsSupportedMajor(effectiveMajor) {
		return nil
	}
	if compareJavaMajors(effectiveMajor, maxMajor) > 0 {
		return nil
	}

	return &javaruntime.Selection{
		RequestedMajor: effectiveMajor,
		JavaHome:       javaHome,
		RuntimeVersion: runtimeVersion,
		EffectiveMajor: effectiveMajor,
	}
}

func detectGradleWrapperVersion(targetDir string) (*gradleVersion, bool, error) {
	data, err := os.ReadFile(filepath.Join(targetDir, "gradle", "wrapper", "gradle-wrapper.properties"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, failure.Wrap(
			err,
			failure.CodeDependencyResolutionFailed,
			failure.StageDependency,
			"read gradle-wrapper.properties",
		)
	}

	matches := gradleDistributionVersionPattern.FindStringSubmatch(string(data))
	if len(matches) != 2 {
		return nil, false, nil
	}

	version, err := parseGradleVersion(matches[1])
	if err != nil {
		return nil, false, failure.Wrap(
			err,
			failure.CodeDependencyResolutionFailed,
			failure.StageDependency,
			fmt.Sprintf("parse Gradle wrapper version %q", matches[1]),
		)
	}
	return version, true, nil
}

func parseGradleVersion(raw string) (*gradleVersion, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("unexpected Gradle version format")
	}

	ints := make([]int, 3)
	for i := range parts {
		value, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil, err
		}
		ints[i] = value
	}

	return &gradleVersion{
		raw:   raw,
		major: ints[0],
		minor: ints[1],
		patch: ints[2],
	}, nil
}

func (v *gradleVersion) maxSupportedRuntimeMajor() string {
	switch {
	case v == nil:
		return ""
	case v.major > 8 || (v.major == 8 && v.minor >= 5):
		return "21"
	case v.major > 7 || (v.major == 7 && v.minor >= 3):
		return "17"
	default:
		return "11"
	}
}

func compatibleJavaMajors(maxMajor string) []string {
	candidates := []string{"21", "17", "11", "8"}
	filtered := make([]string, 0, len(candidates))
	for _, major := range candidates {
		if compareJavaMajors(major, maxMajor) <= 0 {
			filtered = append(filtered, major)
		}
	}
	return filtered
}

func compatibleJavaMajorsLabel(maxMajor string) string {
	return strings.Join(compatibleJavaMajors(maxMajor), ", ")
}

func compareJavaMajors(left, right string) int {
	leftInt, _ := strconv.Atoi(left)
	rightInt, _ := strconv.Atoi(right)
	switch {
	case leftInt < rightInt:
		return -1
	case leftInt > rightInt:
		return 1
	default:
		return 0
	}
}

func (r *GradleResolver) selectGradleCommand(targetDir string) (string, error) {
	wrapperName := "gradlew"
	if runtime.GOOS == "windows" {
		wrapperName = "gradlew.bat"
	}
	wrapperPath := filepath.Join(targetDir, wrapperName)
	if info, err := os.Stat(wrapperPath); err == nil && !info.IsDir() {
		return wrapperPath, nil
	}

	if path, err := r.lookPath("gradle"); err == nil {
		return path, nil
	}

	return "", failure.New(
		failure.CodeGradleToolMissing,
		failure.StageDependency,
		fmt.Sprintf("Gradle dependency scanning requires ./gradlew or gradle in PATH for %s", targetDir),
		failure.WithDetail("target_dir", targetDir),
	)
}

func (r *GradleResolver) writeInitScript() (string, error) {
	file, err := os.CreateTemp("", "crypto-finder-gradle-init-*.gradle")
	if err != nil {
		return "", failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"create temporary Gradle init script",
		)
	}
	if _, err := file.WriteString(gradleExportInitScript); err != nil {
		_ = file.Close()
		return "", failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"write temporary Gradle init script",
		)
	}
	if err := file.Close(); err != nil {
		return "", failure.Wrap(
			err,
			failure.CodeGradleExportFailed,
			failure.StageDependency,
			"close temporary Gradle init script",
		)
	}
	return file.Name(), nil
}

func canonicalGradleDependencies(deps []gradleDependencyRecord) []gradleDependencyRecord {
	if len(deps) == 0 {
		return nil
	}

	byKey := make(map[string]gradleDependencyRecord, len(deps))
	keys := make([]string, 0, len(deps))
	for _, dep := range deps {
		key := dependencyCoordinateKey(dep.Module, dep.Version)
		existing, ok := byKey[key]
		if !ok {
			byKey[key] = dep
			keys = append(keys, key)
			continue
		}
		if existing.BinaryPath == "" && dep.BinaryPath != "" {
			existing.BinaryPath = dep.BinaryPath
		}
		if existing.SourceArchivePath == "" && dep.SourceArchivePath != "" {
			existing.SourceArchivePath = dep.SourceArchivePath
		}
		byKey[key] = existing
	}

	sort.Strings(keys)
	out := make([]gradleDependencyRecord, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func truncateForFailure(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
