// Package javaruntime manages Java runtime selection for Java dependency
// resolution and platform signature indexing.
package javaruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// AutoMajor uses the ambient JAVA_HOME instead of requiring an explicit JDK major.
	AutoMajor = "auto"
	// DefaultMiningMajor is the default JDK major for upstream mining and API retrieval.
	DefaultMiningMajor = "21"
)

const cacheKeyAuto = "jdk-auto"

var supportedMajors = map[string]struct{}{
	"8":  {},
	"11": {},
	"17": {},
	"21": {},
}

// Config controls which Java runtime should be used for Java-specific
// dependency resolution and platform signature indexing.
type Config struct {
	RequestedMajor string
	Homes          map[string]string
}

// Selection is a resolved Java runtime choice with validated runtime metadata.
type Selection struct {
	RequestedMajor string
	JavaHome       string
	RuntimeVersion string
	EffectiveMajor string
}

// NewConfig validates and normalizes Java runtime configuration.
func NewConfig(requestedMajor string, homes map[string]string) (Config, error) {
	major, err := NormalizeMajor(requestedMajor)
	if err != nil {
		return Config{}, err
	}
	normalizedHomes, err := NormalizeHomes(homes)
	if err != nil {
		return Config{}, err
	}
	return Config{
		RequestedMajor: major,
		Homes:          normalizedHomes,
	}, nil
}

// NormalizeMajor validates a requested JDK major selector.
func NormalizeMajor(raw string) (string, error) {
	major := strings.TrimSpace(raw)
	if major == "" {
		return AutoMajor, nil
	}
	if major == AutoMajor {
		return major, nil
	}
	if _, ok := supportedMajors[major]; !ok {
		return "", fmt.Errorf("unsupported Java JDK major %q (supported: auto, 8, 11, 17, 21)", raw)
	}
	return major, nil
}

// IsSupportedMajor reports whether the provided JDK major is supported.
func IsSupportedMajor(major string) bool {
	_, ok := supportedMajors[major]
	return ok
}

// NormalizeHomes validates and trims a major-to-home mapping.
func NormalizeHomes(raw map[string]string) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}

	normalized := make(map[string]string, len(raw))
	for major, path := range raw {
		normMajor, err := NormalizeMajor(major)
		if err != nil {
			return nil, err
		}
		if normMajor == AutoMajor {
			return nil, fmt.Errorf("java_jdk_homes does not support %q as a key", AutoMajor)
		}

		normPath := strings.TrimSpace(path)
		if normPath == "" {
			return nil, fmt.Errorf("empty JDK home for Java major %s", normMajor)
		}
		normalized[normMajor] = normPath
	}

	return normalized, nil
}

// ParseHomeEntries parses repeatable `<major>=<path>` flag values.
func ParseHomeEntries(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return map[string]string{}, nil
	}

	homes := make(map[string]string, len(entries))
	for _, entry := range entries {
		major, path, err := parseHomeEntry(entry)
		if err != nil {
			return nil, err
		}
		homes[major] = path
	}
	return NormalizeHomes(homes)
}

// ParseHomeEnv parses the SCANOSS_JAVA_JDK_HOMES environment variable.
func ParseHomeEnv(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]string{}, nil
	}

	parts := strings.Split(trimmed, ",")
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		entries = append(entries, part)
	}
	return ParseHomeEntries(entries)
}

// MergeHomes overlays override homes on top of base homes.
func MergeHomes(base, override map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(override))
	for major, path := range base {
		merged[major] = path
	}
	for major, path := range override {
		merged[major] = path
	}
	return merged
}

// RequestedMajorOrAuto returns the configured JDK major or `auto`.
func (c Config) RequestedMajorOrAuto() string {
	if c.RequestedMajor == "" {
		return AutoMajor
	}
	return c.RequestedMajor
}

// IsExplicitMajor reports whether a specific JDK major was requested.
func (c Config) IsExplicitMajor() bool {
	return c.RequestedMajorOrAuto() != AutoMajor
}

// CacheKeyToken returns the Java runtime cache partition token for this config.
func (c Config) CacheKeyToken() string {
	if c.IsExplicitMajor() {
		return "jdk-" + c.RequestedMajorOrAuto()
	}

	javaHome := strings.TrimSpace(os.Getenv("JAVA_HOME"))
	if javaHome == "" {
		return cacheKeyAuto
	}

	runtimeVersion, err := RuntimeVersion(javaHome)
	if err != nil {
		return cacheKeyAuto
	}

	major := MajorFromVersion(runtimeVersion)
	if !IsSupportedMajor(major) {
		return cacheKeyAuto
	}

	return "jdk-" + major
}

// ResolveExplicitSelection resolves and validates the explicitly requested Java runtime.
func ResolveExplicitSelection(cfg Config) (*Selection, error) {
	requestedMajor := cfg.RequestedMajorOrAuto()
	if requestedMajor == AutoMajor {
		return nil, nil
	}

	javaHome := strings.TrimSpace(cfg.Homes[requestedMajor])
	if javaHome == "" {
		return nil, fmt.Errorf("no configured JDK home for Java major %s", requestedMajor)
	}

	runtimeVersion, err := RuntimeVersion(javaHome)
	if err != nil {
		return nil, fmt.Errorf("read Java runtime metadata for major %s: %w", requestedMajor, err)
	}

	effectiveMajor := MajorFromVersion(runtimeVersion)
	if effectiveMajor != requestedMajor {
		return nil, fmt.Errorf("configured JDK home %q reports Java %s, expected %s", javaHome, effectiveMajor, requestedMajor)
	}

	return &Selection{
		RequestedMajor: requestedMajor,
		JavaHome:       javaHome,
		RuntimeVersion: runtimeVersion,
		EffectiveMajor: effectiveMajor,
	}, nil
}

// RuntimeVersion returns the normalized Java runtime version from a JDK home.
func RuntimeVersion(javaHome string) (string, error) {
	props, err := ParseReleaseFile(javaHome)
	if err != nil {
		return "", err
	}

	runtimeVersion := strings.TrimSpace(props["JAVA_VERSION"])
	runtimeVersion = strings.Trim(runtimeVersion, "\"")
	if runtimeVersion == "" {
		return "", fmt.Errorf("JAVA_VERSION missing from %s", filepath.Join(javaHome, "release"))
	}

	return runtimeVersion, nil
}

// ParseReleaseFile reads the JDK `release` metadata file from a Java home.
func ParseReleaseFile(javaHome string) (map[string]string, error) {
	// #nosec G304,G703 -- javaHome is a validated JDK home configured by the caller.
	data, err := os.ReadFile(filepath.Join(javaHome, "release"))
	if err != nil {
		return nil, err
	}

	props := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		props[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return props, nil
}

// MajorFromVersion extracts the Java major version from a runtime version string.
func MajorFromVersion(runtimeVersion string) string {
	version := strings.Trim(runtimeVersion, "\"")
	if strings.HasPrefix(version, "1.8.") {
		return "8"
	}

	part, _, _ := strings.Cut(version, ".")
	return part
}

// EnvWithJavaHome rewrites an environment to use the provided Java home.
func EnvWithJavaHome(base []string, javaHome string) []string {
	env := make([]string, 0, len(base)+2)
	pathUpdated := false
	javaHomeSet := false

	for _, entry := range base {
		switch {
		case strings.HasPrefix(entry, "JAVA_HOME="):
			env = append(env, "JAVA_HOME="+javaHome)
			javaHomeSet = true
		case strings.HasPrefix(entry, "PATH="):
			pathValue := strings.TrimPrefix(entry, "PATH=")
			env = append(env, "PATH="+filepath.Join(javaHome, "bin")+string(os.PathListSeparator)+pathValue)
			pathUpdated = true
		default:
			env = append(env, entry)
		}
	}

	if !javaHomeSet {
		env = append(env, "JAVA_HOME="+javaHome)
	}
	if !pathUpdated {
		env = append(env, "PATH="+filepath.Join(javaHome, "bin"))
	}

	return env
}

func parseHomeEntry(entry string) (string, string, error) {
	major, path, ok := strings.Cut(strings.TrimSpace(entry), "=")
	if !ok {
		return "", "", fmt.Errorf("invalid Java JDK home mapping %q (expected <major>=<path>)", entry)
	}

	normMajor, err := NormalizeMajor(major)
	if err != nil {
		return "", "", err
	}
	if normMajor == AutoMajor {
		return "", "", fmt.Errorf("java_jdk_homes does not support %q as a key", AutoMajor)
	}

	normPath := strings.TrimSpace(path)
	if normPath == "" {
		return "", "", fmt.Errorf("empty JDK home in mapping %q", entry)
	}

	return normMajor, normPath, nil
}
