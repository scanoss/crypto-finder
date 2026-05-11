package scan

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/crypto-finder/internal/dependency"
)

const (
	ecosystemGo     = "go"
	ecosystemJava   = "java"
	ecosystemRust   = "rust"
	ecosystemPython = "python"
)

// pythonBuildBackendPrefixes lists PEP 517 build backends that indicate the
// repository is published as a Python package. Matched against entries in
// pyproject.toml's [build-system].requires via case-insensitive prefix compare
// (entries include version specifiers like "setuptools-rust>=1.7.0").
var pythonBuildBackendPrefixes = []string{
	"setuptools",
	"setuptools-rust",
	"maturin",
	"hatchling",
	"hatch-vcs",
	"poetry-core",
	"flit-core",
	"flit_core",
	"pdm-backend",
	"pdm_backend",
	"scikit-build",
	"scikit_build",
	"meson-python",
	"meson_python",
	"cffi",
}

// DetectEcosystem checks the target directory for known manifest files
// and returns the corresponding ecosystem name ("go", "python", "java", "rust").
// Returns empty string if no ecosystem is detected.
//
// Polyglot resolution: when a pyproject.toml declares a Python package (via
// [project] / [tool.*] / PEP 517 build backend), it wins over Cargo.toml —
// this captures Python packages that embed Rust via PyO3, maturin or
// setuptools-rust (pyca/cryptography, pydantic-core, orjson, polars, ...).
// Polyglot conflicts outside the Python↔Rust pair are not disambiguated here;
// they keep the original precedence (Go → Java → Rust → Python fallback).
func DetectEcosystem(target string) string {
	// go.mod at root is authoritative for Go.
	if _, err := os.Stat(filepath.Join(target, "go.mod")); err == nil {
		return ecosystemGo
	}
	if dependency.HasJavaManifest(target) {
		return ecosystemJava
	}
	// Python↔Rust disambiguation: inspect pyproject.toml before letting
	// Cargo.toml win. A pyproject that declares a Python package takes
	// precedence over an embedded Rust crate.
	pyprojectPath := filepath.Join(target, "pyproject.toml")
	if isPythonPackagePyproject(pyprojectPath) {
		return ecosystemPython
	}
	if _, err := os.Stat(filepath.Join(target, "Cargo.toml")); err == nil {
		return ecosystemRust
	}
	for _, manifest := range []string{"pyproject.toml", "requirements.txt", "Pipfile", "setup.py"} {
		if _, err := os.Stat(filepath.Join(target, manifest)); err == nil {
			return ecosystemPython
		}
	}
	return ""
}

// isPythonPackagePyproject returns true when the given pyproject.toml declares
// the repository as a published Python package. Returns false on missing file,
// read errors, malformed TOML, or pyprojects that only hold dev-tooling config
// (e.g. [tool.black], [tool.ruff]) — in those cases the caller falls back to
// the normal manifest precedence.
func isPythonPackagePyproject(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false
	}
	var parsed struct {
		Project     map[string]any `toml:"project"`
		BuildSystem struct {
			Requires []string `toml:"requires"`
			Backend  string   `toml:"build-backend"`
		} `toml:"build-system"`
		Tool map[string]any `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return false
	}
	// PEP 621 [project] table → explicit Python package.
	if len(parsed.Project) > 0 {
		return true
	}
	// PEP 517 build backend pointing at a Python packaging tool.
	if hasPythonBuildBackend(parsed.BuildSystem.Backend, parsed.BuildSystem.Requires) {
		return true
	}
	// [tool.maturin] / [tool.setuptools-rust] declare Python packaging of a
	// Rust extension even without [project] (older layouts).
	if _, ok := parsed.Tool["maturin"]; ok {
		return true
	}
	if _, ok := parsed.Tool["setuptools-rust"]; ok {
		return true
	}
	return false
}

// hasPythonBuildBackend reports whether the declared PEP 517 backend or any
// entry in build-system.requires matches a known Python packaging tool.
func hasPythonBuildBackend(backend string, requires []string) bool {
	if backend != "" {
		head := strings.ToLower(strings.SplitN(backend, ".", 2)[0])
		if slices.Contains(pythonBuildBackendPrefixes, head) {
			return true
		}
	}
	for _, req := range requires {
		name := strings.ToLower(pythonRequirementName(req))
		if slices.Contains(pythonBuildBackendPrefixes, name) {
			return true
		}
	}
	return false
}

// pythonRequirementName extracts the distribution name from a PEP 508
// requirement string, stripping version specifiers, extras and environment
// markers. "setuptools-rust>=1.7.0; platform_python_implementation != 'PyPy'"
// → "setuptools-rust".
func pythonRequirementName(req string) string {
	req = strings.TrimSpace(req)
	for _, sep := range []string{";", "[", " ", "=", "<", ">", "!", "~"} {
		if idx := strings.Index(req, sep); idx >= 0 {
			req = req[:idx]
		}
	}
	return strings.TrimSpace(req)
}
