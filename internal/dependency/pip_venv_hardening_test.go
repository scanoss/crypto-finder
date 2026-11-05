// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package dependency

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestPipResolver_PrefersLocalVenv_OverGlobalPython verifies that when a
// project directory contains a .venv/ subdirectory with a python binary, the
// resolver uses it instead of any globally-installed interpreter — even when
// VIRTUAL_ENV is not set. This is the primary footgun fix: ambient global
// packages (120+ packages visible in the global env) must not pollute the
// resolver for a project that has its own venv.
func TestPipResolver_PrefersLocalVenv_OverGlobalPython(t *testing.T) {
	// Create a fake project dir with .venv/bin/python
	projectDir := t.TempDir()
	venvBin := filepath.Join(projectDir, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatalf("mkdir .venv/bin: %v", err)
	}
	localPython := filepath.Join(venvBin, "python")
	writeExecutable(t, venvBin, "python", "#!/bin/sh\necho local-venv-python\n")

	// Global bin has a different python (should NOT be chosen)
	globalBin := t.TempDir()
	writeExecutable(t, globalBin, "python3", "#!/bin/sh\necho global-python3\n")
	prependPath(t, globalBin)

	// VIRTUAL_ENV is NOT set — tests the project-local venv auto-detection
	t.Setenv("VIRTUAL_ENV", "")

	r := NewPipResolver()
	got, err := r.resolvePythonExecutable(projectDir)
	if err != nil {
		t.Fatalf("resolvePythonExecutable: %v", err)
	}
	if got != localPython {
		t.Errorf("resolvePythonExecutable() = %q, want %q (local .venv)", got, localPython)
	}
}

// TestPipResolver_PrefersLocalVenvDir_OverGlobalPython tests the "venv/"
// variant (without leading dot), which pip also creates by convention.
func TestPipResolver_PrefersLocalVenvDir_OverGlobalPython(t *testing.T) {
	projectDir := t.TempDir()
	venvBin := filepath.Join(projectDir, "venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatalf("mkdir venv/bin: %v", err)
	}
	localPython := filepath.Join(venvBin, "python")
	writeExecutable(t, venvBin, "python", "#!/bin/sh\necho local-venv-python\n")

	globalBin := t.TempDir()
	writeExecutable(t, globalBin, "python3", "#!/bin/sh\necho global\n")
	prependPath(t, globalBin)
	t.Setenv("VIRTUAL_ENV", "")

	r := NewPipResolver()
	got, err := r.resolvePythonExecutable(projectDir)
	if err != nil {
		t.Fatalf("resolvePythonExecutable: %v", err)
	}
	if got != localPython {
		t.Errorf("resolvePythonExecutable() = %q, want %q (local venv)", got, localPython)
	}
}

// TestPipResolver_VirtualEnvEnvVar_TakesPrecedenceOverLocalVenv verifies that an
// explicitly activated VIRTUAL_ENV (the env var) takes precedence even over a
// local .venv/ directory. Activated env = highest priority.
func TestPipResolver_VirtualEnvEnvVar_TakesPrecedenceOverLocalVenv(t *testing.T) {
	projectDir := t.TempDir()
	// Local .venv/ also present
	localVenvBin := filepath.Join(projectDir, ".venv", "bin")
	if err := os.MkdirAll(localVenvBin, 0o755); err != nil {
		t.Fatalf("mkdir .venv: %v", err)
	}
	writeExecutable(t, localVenvBin, "python", "#!/bin/sh\necho local\n")

	// Activated venv (VIRTUAL_ENV points somewhere else)
	activatedVenv := t.TempDir()
	activatedBin := filepath.Join(activatedVenv, "bin")
	if err := os.MkdirAll(activatedBin, 0o755); err != nil {
		t.Fatalf("mkdir activated: %v", err)
	}
	activatedPython := filepath.Join(activatedBin, "python")
	writeExecutable(t, activatedBin, "python", "#!/bin/sh\necho activated\n")

	t.Setenv("VIRTUAL_ENV", activatedVenv)

	r := NewPipResolver()
	got, err := r.resolvePythonExecutable(projectDir)
	if err != nil {
		t.Fatalf("resolvePythonExecutable: %v", err)
	}
	if got != activatedPython {
		t.Errorf("resolvePythonExecutable() = %q, want %q (activated VIRTUAL_ENV)", got, activatedPython)
	}
}

// TestPipResolver_FallsBackToGlobal_WhenNoLocalVenv confirms that when neither
// VIRTUAL_ENV nor a local .venv/venv/ exists, the resolver falls back to
// the ambient interpreter (python3 / python in PATH), as before.
func TestPipResolver_FallsBackToGlobal_WhenNoLocalVenv(t *testing.T) {
	projectDir := t.TempDir() // no .venv/ or venv/ inside

	globalBin := t.TempDir()
	globalPython3 := filepath.Join(globalBin, "python3")
	writeExecutable(t, globalBin, "python3", "#!/bin/sh\necho global3\n")
	prependPath(t, globalBin)
	t.Setenv("VIRTUAL_ENV", "")

	r := NewPipResolver()
	got, err := r.resolvePythonExecutable(projectDir)
	if err != nil {
		t.Fatalf("resolvePythonExecutable: %v", err)
	}
	if got != globalPython3 {
		t.Errorf("resolvePythonExecutable() = %q, want %q (global python3 fallback)", got, globalPython3)
	}
}

// TestPipResolver_Resolve_UsesLocalVenv_WhenPresent is an integration-style test
// proving that Resolve() itself uses the local .venv interpreter when available.
// The stub interpreter writes invocations to a log so we can assert which binary ran.
func TestPipResolver_Resolve_UsesLocalVenv_WhenPresent(t *testing.T) {
	projectDir := t.TempDir()

	// Set up a local .venv with a stub python that logs invocations
	sitePackages := filepath.Join(t.TempDir(), "site-packages")
	if err := os.MkdirAll(filepath.Join(sitePackages, "cryptography"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "invocations.log")

	venvBin := filepath.Join(projectDir, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatalf("mkdir venv bin: %v", err)
	}
	writeExecutable(t, venvBin, "python", `#!/bin/sh
printf 'local-venv:%s\n' "$@" >> "`+logPath+`"
if [ "$1" = "-m" ] && [ "$2" = "pip" ] && [ "$3" = "list" ]; then
  printf '[{"name":"cryptography","version":"41.0.7"}]'
  exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "pip" ] && [ "$3" = "show" ]; then
  printf 'Name: cryptography\nVersion: 41.0.7\nLocation: `+sitePackages+`\nRequires: \n'
  exit 0
fi
if [ "$1" = "-c" ]; then
  printf '{"cryptography":["cryptography"]}'
  exit 0
fi
exit 1
`)

	// Global python3 exists too — should NOT be selected
	globalBin := t.TempDir()
	writeExecutable(t, globalBin, "python3", "#!/bin/sh\necho WRONG-GLOBAL\nexit 1\n")
	prependPath(t, globalBin)
	t.Setenv("VIRTUAL_ENV", "")

	r := NewPipResolver()
	result, err := r.Resolve(context.Background(), projectDir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(result.Dependencies) == 0 {
		t.Error("expected at least one resolved dependency")
	}

	// Verify the local venv python was invoked (log must mention local-venv:)
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read invocation log: %v", readErr)
	}
	if len(data) == 0 {
		t.Error("local venv python was never invoked; global was probably used instead")
	}
}

// TestPipResolver_ResolutionOrder_IsDocumented asserts the documented resolution
// order via comment reference — this test serves as a spec anchor. The actual
// behavior is exercised by the tests above; this one simply verifies that
// resolvePythonExecutable accepts the projectDir parameter (new signature).
func TestPipResolver_ResolutionOrder_IsDocumented(t *testing.T) {
	// resolvePythonExecutable(projectDir string) must accept a string argument.
	// If the signature is wrong, this test will not compile — compile-time spec check.
	r := NewPipResolver()
	r.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	t.Setenv("VIRTUAL_ENV", "")
	// No .venv in an empty dir — expects error (no interpreter found)
	emptyDir := t.TempDir()
	_, err := r.resolvePythonExecutable(emptyDir)
	if err == nil {
		t.Error("expected error when no interpreter available, got nil")
	}
}
