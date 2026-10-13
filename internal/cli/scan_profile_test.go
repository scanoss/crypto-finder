// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanProfilePathsFlagsWinOverEnvironment(t *testing.T) {
	env := map[string]string{envCPUProfile: "env.cpu", envMemProfile: "env.mem", envTrace: "env.trace"}
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }

	got := scanProfilePaths{CPU: "flag.cpu"}.withEnvDefaults(lookup)
	want := scanProfilePaths{CPU: "flag.cpu", Mem: "env.mem", Trace: "env.trace"}
	if got != want {
		t.Fatalf("paths = %+v, want %+v", got, want)
	}
}

func TestStartScanProfilesWritesTrace(t *testing.T) {
	dir := t.TempDir()
	paths := scanProfilePaths{CPU: filepath.Join(dir, "cpu"), Mem: filepath.Join(dir, "mem"), Trace: filepath.Join(dir, "trace")}
	stop, err := startScanProfiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	for _, path := range []string{paths.CPU, paths.Mem, paths.Trace} {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Errorf("%s not written: %v", path, err)
		}
	}
}
