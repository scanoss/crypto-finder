//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type scannerJobsCase struct {
	name     string
	flags    []string
	env      string
	wantJobs []string
	wantErr  string
}

// The primary scan and annotate pass --scanner-jobs (or SCANOSS_SCANNER_JOBS)
// to the OpenGrep scan process, leave OpenGrep's default alone without either,
// and fail before scanning on an invalid value.
func TestScanScannerJobsReachOpenGrep(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}
	binary := buildProgressCryptoFinder(t)
	tests := []scannerJobsCase{
		{name: "default leaves OpenGrep's own jobs"},
		{name: "flag", flags: []string{"--scanner-jobs", "3"}, wantJobs: []string{"--jobs", "3"}},
		{name: "environment", env: "2", wantJobs: []string{"--jobs", "2"}},
		{name: "flag wins over environment", flags: []string{"--scanner-jobs=4"}, env: "2", wantJobs: []string{"--jobs", "4"}},
		{name: "invalid environment", env: "many", wantErr: "SCANOSS_SCANNER_JOBS must be a whole number of jobs"},
	}
	for _, command := range []string{"scan", "annotate"} {
		for _, tt := range tests {
			t.Run(command+"/"+tt.name, func(t *testing.T) {
				runScannerJobsCase(t, binary, command, tt)
			})
		}
	}
}

func runScannerJobsCase(t *testing.T, binary, command string, tt scannerJobsCase) {
	t.Helper()
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "scan-argv")
	writeProgressOpenGrepScript(t, filepath.Join(dir, "opengrep"), `printf '%s\n' "$@" > '`+argvLog+`'
printf '%s\n' '{"results":[],"errors":[]}'`)
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	env := slices.DeleteFunc(progressTestEnv(dir), func(entry string) bool { return strings.HasPrefix(entry, scannerJobsEnv+"=") })
	rules := []string{"--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml")}
	findings := filepath.Join(dir, "findings.json")

	var args []string
	if command == "scan" {
		args = slices.Concat([]string{"scan"}, rules, []string{"--output", findings}, tt.flags, []string{dir})
	} else {
		// annotate re-annotates a fragment that a scan exported first.
		fragment := filepath.Join(dir, "graph-fragment.json")
		setup := exec.CommandContext(t.Context(), binary, slices.Concat([]string{"scan"}, rules, []string{"--output", findings, "--export-graph-fragment", fragment, dir})...)
		setup.Env = env
		if output, err := setup.CombinedOutput(); err != nil {
			t.Fatalf("setup scan: %v\n%s", err, output)
		}
		if err := os.Remove(argvLog); err != nil {
			t.Fatal(err)
		}
		args = slices.Concat([]string{"annotate"}, rules, []string{"--import-fragment", fragment, "--source", dir, "--output", filepath.Join(dir, "annotation.json")}, tt.flags)
	}
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = env
	if tt.env != "" {
		cmd.Env = append(cmd.Env, scannerJobsEnv+"="+tt.env)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if tt.wantErr != "" {
		if err == nil || !strings.Contains(stderr.String(), tt.wantErr) {
			t.Fatalf("%s error = %v, want stderr to contain %q:\n%s", command, err, tt.wantErr, stderr.String())
		}
		if _, statErr := os.Stat(argvLog); statErr == nil {
			t.Fatal("OpenGrep ran despite an invalid job count")
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: %v\nstderr:\n%s", command, err, stderr.String())
	}
	data, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSpace(string(data)), "\n")
	var gotJobs []string
	if i := slices.Index(argv, "--jobs"); i >= 0 && i+1 < len(argv) {
		gotJobs = argv[i : i+2]
	}
	if !slices.Equal(gotJobs, tt.wantJobs) {
		t.Fatalf("OpenGrep jobs = %v, want %v in argv %v", gotJobs, tt.wantJobs, argv)
	}
}
