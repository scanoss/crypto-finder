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

package opengrep

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestRootExcludes pins how exclude patterns follow the engine into the
// base directory. Before the engine ran there, opengrep matched **/P and
// **/P/** against paths starting with the target as given, so a scan of
// ./proj excluded proj/third/x.go for --exclude proj/third (verified with
// opengrep 1.29.0 for the targets proj, ./proj and its absolute path). In
// the base the engine holds third/x.go, which only "third" matches.
func TestRootExcludes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	named, dir := "/cwd/proj", "/real/proj"
	patterns := []string{"proj/third", "proj/third/", "./proj/third", "test/", "**/gen", "/real/proj/node_modules/", "/cwd/proj/dist"}
	got, err := rootExcludes(patterns, "/cwd", named, dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"third", "third/", "third", "test/", "**/gen", "node_modules/", "dist"}; !reflect.DeepEqual(got, want) {
		t.Errorf("excludes = %v, want %v", got, want)
	}
	if _, err := rootExcludes([]string{"/elsewhere/third"}, "/cwd", named, dir); err == nil {
		t.Error("an absolute pattern outside the target must fail")
	}
	// Without a working directory the process's own resolves the pattern,
	// as it resolves the target.
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	got, err = rootExcludes([]string{"proj/third"}, "", filepath.ToSlash(filepath.Join(cwd, "proj")), dir)
	if err != nil || !reflect.DeepEqual(got, []string{"third"}) {
		t.Errorf("excludes = %v, %v, want [third]", got, err)
	}
}

// A pattern written relative to the working directory that names a
// directory below a root reaches that root's process relative to the root,
// and the other roots' processes as written.
func TestScanRoots_RelativeExcludeBelowARootIsNamedRelativeToIt(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdirs(t, a, b)
	exe := fakeOpengrep(t, dir, nil)
	s := batchScanner(t, exe, "a/third/", "test/")
	s.workDir = dir
	if _, err := s.ScanRoots(context.Background(), dirRoots(a, b), rulesFixture(t, dir), entities.ToolInfo{Name: "fixture"}); err != nil {
		t.Fatal(err)
	}
	calls := recordedCalls(t, dir)
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want one process per root", calls)
	}
	want := [][]string{{"third/", "test/"}, {"a/third/", "test/"}}
	for i, c := range calls {
		if got := excludesOf(c.argv); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("call %d: excludes = %v, want %v", i, got, want[i])
		}
	}
}
