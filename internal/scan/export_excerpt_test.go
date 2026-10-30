// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// numberedSource is a file of n lines, "line 1" to "line n".
func numberedSource(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func writeSource(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// excerptFixture is a project root and one dependency source directory, and an
// excerpt reader over them that counts its reads.
type excerptFixture struct {
	project, dependency string
	reads               map[string]int
	excerpts            *sourceExcerpts
}

func newExcerptFixture(t *testing.T) *excerptFixture {
	t.Helper()
	f := &excerptFixture{project: t.TempDir(), dependency: t.TempDir(), reads: map[string]int{}}
	artifacts := newExportArtifacts(&engine.DepScanResult{
		ProjectRoot:  f.project,
		Dependencies: []dependency.Dependency{{Module: "org.lib:lib", Version: "1.0", Dir: f.dependency}},
	})
	f.excerpts = newSourceExcerpts(&artifacts, func(path string) ([]byte, error) {
		f.reads[path]++
		return os.ReadFile(path)
	})
	return f
}

func lineRange(first, last int) []string {
	lines := make([]string, 0, last-first+1)
	for i := first; i <= last; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	return lines
}

// TestSourceExcerpts_WindowClipsToTheFile: the window is the focus line and
// three lines either side, cut short at the start and end of the file.
func TestSourceExcerpts_WindowClipsToTheFile(t *testing.T) {
	t.Parallel()
	f := newExcerptFixture(t)
	path := filepath.Join(f.project, "App.java")
	writeSource(t, path, numberedSource(10))
	for _, tc := range []struct {
		focus int
		want  graphfrag.ExportExcerpt
	}{
		{5, graphfrag.ExportExcerpt{StartLine: 2, FocusLine: 5, Lines: lineRange(2, 8)}},
		{1, graphfrag.ExportExcerpt{StartLine: 1, FocusLine: 1, Lines: lineRange(1, 4)}},
		{10, graphfrag.ExportExcerpt{StartLine: 7, FocusLine: 10, Lines: lineRange(7, 10)}},
	} {
		got, unavailable := f.excerpts.excerpt(path, tc.focus)
		if unavailable != "" || got == nil || !reflect.DeepEqual(*got, tc.want) {
			t.Errorf("excerpt(focus %d) = %+v, %q; want %+v", tc.focus, got, unavailable, tc.want)
		}
	}
	for _, focus := range []int{0, 11} {
		if got, unavailable := f.excerpts.excerpt(path, focus); got != nil || unavailable != graphfrag.ExcerptOutOfRange {
			t.Errorf("excerpt(focus %d) = %+v, %q; want out_of_range", focus, got, unavailable)
		}
	}
}

// TestSourceExcerpts_CapsLongLinesByRune: a line longer than the cap keeps
// its first 240 characters, whole, and the excerpt says it was cut; CRLF line
// endings are not part of a line.
func TestSourceExcerpts_CapsLongLinesByRune(t *testing.T) {
	t.Parallel()
	f := newExcerptFixture(t)
	path := filepath.Join(f.project, "Wide.java")
	long := strings.Repeat("é", 300)
	writeSource(t, path, "short\r\n"+long+"\r\n")
	got, _ := f.excerpts.excerpt(path, 2)
	if got == nil || !got.Truncated || len(got.Lines) != 2 {
		t.Fatalf("excerpt = %+v, want two lines, truncated", got)
	}
	if got.Lines[0] != "short" || got.Lines[1] != strings.Repeat("é", graphfrag.ExcerptLineMaxRunes) {
		t.Errorf("lines = %q (%d runes), want short and 240 runes of é", got.Lines[0], len([]rune(got.Lines[1])))
	}
	if whole, _ := f.excerpts.excerpt(path, 1); whole == nil || whole.Truncated != true {
		t.Errorf("window over the long line = %+v, want truncated", whole)
	}
}

// TestSourceExcerpts_ReadsOnlyResolvedRoots: a file outside the project and
// the dependency source directories has no excerpt and is never read, whether
// the graph names it directly, through "..", or through a symlink inside the
// project; a dependency file is read.
func TestSourceExcerpts_ReadsOnlyResolvedRoots(t *testing.T) {
	t.Parallel()
	f := newExcerptFixture(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	writeSource(t, outside, numberedSource(5))
	if err := os.Symlink(outside, filepath.Join(f.project, "link.txt")); err != nil {
		t.Fatal(err)
	}
	inDependency := filepath.Join(f.dependency, "org", "lib", "Hash.java")
	writeSource(t, inDependency, numberedSource(5))

	for _, path := range []string{
		outside,
		f.project + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(filepath.Dir(outside)) + string(filepath.Separator) + "secret.txt",
		filepath.Join(f.project, "link.txt"),
		"",
	} {
		if got, unavailable := f.excerpts.excerpt(path, 2); got != nil || unavailable != graphfrag.ExcerptNoSource {
			t.Errorf("excerpt(%q) = %+v, %q; want no_source", path, got, unavailable)
		}
	}
	if len(f.reads) != 0 {
		t.Errorf("read %v, want nothing outside the roots read", f.reads)
	}
	if got, unavailable := f.excerpts.excerpt(inDependency, 2); got == nil || unavailable != "" {
		t.Errorf("dependency file excerpt = %+v, %q; want one", got, unavailable)
	}
}

// TestSourceExcerpts_UnreadableFile: a path under a root that cannot be read
// as a file says so.
func TestSourceExcerpts_UnreadableFile(t *testing.T) {
	t.Parallel()
	f := newExcerptFixture(t)
	dir := filepath.Join(f.project, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, unavailable := f.excerpts.excerpt(dir, 1); got != nil || unavailable != graphfrag.ExcerptUnreadable {
		t.Errorf("excerpt(dir) = %+v, %q; want unreadable", got, unavailable)
	}
}

// excerptChainContext is an export context over the excerpt fixture's roots.
func excerptChainContext(f *excerptFixture) *exportBuildContext {
	ctx := newExportPathContext(&engine.DepScanResult{
		ProjectRoot:  f.project,
		Dependencies: []dependency.Dependency{{Module: "org.lib:lib", Version: "1.0", Dir: f.dependency}},
	})
	ctx.excerptSource = f.excerpts
	return ctx
}

// TestAttachChainExcerpts_FocusesWhereTheChainMovesOn: the root and middle
// frames focus on the call into the next frame, the last frame on the crypto
// call, and a frame with neither on its first line. A file the chain visits
// twice is read once, and a dependency frame whose file the scan has no source
// for (a dependency joined for its types only) reads no_source.
func TestAttachChainExcerpts_FocusesWhereTheChainMovesOn(t *testing.T) {
	t.Parallel()
	f := newExcerptFixture(t)
	app := filepath.Join(f.project, "App.java")
	lib := filepath.Join(f.dependency, "Lib.java")
	writeSource(t, app, numberedSource(40))
	writeSource(t, lib, numberedSource(40))
	typesOnly := filepath.Join(t.TempDir(), "types", "Types.java")
	writeSource(t, typesOnly, numberedSource(40))

	chain := []callGraphChainNode{
		{StartLine: 3, sourcePath: app},
		{StartLine: 10, sourcePath: lib, EntryCall: &callGraphEntryCall{Line: 5}},
		{StartLine: 20, sourcePath: app, EntryCall: &callGraphEntryCall{Line: 12}},
		{StartLine: 30, sourcePath: typesOnly, EntryCall: &callGraphEntryCall{Line: 24}},
		{StartLine: 33, sourcePath: app, CryptoCall: &callGraphCalledFunction{Line: 35}},
	}
	lonely := []callGraphChainNode{{StartLine: 8, sourcePath: lib}}
	attachChainExcerpts(excerptChainContext(f), [][]callGraphChainNode{chain, lonely})

	for i, want := range []int{5, 12, 24, 0, 35} {
		frame := chain[i]
		if want == 0 {
			if frame.Excerpt != nil || frame.ExcerptUnavailable != graphfrag.ExcerptNoSource {
				t.Errorf("frame %d = %+v, %q; want no_source", i, frame.Excerpt, frame.ExcerptUnavailable)
			}
			continue
		}
		if frame.Excerpt == nil || frame.Excerpt.FocusLine != want || frame.ExcerptUnavailable != "" {
			t.Errorf("frame %d excerpt = %+v, %q; want focus line %d", i, frame.Excerpt, frame.ExcerptUnavailable, want)
		}
	}
	if got := lonely[0].Excerpt; got == nil || got.FocusLine != 8 {
		t.Errorf("single frame excerpt = %+v, want focus on its start line 8", got)
	}
	if f.reads[app] != 1 || f.reads[lib] != 1 || len(f.reads) != 2 {
		t.Errorf("reads = %v, want App.java and Lib.java once each", f.reads)
	}
}
