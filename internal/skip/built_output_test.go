// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package skip

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeFiles(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("// x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A published npm tarball is not a checkout. `dist` and `build` are generated
// noise BESIDE sources in a repository, and they are the package itself when
// they are all that was published -- which is the modern default for TypeScript.
//
// Measured on @azure/cosmos 4.10.1, which ships only dist/: the same scan
// reported 0 findings with the exclusion and 6 without it. A zero that means
// "nobody read the tree" is indistinguishable from one that means "no
// cryptography here", and the second is what reaches a coverage tracker.
func TestBuiltOutputOnlySource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{
			name:  "a published package that shipped only dist",
			files: []string{"package.json", "dist/index.js", "dist/keys/rsa.js"},
			want:  []string{"dist"},
		},
		{
			name:  "a published package that shipped only build",
			files: []string{"package.json", "build/index.js"},
			want:  []string{"build"},
		},
		{
			name:  "both, when both are all there is",
			files: []string{"dist/a.js", "build/b.js"},
			want:  []string{"build", "dist"},
		},
		{
			name:  "a checkout keeps its exclusions: source sits beside dist",
			files: []string{"src/index.ts", "dist/index.js"},
			want:  nil,
		},
		{
			name:  "one source file outside is enough to keep the exclusion",
			files: []string{"index.js", "dist/index.js", "dist/b.js", "dist/c.js"},
			want:  nil,
		},
		{
			name:  "source in another language still counts as source",
			files: []string{"lib/thing.py", "dist/index.js"},
			want:  nil,
		},
		{
			name:  "non-code files outside do NOT count as source",
			files: []string{"package.json", "README.md", "LICENSE", "dist/index.js"},
			want:  []string{"dist"},
		},
		{
			name:  "nothing to rescue when the tree holds no code at all",
			files: []string{"package.json", "README.md"},
			want:  nil,
		},
		{
			name:  "installed dependencies do not cancel the rescue",
			files: []string{"package.json", "dist/index.js", "node_modules/left-pad/index.js"},
			want:  []string{"dist"},
		},
		{
			name:  "a type declaration is not source: it holds no executable code",
			files: []string{"package.json", "index.d.ts", "dist/index.js"},
			want:  []string{"dist"},
		},
		{
			name:  "source the scan itself excludes cannot keep an exclusion",
			files: []string{"package.json", "test/t.js", "dist/index.js"},
			want:  []string{"dist"},
		},
		{
			name:  "a vendored copy is not this package's source",
			files: []string{"dist/index.js", "vendor/other/a.go"},
			want:  []string{"dist"},
		},
		{
			name:  "a hidden directory is not source either",
			files: []string{"dist/index.js", ".github/scripts/release.js"},
			want:  []string{"dist"},
		},
		{
			name:  "a nested dist inside real source is left excluded",
			files: []string{"src/a.ts", "packages/x/src/b.ts", "packages/x/dist/b.js"},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuiltOutputOnlySource(writeFiles(t, tc.files...))
			slices.Sort(got)
			if len(got) != len(tc.want) {
				t.Fatalf("BuiltOutputOnlySource = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("BuiltOutputOnlySource = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// The rescued names must actually leave the pattern list, or the walk still
// skips them and the fix is decorative.
func TestDefaultPatternsForTargetDropsOnlyTheRescuedNames(t *testing.T) {
	t.Parallel()

	root := writeFiles(t, "package.json", "dist/index.js")
	got := DefaultPatternsForTarget(root)

	if slices.Contains(got, "dist") {
		t.Error("dist is still excluded although it holds the only source")
	}
	for _, keep := range []string{"node_modules", "vendor", "build", "docs", "target"} {
		if !slices.Contains(got, keep) {
			t.Errorf("%q was dropped from the defaults; only the rescued name may go", keep)
		}
	}
}

func TestDefaultPatternsForTargetIsUnchangedForACheckout(t *testing.T) {
	t.Parallel()

	root := writeFiles(t, "src/index.ts", "dist/index.js")
	got := DefaultPatternsForTarget(root)
	want := DefaultPatterns()
	// Compared element by element: equal LENGTHS would also hold for an
	// implementation that dropped one name and added another.
	if !slices.Equal(got, want) {
		t.Errorf("a checkout's default patterns changed; they must not.\n got=%v\nwant=%v", got, want)
	}
}

// The target spelling is whatever the operator typed -- `./pkg`, `pkg/`,
// `pkg//`, an absolute path. WalkDir joins (and so CLEANS) every child path,
// so a walk-relative path has to come from filepath.Rel: trimming the raw
// spelling as a prefix matches nothing for four of these six, every file then
// reads as top level, and the rescue silently never fires for the most common
// way to name a directory.
func TestBuiltOutputOnlySourceIgnoresTargetSpelling(t *testing.T) {
	t.Parallel()

	root := writeFiles(t, "package.json", "dist/index.js")
	base := filepath.Base(root)
	parent := filepath.Dir(root)

	for _, spelling := range []string{
		root,
		root + string(filepath.Separator),
		root + string(filepath.Separator) + ".",
		root + string(filepath.Separator) + string(filepath.Separator),
		filepath.Join(parent, ".", base),
		filepath.Join(parent, base, "..", base),
	} {
		if got := BuiltOutputOnlySource(spelling); !slices.Equal(got, []string{"dist"}) {
			t.Errorf("BuiltOutputOnlySource(%q) = %v, want [dist]", spelling, got)
		}
	}
}

// Pointing the scanner AT the built output is an explicit instruction to read
// it. The CLI maps a file target to its parent directory, so `scan pkg/dist`
// and `scan pkg/dist/index.js` both arrive here as pkg/dist -- where every
// file is top level and would otherwise read as source outside any built
// output, leaving the operator the same silent zero.
func TestBuiltOutputOnlySourceWhenTheTargetIsTheBuiltOutput(t *testing.T) {
	t.Parallel()

	root := writeFiles(t, "package.json", "dist/index.js", "dist/keys/rsa.js")

	if got := BuiltOutputOnlySource(filepath.Join(root, "dist")); !slices.Equal(got, []string{"dist"}) {
		t.Errorf("BuiltOutputOnlySource(<root>/dist) = %v, want [dist]", got)
	}
	// An empty built-output directory has nothing to rescue.
	empty := filepath.Join(t.TempDir(), "dist")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := BuiltOutputOnlySource(empty); got != nil {
		t.Errorf("BuiltOutputOnlySource(empty dist) = %v, want nil", got)
	}
}

// A walk that could not finish has a PARTIAL picture, and a partial picture is
// indistinguishable from "dist is all there is". Acting on it scans a plain
// checkout's generated output. Both ways a walk can be cut short must abstain.
func TestBuiltOutputOnlySourceAbstainsWhenTheWalkCannotFinish(t *testing.T) {
	t.Parallel()

	t.Run("an unreadable directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0o000 directory, so the error path cannot be provoked")
		}
		// `noread` sorts after `dist` and before `src`, so the walk collects
		// dist and then fails -- the exact order that produces a false rescue.
		root := writeFiles(t, "package.json", "dist/bundle.js", "noread/a.js", "src/index.ts")
		blocked := filepath.Join(root, "noread")
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

		if got := BuiltOutputOnlySource(root); got != nil {
			t.Errorf("BuiltOutputOnlySource = %v, want nil: the walk never saw src/", got)
		}
	})

	t.Run("a tree past the entry cap", func(t *testing.T) {
		root := writeFiles(t, "dist/a.js", "dist/b.js", "dist/c.js", "src/index.ts")
		// `dist` sorts before `src`, so a cap that binds mid-walk sees only
		// the built output. The cap is passed in rather than written out as
		// 50k files, and rather than mutated on a shared variable.
		if got := builtOutputOnlySource(root, 3); got != nil {
			t.Errorf("BuiltOutputOnlySource = %v, want nil: the walk stopped before src/", got)
		}
	})

	t.Run("a target that does not exist", func(t *testing.T) {
		if got := BuiltOutputOnlySource(filepath.Join(t.TempDir(), "absent")); got != nil {
			t.Errorf("BuiltOutputOnlySource = %v, want nil", got)
		}
	})
}
