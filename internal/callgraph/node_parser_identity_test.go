// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// Two files in one directory, each declaring a same-named function, must each
// keep an identity of their own.
//
// A Node file IS a module: `src/alpha.js` and `src/beta.js` are different
// modules whatever they call their exports, and `index.js` plus `utils.js` each
// carrying a `hash()` is routine layout. Keying the identity on the DIRECTORY
// alone collapses them, and the loser does not merely lose its key — its
// findings come back `no_containing_function`, so the call site is reported with
// no reachability at all.
func TestNodeParser_SameNamedFunctionsInOneDirectoryKeepDistinctIdentities(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	alpha := `import crypto from "node:crypto";
export function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
`
	beta := `import crypto from "node:crypto";
export function hash(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}
`
	if err := os.WriteFile(filepath.Join(dir, "alpha.js"), []byte(alpha), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beta.js"), []byte(beta), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewNodeParser().ParseDirectory(dir, "example-app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 2 {
		t.Fatalf("analyses = %d, want 2", len(analyses))
	}

	keys := map[string]string{} // identity key -> file it came from
	for _, a := range analyses {
		for i := range a.Functions {
			fn := &a.Functions[i]
			if fn.ID.Name != "hash" && fn.ID.Name != "" {
				continue
			}
			k := fn.ID.Package + "|" + fn.ID.Type + "|" + fn.ID.Name
			if prev, clash := keys[k]; clash {
				t.Errorf("identity %q is shared by %s and %s; a Node file is its own module",
					k, prev, fn.FilePath)
			}
			keys[k] = fn.FilePath
		}
	}
	if len(keys) != 2 {
		t.Errorf("distinct hash identities = %d, want 2 (one per file); got %v", len(keys), keys)
	}
}

// Methods must be discovered wherever JavaScript lets them be written, not only
// inside a `class_declaration`. Dispatching on `class_declaration` alone leaves
// three idiomatic shapes binding no containing function: each matches at the
// rule layer and then resolves to nothing, which is the same silent loss as the
// identity collision above — the call is reported with no reachability.
func TestNodeParser_MethodsOutsideClassDeclarationsBindAFunction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "class expression bound to a const",
			src: `import crypto from "node:crypto";
export const Hasher = class {
  run(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
};
`,
			want: "run",
		},
		{
			name: "shorthand method in an object literal",
			src: `import crypto from "node:crypto";
export const hasher = {
  run(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
};
`,
			want: "run",
		},
		{
			name: "class field initialiser",
			src: `import crypto from "node:crypto";
export class Hasher {
  digest = crypto.createHash("sha256");
}
`,
			want: "digest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "mod.js"), []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewNodeParser().ParseDirectory(dir, "example-app")
			if err != nil {
				t.Fatalf("ParseDirectory: %v", err)
			}
			if len(analyses) != 1 {
				t.Fatalf("analyses = %d, want 1", len(analyses))
			}
			if len(analyses[0].Functions) == 0 {
				t.Fatalf("no function bound; the crypto call has no containing function")
			}
		})
	}
}

// A dotfile named exactly ".js" must not adopt the key of the same-named module
// in its parent directory: trimming the extension empties the base, and an empty
// base falls back to the package path.
func TestNodeParser_DotfileModuleDoesNotCollideWithItsParentDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	const body = "import crypto from \"node:crypto\";\n" +
		"export function x(d){ return crypto.createHash(\"sha256\").update(d).digest(\"hex\"); }\n"
	if err := os.WriteFile(filepath.Join(dir, "b.js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b", ".js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	parser := NewNodeParser()
	keys := map[string]string{}
	for d, imp := range map[string]string{dir: "a", filepath.Join(dir, "b"): "a/b"} {
		analyses, err := parser.ParseDirectory(d, imp)
		if err != nil {
			t.Fatalf("ParseDirectory(%s): %v", d, err)
		}
		for _, a := range analyses {
			for _, fn := range a.Functions {
				key := fn.ID.Package + "|" + fn.ID.Type + "|" + fn.ID.Name
				if prev, dup := keys[key]; dup {
					t.Fatalf("identity %q shared by %s and %s", key, prev, a.FilePath)
				}
				keys[key] = a.FilePath
			}
		}
	}
	if len(keys) != 2 {
		t.Fatalf("functions = %d, want 2", len(keys))
	}
}
