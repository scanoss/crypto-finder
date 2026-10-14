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

package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeTree writes files, a map of slash-relative path to content, under
// dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourceDigestNamesContentNotPlace(t *testing.T) {
	base := t.TempDir()
	lib := map[string]string{"index.js": "crypto.createHash('md5')", "lib/kdf.js": "pbkdf2()", "package.json": `{"version":"4.17.21"}`}
	digestOf := func(dir string, files map[string]string, listed, excluded []string) string {
		t.Helper()
		writeTree(t, dir, files)
		got, err := sourceDigest(dir, listed, excluded)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	same := digestOf(filepath.Join(base, "a", "node_modules", "lodash"), lib, nil, nil)
	if elsewhere := digestOf(filepath.Join(base, "deep", "er", "node_modules", "lodash"), lib, nil, nil); elsewhere != same {
		t.Fatal("the same files elsewhere must digest the same")
	}
	fork := map[string]string{"index.js": "crypto.createHash('md5')", "lib/kdf.js": "pbkdf2(); scrypt()", "package.json": `{"version":"4.17.21"}`}
	if forked := digestOf(filepath.Join(base, "fork", "node_modules", "lodash"), fork, nil, nil); forked == same {
		t.Fatal("other content at the same version must digest differently")
	}
	moved := map[string]string{"index.js": "crypto.createHash('md5')", "kdf.js": "pbkdf2()", "package.json": `{"version":"4.17.21"}`}
	if renamed := digestOf(filepath.Join(base, "moved", "node_modules", "lodash"), moved, nil, nil); renamed == same {
		t.Fatal("the same content at another path must digest differently")
	}
	// A nested install the scan excludes does not split the key.
	nested := filepath.Join(base, "nested", "node_modules", "lodash")
	withDep := digestOf(nested, lib, nil, []string{"node_modules"})
	writeTree(t, nested, map[string]string{"node_modules/x/index.js": "aes()"})
	got, err := sourceDigest(nested, nil, []string{"node_modules"})
	if err != nil {
		t.Fatal(err)
	}
	if got != withDep || withDep != same {
		t.Fatal("files under an excluded directory must not change the digest")
	}
	if unexcluded, _ := sourceDigest(nested, nil, nil); unexcluded == same {
		t.Fatal("without the exclusion the nested install is content")
	}
	// A symlink is not followed out of the dependency, but the dependency
	// directory itself is read through its own symlink.
	linked := filepath.Join(base, "linked", "node_modules", "lodash")
	writeTree(t, linked, lib)
	if err := os.Symlink(filepath.Join(base, "fork", "node_modules", "lodash", "lib"), filepath.Join(linked, "elsewhere")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(filepath.Join(base, "fork", "node_modules", "lodash", "index.js"), filepath.Join(linked, "elsewhere.js")); err != nil {
		t.Fatal(err)
	}
	if got, err := sourceDigest(linked, nil, nil); err != nil || got != same {
		t.Fatalf("symlinks must add nothing: digest=%q err=%v", got, err)
	}
	link := filepath.Join(base, "link-to-lodash")
	if err := os.Symlink(filepath.Join(base, "a", "node_modules", "lodash"), link); err != nil {
		t.Fatal(err)
	}
	if got, err := sourceDigest(link, nil, nil); err != nil || got != same {
		t.Fatalf("a dependency reached through a symlink digests its target: digest=%q err=%v", got, err)
	}
}

// A dependency listing its files digests only those: the files a Go
// program compiles, not the module's other packages.
func TestSourceDigestOfListedFiles(t *testing.T) {
	base := t.TempDir()
	module := map[string]string{"a.go": "package a", "a_windows.go": "package a", "other/o.go": "package other"}
	dir := filepath.Join(base, "gomod", "m@v1")
	writeTree(t, dir, module)
	listed, err := sourceDigest(dir, []string{filepath.Join(dir, "a.go")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := sourceDigest(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listed == whole {
		t.Fatal("the listed files are not the whole module")
	}
	writeTree(t, dir, map[string]string{"other/o.go": "package other // changed"})
	if again, _ := sourceDigest(dir, []string{filepath.Join(dir, "a.go")}, nil); again != listed {
		t.Fatal("a file the scan does not read must not change the digest")
	}
	writeTree(t, dir, map[string]string{"a.go": "package a // changed"})
	if again, _ := sourceDigest(dir, []string{filepath.Join(dir, "a.go")}, nil); again == listed {
		t.Fatal("a listed file's content must change the digest")
	}
	if _, err := sourceDigest(dir, []string{filepath.Join(dir, "missing.go")}, nil); err == nil {
		t.Fatal("a listed file that cannot be read must fail, not digest the rest")
	}
	if _, err := sourceDigest(filepath.Join(base, "absent"), nil, nil); err == nil {
		t.Fatal("a missing dependency directory must fail")
	}
}

func TestRootAnchoredDirs(t *testing.T) {
	got := rootAnchoredDirs([]string{"test/", "/deps/a/node_modules/", "/deps/a/vendor/x/", "/deps/a/file.js", "/deps/ab/node_modules/", "**/*Test.java"}, "/deps/a")
	if want := []string{"node_modules", "vendor/x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rootAnchoredDirs = %v, want %v", got, want)
	}
}

func TestSourceDigestIgnoresPythonBytecode(t *testing.T) {
	base := t.TempDir()
	hostA, hostB := filepath.Join(base, "a", "site-packages", "jwt"), filepath.Join(base, "b", "site-packages", "jwt")
	writeTree(t, hostA, map[string]string{"api_jws.py": "hmac.new()", "__pycache__/api_jws.cpython-313.pyc": "mtime-a"})
	writeTree(t, hostB, map[string]string{"api_jws.py": "hmac.new()", "__pycache__/api_jws.cpython-313.pyc": "mtime-b"})
	a, errA := sourceDigest(hostA, nil, nil)
	b, errB := sourceDigest(hostB, nil, nil)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if a != b {
		t.Fatal("one wheel compiled at different times must digest the same")
	}
}
