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

package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"maps"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

// languageRules covers every normalization case: mixed case and spaces, a
// rule without languages, duplicates across files, an upper-case extension,
// and files that are not read (not YAML, macOS metadata, filtered copies,
// paths outside the bundle).
var languageRules = map[string]string{
	"rules/java/aes.yaml": `rules:
  - id: a
    languages: [" Java ", PYTHON]
  - id: b
    languages: [java]
`,
	"rules/generic/any.YML": `rules:
  - id: c
    pattern: x
`,
	"rules/c/sha.yml": `rules:
  - id: d
    languages: [C]
`,
	"rules/README.md":                     "not: [a, rule",
	"rules/java/._aes.yaml":               "\x00\x01 not yaml: [",
	".crypto-finder-filtered/rust.yaml":   "rules:\n  - id: e\n    languages: [rust]\n",
	"rules/.crypto-finder-filtered/x.yml": "rules:\n  - id: f\n    languages: [ruby]\n",
	"../outside.yaml":                     "rules:\n  - id: g\n    languages: [php]\n",
}

var wantLanguages = []string{"c", "generic", "java", "python"}

func tarGzFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		content := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBundleLanguages(t *testing.T) {
	got, err := bundleLanguages(tarGzFiles(t, languageRules))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, wantLanguages) {
		t.Fatalf("bundleLanguages = %v, want %v", got, wantLanguages)
	}
}

func TestLanguages_EmptyAndInvalid(t *testing.T) {
	got, err := bundleLanguages(tarGzFiles(t, map[string]string{"rules/a.yaml": "rules: []\n"}))
	if err != nil || got != nil {
		t.Fatalf("no rules: got %v, %v; want nil, nil", got, err)
	}
	if _, err := bundleLanguages(tarGzFiles(t, map[string]string{"rules/a.yaml": "rules: [\n"})); err == nil {
		t.Fatal("invalid YAML: want an error")
	}
}

func TestLeased_MetadataRecordsLanguages(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", languageRules, time.Now().Add(30*24*time.Hour))
	srv := rulesettest.NewServer(t, issued)
	m := newLeasedManager(t, srv.URL)

	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := LoadMetadata(filepath.Join(path, metadataFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(meta.Languages, wantLanguages) {
		t.Fatalf("metadata languages = %v, want %v", meta.Languages, wantLanguages)
	}
	if got := yamlFilesUnder(t, m.cacheDir); len(got) != 0 {
		t.Fatalf("plaintext rule files in the cache: %v", got)
	}
}
