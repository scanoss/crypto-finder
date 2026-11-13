// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// literalFixture is a project whose crypto calls (each `consumers` text, which
// must occur once in its file) a rule reports as algorithm findings.
type literalFixture struct {
	ecosystem  string
	importPath string
	files      map[string]string
	consumers  map[string][]string
}

// literalMaterials scans the fixture's graph the way a scan with a call graph
// does and returns, sorted, every related material asset as
// "file:line:material".
func literalMaterials(t *testing.T, fx literalFixture) []string {
	t.Helper()
	return literalMaterialsWith(t, fx, nil)
}

// literalMaterialsWith is literalMaterials with edit applied to each consumer
// asset before the pass runs.
func literalMaterialsWith(t *testing.T, fx literalFixture, edit func(*entities.CryptographicAsset)) []string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range fx.files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var b *callgraph.Builder
	if fx.ecosystem == ecosystemJava {
		b = callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser())
	} else {
		b = callgraph.NewBuilderForEcosystem(fx.ecosystem, callgraph.NewParserForEcosystem(fx.ecosystem))
		b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem(fx.ecosystem, javaruntime.Config{}))
	}
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: fx.importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{}
	for name, texts := range fx.consumers {
		finding := entities.Finding{FilePath: name, Language: fx.ecosystem}
		src := fx.files[name]
		for _, text := range texts {
			if strings.Count(src, text) != 1 {
				t.Fatalf("consumer %q must occur once in %s", text, name)
			}
			for i, line := range strings.Split(src, "\n") {
				if c := strings.Index(line, text); c >= 0 {
					finding.CryptographicAssets = append(finding.CryptographicAssets, entities.CryptographicAsset{
						StartLine: i + 1, EndLine: i + 1, StartCol: c + 1, EndCol: c + 1 + len(text),
						Match:    text,
						Rules:    []entities.RuleInfo{{ID: "test.crypto.consumer"}},
						Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "kdf"},
					})
					break
				}
			}
		}
		if edit != nil {
			for i := range finding.CryptographicAssets {
				edit(&finding.CryptographicAssets[i])
			}
		}
		report.Findings = append(report.Findings, finding)
	}
	MaterializeRelatedMaterial(report, &engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: fx.ecosystem,
	})
	var got []string
	for _, f := range report.Findings {
		for i := range f.CryptographicAssets {
			a := &f.CryptographicAssets[i]
			if a.Metadata["assetType"] != "related-crypto-material" {
				continue
			}
			if len(a.Rules) != 1 || a.Rules[0].ID != "test.crypto.consumer" || len(a.Metadata) != 2 {
				t.Errorf("material %+v does not carry the consumer's rule and only the material metadata", a)
			}
			got = append(got, fmt.Sprintf("%s:%d:%s", filepath.ToSlash(f.FilePath), a.StartLine, a.Metadata["materialType"]))
		}
	}
	slices.Sort(got)
	return got
}

const pythonLiteralKdf = `import hashlib


def pbkdf2_sha1(password, salt, iterations, key_length):
    return hashlib.pbkdf2_hmac('sha1', password, salt, iterations, key_length)


class Keys:
    @staticmethod
    def derive_key(password):
        return pbkdf2_sha1(password, salt=b'fixedsalt', iterations=1, key_length=16)


def positional(password):
    return pbkdf2_sha1(password, b' ' * 16, 1, 16)


def forward(password, salt):
    return pbkdf2_sha1(password, salt, 1, 16)


def outer(password):
    return forward(password, b'outer-salt')


def computed(password, prefix):
    return pbkdf2_sha1(password, prefix + b'x', 1, 16)


def rebinding(password, salt):
    salt = salt + b'pepper'
    return hashlib.pbkdf2_hmac('sha256', password, salt, 1000)


def call_rebinding(password):
    return rebinding(password, b'never-reported')


def defaulted(password, salt=b'default-salt'):
    return hashlib.pbkdf2_hmac('sha512', password, salt, 1000)


def drawn(password, salt):
    return pbkdf2_sha1(password, salt, 1, 16)
`

const pythonLiteralCaller = `from app.kdf import pbkdf2_sha1


def check():
    return pbkdf2_sha1(b'peanuts', b'\x00' * 16, 1, 16)
`

const nodeLiteralSource = `const crypto = require('crypto');

function prf(key, data) {
  const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
  return cipher.update(data);
}

function ecb(key, data) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return cipher.update(data);
}

function derive(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256');
}

function run(password) {
  return derive(password, 'static-salt');
}

function runComputed(password, user) {
  return derive(password, user.id);
}

module.exports = { prf, ecb, run, runComputed };
`

const tsLiteralSource = `import { createCipheriv } from "node:crypto";

export function mac(key: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(16));
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
`

func TestMaterializeRelatedMaterial_Literals(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		fx   literalFixture
		want []string
	}{
		"python literal salt through a project helper": {
			fx: literalFixture{
				ecosystem: ecosystemPython, importPath: "app",
				files: map[string]string{"app/kdf.py": pythonLiteralKdf, "app/check.py": pythonLiteralCaller},
				consumers: map[string][]string{"app/kdf.py": {
					"hashlib.pbkdf2_hmac('sha1'", "hashlib.pbkdf2_hmac('sha256'", "hashlib.pbkdf2_hmac('sha512'",
				}},
			},
			want: []string{
				"app/check.py:5:salt",
				"app/kdf.py:11:salt",
				"app/kdf.py:15:salt",
				"app/kdf.py:23:salt",
				"app/kdf.py:39:salt",
			},
		},
		"node literal iv at the call and literal salt through a helper": {
			fx: literalFixture{
				ecosystem: ecosystemNode, importPath: "app",
				files: map[string]string{"a.js": nodeLiteralSource},
				consumers: map[string][]string{"a.js": {
					"crypto.createCipheriv('aes-128-cbc'", "crypto.createCipheriv('aes-128-ecb'", "crypto.pbkdf2Sync(",
				}},
			},
			want: []string{"a.js:18:salt", "a.js:4:initialization-vector"},
		},
		"typescript literal iv with a named import": {
			fx: literalFixture{
				ecosystem: ecosystemNode, importPath: "app",
				files:     map[string]string{"mac.ts": tsLiteralSource},
				consumers: map[string][]string{"mac.ts": {`createCipheriv("aes-128-cbc"`}},
			},
			want: []string{"mac.ts:4:initialization-vector"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := literalMaterials(t, tc.fx); !slices.Equal(got, tc.want) {
				t.Errorf("materials = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMaterializeRelatedMaterial_LiteralKeepsRuleMaterial: a rule that
// already reported the literal as material keeps the only asset at its line.
func TestMaterializeRelatedMaterial_LiteralKeepsRuleMaterial(t *testing.T) {
	t.Parallel()
	fx := literalFixture{
		ecosystem: ecosystemNode, importPath: "app",
		files:     map[string]string{"mac.ts": tsLiteralSource},
		consumers: map[string][]string{"mac.ts": {`createCipheriv("aes-128-cbc"`, "Buffer.alloc(16)"}},
	}
	// The second consumer stands for the rule's own iv finding at the literal.
	got := literalMaterialsWith(t, fx, func(a *entities.CryptographicAsset) {
		if a.Match == "Buffer.alloc(16)" {
			a.Metadata = map[string]string{"assetType": "related-crypto-material", "materialType": "initialization-vector"}
		}
	})
	if want := []string{"mac.ts:4:initialization-vector"}; !slices.Equal(got, want) {
		t.Errorf("materials = %q, want %q", got, want)
	}
}
