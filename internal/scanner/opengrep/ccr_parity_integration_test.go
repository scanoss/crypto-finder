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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
)

// The tests below pin CLI parity of core mode and the import prefilter for
// C, C++ and Rust on fixtures shaped like the projects that showed
// differences in benchmarks. They need opengrep and opengrep-core 1.30.2
// but no parity paths: rules and code are inline.

// cIncludeRule is the shape of most C/C++ rules: an include of the library
// (matched through a metavariable regex) before the call.
const cIncludeRule = `- id: %s
  message: m
  severity: INFO
  languages: [c, cpp]
  patterns:
    - pattern-inside: |
        #include "$HEADER"
        ...
    - metavariable-regex:
        metavariable: $HEADER
        regex: '%s'
    - pattern: $FUNC(...)
    - metavariable-regex:
        metavariable: $FUNC
        regex: '%s'
    - focus-metavariable: $FUNC
`

// requireRulesKept fails when the prefilter, given every target of dir as
// one unit, drops one of the rule ids (unprefixed) or keeps one of dropped.
func requireRulesKept(t *testing.T, dir, rulePath string, kept, dropped []string) {
	t.Helper()
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := loadCoreRuleset([]string{rulePath}, cwd)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := enumerateTargets(context.Background(), targetOptions{targets: []string{dir}, includeGitIgnored: true, maxTargetBytes: defaultMaxTargetBytes}, languagesOf(ruleset.rules))
	if err != nil {
		t.Fatal(err)
	}
	inspection := inspectTargets(plan, true)
	inputs := make([]prefilter.Rule, len(ruleset.rules))
	for i, rule := range ruleset.rules {
		inputs[i] = prefilter.Rule{Analyzers: rule.analyzers(), Requirement: rule.requirement()}
	}
	keep, _ := prefilter.Decide(inputs, inspection.evidence)
	decided := make(map[string]bool, len(ruleset.rules))
	for i, rule := range ruleset.rules {
		decided[rule.id[strings.LastIndex(rule.id, ".")+1:]] = keep[i]
	}
	for _, id := range kept {
		if keepRule, ok := decided[id]; !ok || !keepRule {
			t.Errorf("prefilter drops %s (known %v)", id, ok)
		}
	}
	for _, id := range dropped {
		if decided[id] {
			t.Errorf("prefilter keeps %s, whose library no file includes", id)
		}
	}
}

func sprintfRule(id, header, function string) string {
	return fmt.Sprintf(cIncludeRule, id, header, function)
}

func writeRules(t *testing.T, root string, rules ...string) string {
	t.Helper()
	body := "rules:\n"
	for _, rule := range rules {
		body += rule
	}
	writeTree(t, root, map[string]string{"rules/c/rules.yaml": body})
	return mergeRulesLikeMaterializer(t, filepath.Join(root, "rules"))
}

// TestCCRParityCOpensshIncludes reproduces openssh-portable: sources reach
// OpenSSL through local wrapper headers ("includes.h",
// "openbsd-compat/openssl-compat.h") and conditional includes, and the DH
// rules that went missing in benchmarks match calls with no include in their
// patterns. Those rules have an unknown requirement and are always kept; the
// include rules are kept because some unit file includes the header. The
// benchmark losses were rule timeouts on a loaded host, not the prefilter.
func TestCCRParityCOpensshIncludes(t *testing.T) {
	checkOpengrepAvailable(t)
	root := t.TempDir()
	rulePath := writeRules(t, root,
		"- id: dh-low-level\n  message: m\n  severity: INFO\n  languages: [c, cpp]\n  patterns:\n    - pattern: $API(...)\n    - metavariable-regex:\n        metavariable: $API\n        regex: ^(?:DH_new|DH_generate_key|DH_compute_key)$\n",
		sprintfRule("openssl-ecdh", `^<?(?:[\w.\-/]*/)?openssl/[\w/]+\.h>?$`, `^(?:ECDH_compute_key|EC_POINT_new)$`),
		sprintfRule("openssl-evp", `^<?(?:[\w.\-/]*/)?openssl/[\w/]+\.h>?$`, `^EVP_\w+$`),
		sprintfRule("wolfssl-aes", `^<?wolfssl/wolfcrypt/aes\.h>?$`, `^wc_AesInit$`),
	)
	src := filepath.Join(root, "src")
	writeTree(t, src, map[string]string{
		"includes.h": "#ifndef INCLUDES_H\n#define INCLUDES_H\n#include \"config.h\"\n#ifdef WITH_OPENSSL\n# include <openssl/opensslv.h>\n#endif\n#endif\n",
		"config.h":   "#define WITH_OPENSSL 1\n",
		"openbsd-compat/openssl-compat.h": "#ifdef WITH_OPENSSL\n#include <openssl/evp.h>\n#include <openssl/ec.h>\n" +
			"#endif\n",
		"dh.c": "#include \"includes.h\"\n#ifdef WITH_OPENSSL\n#include \"openbsd-compat/openssl-compat.h\"\n#include <openssl/bn.h>\n#  include <openssl/dh.h>\n\n" +
			"int dh_gen(void) {\n\tDH *dh = DH_new();\n\tif (DH_generate_key(dh) == 0)\n\t\treturn -1;\n\treturn DH_compute_key(0, 0, dh);\n}\n#endif\n",
		"regress/misc/sk-dummy/sk-dummy.c": "#include \"includes.h\"\n#include \"openbsd-compat/openssl-compat.h\"\n#ifdef WITH_OPENSSL\n#include <openssl/ecdh.h>\n#endif\n\n" +
			"int pack(void *k) {\n\tvoid *p = EC_POINT_new(k);\n\treturn ECDH_compute_key(0, 0, p, k, 0);\n}\n",
		"digest.c": "#include \"includes.h\"\n#include \"openbsd-compat/openssl-compat.h\"\n\nint d(void) {\n\treturn EVP_DigestInit(0, EVP_sha256());\n}\n",
	})
	requireRulesKept(t, src, rulePath, []string{"dh-low-level", "openssl-ecdh", "openssl-evp"}, []string{"wolfssl-aes"})
	// Three DH calls in dh.c and two ECDH calls in sk-dummy.c. digest.c
	// reaches OpenSSL only through a wrapper header, which a pattern-inside
	// include does not see in the CLI either.
	if n := requireModeParity(context.Background(), t, src, rulePath); n != 5 {
		t.Fatalf("the CLI found %d findings, want 5", n)
	}
}

// TestCCRParityCppCLanguageRules reproduces cryptopp: .cpp sources and .h
// headers under rules with languages [c, cpp] (a taint rule like the Nettle
// curve25519 one) and [c] only. The CLI analyzes .cpp as C++ only and .h as
// both, and core mode must select the same targets: the benchmark's 84 extra
// findings on donna_64.cpp/donna_sse.cpp came from the baseline binary
// dropping rules that timed out, which the timeout retry recovers.
func TestCCRParityCppCLanguageRules(t *testing.T) {
	checkOpengrepAvailable(t)
	root := t.TempDir()
	rulePath := writeRules(t, root,
		"- id: curve25519\n  message: m\n  mode: taint\n  options:\n    interfile: true\n  severity: INFO\n  languages: [c, cpp]\n  pattern-sources:\n    - pattern: $KEY\n  pattern-sinks:\n    - patterns:\n        - pattern: $FUNC(...)\n        - metavariable-regex:\n            metavariable: $FUNC\n            regex: '^curve25519_mul(?:_g)?$'\n        - focus-metavariable: $FUNC\n",
		"- id: c-only\n  message: m\n  severity: INFO\n  languages: [c]\n  pattern: curve25519_mul(...)\n",
		"- id: cpp-only\n  message: m\n  severity: INFO\n  languages: [cpp]\n  pattern: curve25519_mul(...)\n",
	)
	src := filepath.Join(root, "src")
	writeTree(t, src, map[string]string{
		"donna.h":      "#ifndef DONNA_H\n#define DONNA_H\nint curve25519_mul(unsigned char *out, const unsigned char *k, const unsigned char *p);\nstatic inline int g(unsigned char *o, const unsigned char *k) { return curve25519_mul(o, k, 0); }\n#endif\n",
		"donna_64.cpp": "#include \"donna.h\"\n#include <cstring>\n\nnamespace CryptoPP {\nint curve25519_mul_g(unsigned char *out, const unsigned char *k) {\n\tunsigned char e[32];\n\tstd::memcpy(e, k, 32);\n\treturn curve25519_mul(out, e, 0);\n}\n}\n",
		"donna_32.c":   "#include \"donna.h\"\nint f(unsigned char *o, const unsigned char *k) { return curve25519_mul(o, k, 0); }\n",
	})
	requireRulesKept(t, src, rulePath, []string{"curve25519", "c-only", "cpp-only"}, nil)
	// donna.h matches all three rules as C and C++, donna_32.c the C ones,
	// donna_64.cpp the C++ ones: one asset per call.
	if n := requireModeParity(context.Background(), t, src, rulePath); n != 3 {
		t.Fatalf("the CLI found %d findings, want 3", n)
	}
}

// TestCCRParityRustCrate reproduces a crates.io source package (aes-gcm):
// the crate sits one directory below the target, its lib.rs starts with
// inner attributes, and rules require use declarations or qualified names.
func TestCCRParityRustCrate(t *testing.T) {
	checkOpengrepAvailable(t)
	root := t.TempDir()
	body := "rules:\n" +
		"- id: aes-gcm-use\n  message: m\n  severity: INFO\n  languages: [rust]\n  patterns:\n    - pattern-inside: |\n        use aes_gcm::$X;\n        ...\n    - pattern: Aes256Gcm::new(...)\n" +
		"- id: aes-gcm-path\n  message: m\n  severity: INFO\n  languages: [rust]\n  pattern: aes_gcm::Aes256Gcm::new_from_slice(...)\n" +
		"- id: ring-path\n  message: m\n  severity: INFO\n  languages: [rust]\n  pattern: ring::aead::LessSafeKey::new(...)\n" +
		"- id: any-encrypt\n  message: m\n  severity: INFO\n  languages: [rust]\n  pattern: $C.encrypt($N, $P)\n"
	writeTree(t, root, map[string]string{"rules/rust/rules.yaml": body})
	rulePath := mergeRulesLikeMaterializer(t, filepath.Join(root, "rules"))
	src := filepath.Join(root, "crate")
	writeTree(t, src, map[string]string{
		"aes-gcm-0.11.1/Cargo.toml": "[package]\nname = \"aes-gcm\"\nversion = \"0.11.1\"\n",
		"aes-gcm-0.11.1/src/lib.rs": "#![no_std]\n#![doc = include_str!(\"../README.md\")]\n\n//! # Usage\n\n" +
			"use aes_gcm::{\n    aead::{Aead, KeyInit},\n    Aes256Gcm,\n};\n\npub fn seal(k: &[u8], n: &[u8], p: &[u8]) {\n" +
			"    let c = Aes256Gcm::new(k.into());\n    let _ = c.encrypt(n.into(), p);\n    let _ = aes_gcm::Aes256Gcm::new_from_slice(k);\n}\n",
	})
	requireRulesKept(t, src, rulePath, []string{"aes-gcm-use", "aes-gcm-path", "any-encrypt"}, []string{"ring-path"})
	if n := requireModeParity(context.Background(), t, src, rulePath); n != 3 {
		t.Fatalf("the CLI found %d findings, want 3", n)
	}
}
