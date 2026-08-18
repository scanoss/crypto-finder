// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package purl

import "testing"

func TestDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, ecosystem, module, version, want string
	}{
		{name: "maven", ecosystem: "java", module: "org.example:crypto-lib", version: "1.2.3", want: "pkg:maven/org.example/crypto-lib@1.2.3"},
		{name: "pypi-normalization", ecosystem: "python", module: "My_Package.Name", version: "2.0", want: "pkg:pypi/my-package-name@2.0"},
		{name: "golang", ecosystem: "go", module: "GitHub.com/Example/Crypto", version: "v1.2.3", want: "pkg:golang/github.com/example/crypto@v1.2.3"},
		{name: "cargo", ecosystem: "rust", module: "ring", version: "0.17.8", want: "pkg:cargo/ring@0.17.8"},
		{name: "versionless", ecosystem: "python", module: "cryptography", want: "pkg:pypi/cryptography"},
		{name: "unknown-ecosystem", ecosystem: "node", module: "left-pad", version: "1.3.0"},
		{name: "missing-module", ecosystem: "go", version: "v1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Dependency(tt.ecosystem, tt.module, tt.version); got != tt.want {
				t.Fatalf("Dependency(%q, %q, %q) = %q, want %q", tt.ecosystem, tt.module, tt.version, got, tt.want)
			}
		})
	}
}

func TestRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, raw, want string
	}{
		{name: "normalizes", raw: "pkg:pypi/My_Package.Name", want: "pkg:pypi/my-package-name"},
		{name: "rejects version", raw: "pkg:maven/org.example/lib@1.2.3"},
		{name: "rejects invalid", raw: "not-a-purl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Rule(tt.raw); got != tt.want {
				t.Fatalf("Rule(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestWithVersion(t *testing.T) {
	if got := WithVersion("pkg:maven/org.example/lib", "1.2.3"); got != "pkg:maven/org.example/lib@1.2.3" {
		t.Fatalf("WithVersion() = %q", got)
	}
	if got := WithVersion("pkg:maven/org.example/lib@1.2.3", "2.0.0"); got != "" {
		t.Fatalf("WithVersion(versioned) = %q, want empty", got)
	}
}
