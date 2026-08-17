// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestDependencyContextFromEntity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, ecosystem, module, version, want string
	}{
		{name: "known-version", ecosystem: "java", module: "org.example:crypto", version: "1.0.0", want: "pkg:maven/org.example/crypto@1.0.0"},
		{name: "versionless", ecosystem: "go", module: "example.com/crypto", want: "pkg:golang/example.com/crypto"},
		{name: "unknown-ecosystem", ecosystem: "node", module: "@scope/crypto", version: "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dependencyContextFromEntity(&entities.DependencyInfo{
				Module:  tt.module,
				Version: tt.version,
			}, tt.ecosystem)
			if got == nil {
				t.Fatal("dependency context is nil")
			}
			if got.PURL != tt.want {
				t.Errorf("PURL = %q, want %q", got.PURL, tt.want)
			}
		})
	}
}
