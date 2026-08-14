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

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// TestJavaGenericReceiver_CalleeIdentityDropsGenericArguments pins the callee
// identity produced for a method call on a variable whose declared type carries
// generic arguments. Class declarations are indexed under the bare identifier
// (parseJavaClass records no type_parameters), so any generic left in the callee
// Type yields an identity that can never match the declaration it names — the
// #228 defect, which broke consumer→library joins AND same-package edges.
func TestJavaGenericReceiver_CalleeIdentityDropsGenericArguments(t *testing.T) {
	dir := t.TempDir()
	src := `package com.example;

import java.util.Map;
import java.util.List;
import javax.crypto.*;
import org.springframework.kafka.core.KafkaTemplate;

class LocalCache<T> {
    T get(String key) { return null; }
}

class Consumer {
    void run(String k, String v) {
        // imported generic type -> the IMPORT's package, bare type
        Map<String, Object> props = null;
        props.put(k, v);

        // fully-qualified generic whose ARGUMENT is itself qualified. The last
        // dot sits inside the angle brackets, so an un-erased name would split
        // the package as "Map<String, java.util".
        java.util.Map<String, java.util.List<byte[]>> cache = null;
        cache.put(k, null);

        // third-party generic API -> the import's package, bare type
        KafkaTemplate<String, String> template = null;
        template.send(k, v);

        // SAME-PACKAGE generic type, no import -> the scanned file's package is
        // the correct answer here; erasure must not change that.
        LocalCache<String> local = null;
        local.get(k);

        // wildcard import, resolved through the curated known-type table.
        // Not generic, but it guards the branch erasure now shares.
        Cipher c = null;
        c.doFinal(null);
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Consumer.java"), []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	graph, err := NewBuilderForEcosystem("java", NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "com.example"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	var run *FunctionDecl
	for _, fn := range graph.Functions {
		if fn.ID.Type == "Consumer" && BaseFunctionName(fn.ID.Name) == "run" {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("Consumer.run not found in graph")
	}

	calleeFor := func(method string) FunctionID {
		t.Helper()
		for _, c := range run.Calls {
			if BaseFunctionName(c.Callee.Name) == method {
				return c.Callee
			}
		}
		t.Fatalf("no call to %q in Consumer.run", method)
		return FunctionID{}
	}

	tests := []struct {
		name     string
		method   string
		wantPkg  string
		wantType string
	}{
		{
			name:     "imported generic resolves through the import map",
			method:   "put",
			wantPkg:  "java.util",
			wantType: "Map",
		},
		{
			name:     "third-party generic API keeps its declaring package",
			method:   "send",
			wantPkg:  "org.springframework.kafka.core",
			wantType: "KafkaTemplate",
		},
		{
			name:     "same-package generic still falls back to the file's package",
			method:   "get",
			wantPkg:  "com.example",
			wantType: "LocalCache",
		},
		{
			name:     "wildcard import still resolves",
			method:   "doFinal",
			wantPkg:  "javax.crypto",
			wantType: "Cipher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callee := calleeFor(tt.method)
			if callee.Package != tt.wantPkg || callee.Type != tt.wantType {
				t.Fatalf("callee = %s.(%s).%s, want %s.(%s)",
					callee.Package, callee.Type, callee.Name, tt.wantPkg, tt.wantType)
			}
		})
	}

	// The same-package generic must resolve to the class the file actually
	// declares, i.e. the edge has to land on a real function.
	localGet := calleeFor("get")
	if _, ok := graph.Functions[localGet.String()]; !ok {
		t.Fatalf("callee %q has no declaration in the graph — the edge is lost", localGet.String())
	}
}

// TestStripGenericSuffix_DeclaredTypeInputs covers the erasure helper on the
// declared-type shapes resolveJavaVariableTypeCallee actually receives.
func TestStripGenericSuffix_DeclaredTypeInputs(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"KafkaTemplate<String, String>", "KafkaTemplate"},
		{"Map<String, java.util.List<byte[]>>", "Map"},
		{"List<? extends Number>", "List"},
		{"java.util.Map<String, String>", "java.util.Map"},
		{"Map", "Map"},
		{"", ""},
		// A leading '<' is not a generic argument list; index 0 is left alone.
		{"<T>", "<T>"},
		// Arrays carry no generics of their own and are returned verbatim.
		{"String[]", "String[]"},
	}
	for _, tt := range tests {
		if got := stripGenericSuffix(tt.in); got != tt.want {
			t.Errorf("stripGenericSuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
