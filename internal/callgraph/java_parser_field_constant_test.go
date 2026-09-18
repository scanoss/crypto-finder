// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

func javaArgumentSourcesOfCall(t *testing.T, graph *CallGraph, methodName, calleeSuffix string) [][]SourceNode {
	t.Helper()
	fn := findFunctionBySimpleName(t, graph, methodName)
	for i := range fn.Calls {
		if strings.Contains(fn.Calls[i].Callee.String(), "."+calleeSuffix+"#") {
			return fn.Calls[i].ArgumentSources
		}
	}
	t.Fatalf("no call to %s in %s; calls: %+v", calleeSuffix, methodName, fn.Calls)
	return nil
}

func TestJavaParser_FinalFieldInitializer_PropagatesToArgumentSources(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.KeyPairGenerator;
public class Keys {
    private static final int RSA_BITS = 2048;
    void make() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_BITS);
    }
}
`
	graph := parseInlineJava(t, "Keys", src)
	sources := javaArgumentSourcesOfCall(t, graph, "make", "initialize")
	if len(sources) != 1 || len(sources[0]) != 1 {
		t.Fatalf("argument sources = %+v, want one FIELD node", sources)
	}
	field := sources[0][0]
	if field.Type != sourceNodeField || field.Name != "RSA_BITS" {
		t.Fatalf("argument source = %+v, want FIELD RSA_BITS", field)
	}
	if field.Location == nil || field.Location.Line != 4 {
		t.Errorf("FIELD location = %+v, want declaration line 4", field.Location)
	}
	if len(field.SourceNodes) != 1 || field.SourceNodes[0].Type != sourceNodeValue || field.SourceNodes[0].Value != "2048" {
		t.Errorf("FIELD source nodes = %+v, want one VALUE 2048 from the final field's initializer", field.SourceNodes)
	}
}

func TestJavaParser_MutableFieldInitializer_StaysUnresolved(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.KeyPairGenerator;
public class Keys {
    private int bits = 2048;
    void make() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
    }
    void shrink() { bits = 1024; }
}
`
	graph := parseInlineJava(t, "Keys", src)
	sources := javaArgumentSourcesOfCall(t, graph, "make", "initialize")
	if len(sources) != 1 || len(sources[0]) != 1 {
		t.Fatalf("argument sources = %+v, want one FIELD node", sources)
	}
	field := sources[0][0]
	if field.Type != sourceNodeField || field.Name != "bits" {
		t.Fatalf("argument source = %+v, want FIELD bits", field)
	}
	if len(field.SourceNodes) != 0 {
		t.Errorf("FIELD source nodes = %+v, want none: a non-final field can be reassigned anywhere, so its initializer is not its value", field.SourceNodes)
	}
}
