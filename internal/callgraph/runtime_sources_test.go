// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// argumentRuntimeSources lists, per call of a callee whose name starts with
// method, in line order, the runtime inputs its first argument reads.
func argumentRuntimeSources(t *testing.T, graph *CallGraph, method string) []string {
	t.Helper()
	type read struct {
		line   int
		source string
	}
	var reads []read
	var walk func([]SourceNode, *[]string)
	walk = func(nodes []SourceNode, out *[]string) {
		for i := range nodes {
			if source, ok := nodes[i].RuntimeSource(); ok {
				*out = append(*out, string(source.Kind)+":"+source.Key)
				continue
			}
			walk(nodes[i].SourceNodes, out)
		}
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if !strings.HasPrefix(call.Callee.Name, method) || len(call.ArgumentSources) == 0 {
				continue
			}
			var sources []string
			walk(call.ArgumentSources[0], &sources)
			reads = append(reads, read{call.Line, strings.Join(sources, ",")})
		}
	}
	slices.SortFunc(reads, func(a, b read) int { return a.line - b.line })
	got := make([]string, len(reads))
	for i := range reads {
		got[i] = reads[i].source
	}
	return got
}

func buildRuntimeSourceGraph(t *testing.T, ecosystem string, parser Parser, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystem, parser).BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// Each parser marks the environment, property and program-argument reads it
// recognizes, with the key a literal, a local or a constant of another file
// pins, an empty key when nothing pins it, and nothing for a look-alike.
func TestRuntimeSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, ecosystem, method string
		parser                  Parser
		files                   map[string]string
		want                    []string
	}{
		{
			name: "java", ecosystem: "java", method: "getInstance", parser: NewJavaParser(),
			files: map[string]string{
				"p/Cfg.java": "package p;\npublic class Cfg { public static final String KEY = \"CROSS\"; }\n",
				"p/A.java": `package p;
import java.security.Signature;
import java.util.Properties;
public class A {
  static final String KEY = "SIG_ALG";
  public static void main(String[] args) throws Exception {
    Signature.getInstance(System.getenv("SIG_ALG"));
    Signature.getInstance(System.getenv(KEY));
    Signature.getInstance(System.getenv(Cfg.KEY));
    Signature.getInstance(args[1]);
    Signature.getInstance(System.getProperty("sig.alg", "AES"));
    Properties props = new Properties();
    Signature.getInstance(props.getProperty("cfg.alg"));
    String local = System.getenv("LOCAL");
    Signature.getInstance(local);
  }
  void notMain(String[] args, String name) throws Exception {
    Signature.getInstance(args[0]);
    Signature.getInstance(System.getenv(name));
  }
}
`,
			},
			want: []string{"env:SIG_ALG", "env:SIG_ALG", "env:CROSS", "argv:1", "property:sig.alg", "property:cfg.alg", "env:LOCAL", "", "env:"},
		},
		{
			name: "python", ecosystem: "python", method: "new", parser: NewPythonParser(),
			files: map[string]string{
				"cfg.py": "KEY = \"CROSS\"\n",
				"m.py": `import hashlib, os, sys
from os import environ, getenv
from cfg import KEY
LOCAL_KEY = "HASH_ALG"
def f(name):
    hashlib.new(os.environ["HASH_ALG"])
    hashlib.new(os.environ.get("HASH_ALG", "sha256"))
    hashlib.new(os.getenv(LOCAL_KEY))
    hashlib.new(getenv(KEY))
    hashlib.new(environ["E"])
    hashlib.new(sys.argv[1])
    a = os.environ["LOCAL"]
    hashlib.new(a)
    hashlib.new(os.getenv(name))
    hashlib.new(cfg.environ["X"])
`,
			},
			want: []string{"env:HASH_ALG", "env:HASH_ALG", "env:HASH_ALG", "env:CROSS", "env:E", "argv:1", "env:LOCAL", "env:", ""},
		},
		{
			name: "node", ecosystem: "node", method: "createHash", parser: NewNodeParser(),
			files: map[string]string{
				"cfg.mjs": "export const KEY = \"CROSS\";\n",
				"m.mjs": `import crypto from "crypto";
import { KEY } from "./cfg.mjs";
const LOCAL_KEY = "HASH_ALG";
export function f(name) {
  crypto.createHash(process.env.HASH_ALG);
  crypto.createHash(process.env["HASH_ALG"]);
  crypto.createHash(process.env[LOCAL_KEY]);
  crypto.createHash(process.env[KEY]);
  crypto.createHash(process.argv[2]);
  const a = process.env.LOCAL;
  crypto.createHash(a);
  crypto.createHash(process.env[name]);
  crypto.createHash(other.env.X);
}
`,
			},
			want: []string{"env:HASH_ALG", "env:HASH_ALG", "env:HASH_ALG", "env:CROSS", "argv:2", "env:LOCAL", "env:", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			graph := buildRuntimeSourceGraph(t, tt.ecosystem, tt.parser, tt.files)
			if got := argumentRuntimeSources(t, graph, tt.method); !slices.Equal(got, tt.want) {
				t.Fatalf("runtime sources = %q\nwant              %q", got, tt.want)
			}
		})
	}
}
