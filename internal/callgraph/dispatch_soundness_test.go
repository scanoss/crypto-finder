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

// These tests pin the rule the dispatch expansions follow: an edge is dropped
// only when the candidate's hierarchy is known and excludes the declared type.
// When a hierarchy is unknown, the edge stays and is marked name_only.

func TestDispatch_NodeInheritedMethodThroughThisIsLinked(t *testing.T) {
	dir := t.TempDir()
	src := `const crypto = require('crypto');
class Base {
  digest(d) { return crypto.createHash('sha256').update(d).digest('hex'); }
}
class Sub extends Base {
  run(d) { return this.digest(d); }
}
module.exports = { Sub };
`
	if err := os.WriteFile(filepath.Join(dir, "hash.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemNode, NewNodeParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var runKey, digestKey string
	for key, fn := range graph.Functions {
		switch {
		case fn.ID.Type == "Sub" && BaseFunctionName(fn.ID.Name) == "run":
			runKey = key
		case fn.ID.Type == "Base" && BaseFunctionName(fn.ID.Name) == "digest":
			digestKey = key
		}
	}
	if runKey == "" || digestKey == "" {
		t.Fatalf("fixture: run=%q digest=%q", runKey, digestKey)
	}
	if !hasCaller(graph, digestKey, runKey) {
		t.Fatalf("Callers[%s] = %v, want %s: this.digest() reaches the inherited Base.digest", digestKey, graph.Callers[digestKey], runKey)
	}
	if kind := edgeKindOf(graph, runKey, digestKey); kind != EdgeKindExact {
		t.Fatalf("edge kind = %q, want %q: the extends clause makes Base.digest the static target", kind, EdgeKindExact)
	}
}

func TestDispatch_UnknownCandidateHierarchyKeepsHeuristicEdge(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Hasher.java": `package com.lib;
public interface Hasher { byte[] hash(byte[] d); }
`,
		"com/lib/impl/ShaHasher.java": `package com.lib.impl;
import com.other.AbstractHasher;
public class ShaHasher extends AbstractHasher {
  public byte[] hash(byte[] d) { return d; }
}
`,
		"com/lib/impl/Plain.java": `package com.lib.impl;
public class Plain {
  public byte[] hash(byte[] d) { return d; }
}
`,
		"com/lib/App.java": `package com.lib;
public class App {
  public byte[] go(Hasher hasher, byte[] d) { return hasher.hash(d); }
}
`,
	})
	caller := "com.lib.(App).go#2"
	sha := "com.lib.impl.(ShaHasher).hash#1"
	if !hasCaller(graph, sha, caller) {
		t.Fatalf("ShaHasher's supertype is not in the graph, so it may implement Hasher: the edge must stay")
	}
	if kind := edgeKindOf(graph, caller, sha); kind != EdgeKindNameOnly {
		t.Fatalf("edge kind = %q, want %q for an unproven implementation", kind, EdgeKindNameOnly)
	}
	// Plain's hierarchy is fully known (it extends only Object): it cannot
	// implement Hasher, so it stays unlinked.
	if hasCaller(graph, "com.lib.impl.(Plain).hash#1", caller) {
		t.Fatalf("a class whose known hierarchy excludes Hasher must not be linked")
	}
}

func TestDispatch_OverloadWithUnindexedArgumentClassKeepsAll(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		// KeyMaterial is in the graph, so the parameter type is known; the
		// argument's class VendorKey is not, so nothing proves it is not a
		// KeyMaterial.
		"com/lib/KeyMaterial.java": `package com.lib;
public interface KeyMaterial { byte[] bytes(); }
`,
		"com/lib/Wrapper.java": `package com.lib;
import javax.crypto.Cipher;
public class Wrapper {
  public void init(Object key) {}
  public void init(KeyMaterial key) throws Exception { Cipher.getInstance("AES"); }
}
`,
		"com/app/Use.java": `package com.app;
import com.lib.Wrapper;
import com.vendor.VendorKey;
public class Use {
  public void go(Wrapper w) throws Exception { w.init(new VendorKey()); }
}
`,
	})
	caller := "com.app.(Use).go#1"
	for _, overload := range []string{"init#1$Object", "init#1$KeyMaterial"} {
		key := "com.lib.(Wrapper)." + overload
		if !hasCaller(graph, key, caller) {
			t.Errorf("VendorKey's hierarchy is unknown, so overload %s must be kept", key)
		}
	}
}

func TestNodeClassBasesRecordsExtendsClause(t *testing.T) {
	dir := t.TempDir()
	src := "class Base { a() {} }\nclass Sub extends Base { b() {} }\n"
	if err := os.WriteFile(filepath.Join(dir, "c.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range analyses {
		for _, fn := range a.Functions {
			if fn.ID.Type == "Sub" && (len(fn.OwnerBases) != 1 || fn.OwnerBases[0] != "Base") {
				t.Fatalf("Sub.%s OwnerBases = %v, want [Base]", fn.ID.Name, fn.OwnerBases)
			}
		}
	}
}
