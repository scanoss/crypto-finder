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
	"strings"
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

func TestDispatch_InterfaceMethodInheritedFromNonImplementingBaseIsLinked(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Hasher.java": `package com.lib;
public interface Hasher { byte[] hash(byte[] d); }
`,
		// Base does not implement Hasher; Impl does, and inherits hash from Base.
		"com/lib/Base.java": `package com.lib;
import java.security.MessageDigest;
public class Base {
  public byte[] hash(byte[] d) throws Exception { return MessageDigest.getInstance("SHA-256").digest(d); }
}
`,
		"com/lib/Impl.java": `package com.lib;
public class Impl extends Base implements Hasher {}
`,
		"com/lib/Unrelated.java": `package com.lib;
public class Unrelated {
  public byte[] hash(byte[] d) { return d; }
}
`,
		"com/app/App.java": `package com.app;
import com.lib.Hasher;
public class App {
  public byte[] main(Hasher h, byte[] x) { return h.hash(x); }
}
`,
	})
	caller := "com.app.(App).main#2"
	if !hasCaller(graph, "com.lib.(Base).hash#1", caller) {
		t.Fatalf("Impl implements Hasher with the hash it inherits from Base: Base.hash must stay linked")
	}
	if hasCaller(graph, "com.lib.(Unrelated).hash#1", caller) {
		t.Fatalf("no implementor of Hasher inherits from Unrelated, so it must not be linked")
	}
}

func TestDispatch_UntypedArgumentDoesNotLetPartialExactOverloadWin(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Key.java": `package com.lib;
public interface Key {}
`,
		"com/lib/Engine.java": `package com.lib;
import java.security.MessageDigest;
public class Engine {
  public void run(String s, Integer n) {}
  public void run(Object o, Key k) throws Exception { MessageDigest.getInstance("SHA-256"); }
}
`,
		"com/app/Use.java": `package com.app;
import com.lib.Engine;
import com.vendor.Keys;
public class Use {
  public void go(Engine e) throws Exception { e.run("x", Keys.make()); }
}
`,
	})
	caller := "com.app.(Use).go#1"
	for _, overload := range []string{"run#2$String,Integer", "run#2$Object,Key"} {
		if key := "com.lib.(Engine)." + overload; !hasCaller(graph, key, caller) {
			t.Errorf("the second argument's type is unknown, so overload %s must be kept", key)
		}
	}
}

func TestJavaSupertypesSkipTypeAnnotations(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Hasher.java": "package com.lib;\npublic interface Hasher { byte[] hash(byte[] d); }\n",
		"com/lib/Ann.java":    "package com.lib;\npublic @interface Ann {}\n",
		"com/lib/Impl.java":   "package com.lib;\npublic class Impl implements @Ann Hasher {\n  public byte[] hash(byte[] d) { return d; }\n}\n",
	})
	parents := graph.SourceSupertypes["com.lib.Impl"]
	if len(parents) != 1 || strings.Split(parents[0], javaSupertypeAlternatives)[0] != "com.lib.Hasher" {
		t.Fatalf("SourceSupertypes[com.lib.Impl] = %v, want one entry naming com.lib.Hasher", parents)
	}
}

func TestDispatch_OverriddenAncestorMethodIsNotAnInterfaceTarget(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Hasher.java": `package com.lib;
public interface Hasher { byte[] hash(byte[] d); }
`,
		"com/lib/Base.java": `package com.lib;
public class Base {
  public byte[] hash(byte[] d) { return d; }
}
`,
		// Impl overrides hash, so Base.hash is reached from a Hasher call
		// only through Impl.hash itself, never directly.
		"com/lib/Impl.java": `package com.lib;
public class Impl extends Base implements Hasher {
  public byte[] hash(byte[] d) { return d; }
}
`,
		"com/app/App.java": `package com.app;
import com.lib.Hasher;
public class App {
  public byte[] main(Hasher h, byte[] x) { return h.hash(x); }
}
`,
	})
	caller := "com.app.(App).main#2"
	if !hasCaller(graph, "com.lib.(Impl).hash#1", caller) {
		t.Fatalf("Impl.hash implements Hasher and must be linked")
	}
	if hasCaller(graph, "com.lib.(Base).hash#1", caller) {
		t.Fatalf("every implementor below Base overrides hash, so Base.hash is not a target of the interface call")
	}
}

func TestDispatch_OverloadArgumentTypedByCalleeReturnType(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Codec.java": `package com.lib;
public class Codec {
  public static String name() { return "x"; }
  public static void put(String key, String value) {}
  public static void put(String key, byte[] value) {}
}
`,
		"com/app/Use.java": `package com.app;
import com.lib.Codec;
public class Use {
  public void go() { Codec.put("k", Codec.name()); }
  public void lit() { Codec.put("k", 'c' + "v"); }
}
`,
	})
	for _, caller := range []string{"com.app.(Use).go#0", "com.app.(Use).lit#0"} {
		if !hasCaller(graph, "com.lib.(Codec).put#2$String,String", caller) {
			t.Errorf("%s: the String overload must be linked", caller)
		}
		if hasCaller(graph, "com.lib.(Codec).put#2$String,byte[]", caller) {
			t.Errorf("%s: the second argument is a String, so the byte[] overload must not be linked", caller)
		}
	}
}

func TestJavaLiteralType(t *testing.T) {
	for expr, want := range map[string]string{
		"'c'": "char", "10L": "long", "1.5f": "float", "2.0": "double", "1e3": "double",
		"0x1F": "int", "42": "int", "null": "", "\"s\"": "String",
	} {
		if got := javaLiteralType(expr); got != want {
			t.Errorf("javaLiteralType(%q) = %q, want %q", expr, got, want)
		}
	}
}

func TestDispatch_DominatedOverloadDroppedDespiteUntypedArgument(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Meta.java": `package com.lib;
public class Meta {
  public void set(String name, Object value) {}
  public void set(Object name, Object value) {}
  public void set(String name, Integer value) {}
}
`,
		"com/app/Use.java": `package com.app;
import com.lib.Meta;
import com.vendor.Values;
public class Use {
  public void go(Meta m) { m.set("k", Values.any()); }
}
`,
	})
	caller := "com.app.(Use).go#1"
	// set(String, Object) is more specific than set(Object, Object) whatever
	// the second argument is, so the latter is never chosen.
	if hasCaller(graph, "com.lib.(Meta).set#2$Object,Object", caller) {
		t.Errorf("set(Object, Object) is dominated by set(String, Object) and must not be linked")
	}
	for _, overload := range []string{"set#2$String,Object", "set#2$String,Integer"} {
		if key := "com.lib.(Meta)." + overload; !hasCaller(graph, key, caller) {
			t.Errorf("the second argument's type is unknown, so %s must be kept", key)
		}
	}
}

func TestDispatch_SameArityOverloadInImplementorIsNotAnOverride(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Hasher.java": `package com.lib;
public interface Hasher { byte[] hash(byte[] d); }
`,
		"com/lib/Base.java": `package com.lib;
import java.security.MessageDigest;
public class Base {
  public byte[] hash(byte[] d) throws Exception { return MessageDigest.getInstance("SHA-256").digest(d); }
}
`,
		// hash(String) is an overload, not an override of hash(byte[]).
		"com/lib/Impl.java": `package com.lib;
public class Impl extends Base implements Hasher {
  public byte[] hash(String s) { return null; }
}
`,
		"com/app/App.java": `package com.app;
import com.lib.Hasher;
public class App {
  public byte[] run(Hasher h, byte[] bytes) { return h.hash(bytes); }
}
`,
	})
	if !hasCaller(graph, "com.lib.(Base).hash#1", "com.app.(App).run#2") {
		t.Fatalf("Impl inherits hash(byte[]) from Base; its hash(String) overload does not override it")
	}
}

func TestDispatch_SameSimpleNameInOtherPackageIsNotAnExactOverload(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key {}\n",
		"com/other/Key.java":    "package com.other;\npublic interface Key {}\n",
		"com/acme/Svc.java": `package com.acme;
import com.acme.sec.Key;
import java.security.MessageDigest;
public class Svc {
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("SHA-256"); }
}
`,
		"com/app/App.java": `package com.app;
import com.acme.Svc;
import com.other.Key;
public class App {
  public void run(Svc svc, Key k) throws Exception { svc.r(k); }
}
`,
	})
	if !hasCaller(graph, "com.acme.(Svc).r#1$Object", "com.app.(App).run#2") {
		t.Fatalf("com.other.Key is not com.acme.sec.Key: javac picks r(Object), which must stay linked")
	}
}

func TestJavaExpressionAndHexLiteralTypes(t *testing.T) {
	if got := javaLiteralType("0x10L"); got != "long" {
		t.Errorf("javaLiteralType(0x10L) = %q, want long", got)
	}
	if got := javaExpressionType(`s.indexOf("x") + 1`); got != "" {
		t.Errorf("javaExpressionType(indexOf+1) = %q, want unknown", got)
	}
	if got := javaExpressionType(`"a" + b`); got != javaStringType {
		t.Errorf(`javaExpressionType("a" + b) = %q, want String`, got)
	}
}

func TestDispatch_ReturnTypeResolvedThroughDeclaringFileImports(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key {}\n",
		"com/other/Key.java":    "package com.other;\npublic interface Key {}\n",
		"com/other/Svc.java": `package com.other;
import java.security.MessageDigest;
public class Svc {
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("MD5"); }
}
`,
		// mk returns com.acme.sec.Key through an import, not com.other.Key.
		"com/other/F.java": `package com.other;
import com.acme.sec.Key;
public class F {
  public static Key mk() { return null; }
}
`,
		"com/other/App.java": `package com.other;
public class App {
  public void run() throws Exception { new Svc().r(F.mk()); }
}
`,
	})
	if !hasCaller(graph, "com.other.(Svc).r#1$Object", "com.other.(App).run#0") {
		t.Fatalf("F.mk returns com.acme.sec.Key, so javac picks r(Object), which must stay linked")
	}
}

func TestDispatch_NestedTypeShadowsImportInReturnType(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key {}\n",
		"com/other/Svc.java": `package com.other;
import com.acme.sec.Key;
import java.security.MessageDigest;
public class Svc {
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("MD5"); }
}
`,
		// The nested F.Key shadows the imported com.acme.sec.Key inside F.
		"com/other/F.java": `package com.other;
import com.acme.sec.Key;
public class F {
  public static class Key {}
  public static Key mk() { return new Key(); }
}
`,
		"com/other/App.java": `package com.other;
public class App {
  public void run() throws Exception { new Svc().r(F.mk()); }
}
`,
	})
	if !hasCaller(graph, "com.other.(Svc).r#1$Object", "com.other.(App).run#0") {
		t.Fatalf("F.mk returns the nested F.Key, so javac picks r(Object), which must stay linked")
	}
}

func TestDispatch_NestedTypeShadowsImportInParameter(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key {}\n",
		// r(Key) takes the nested Svc.Key, not the imported com.acme.sec.Key.
		"com/other/Svc.java": `package com.other;
import com.acme.sec.Key;
import java.security.MessageDigest;
public class Svc {
  public static class Key {}
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("MD5"); }
}
`,
		"com/other/App.java": `package com.other;
import com.acme.sec.Key;
public class App {
  public void run(Svc svc, Key k) throws Exception { svc.r(k); }
}
`,
	})
	if !hasCaller(graph, "com.other.(Svc).r#1$Object", "com.other.(App).run#2") {
		t.Fatalf("a com.acme.sec.Key argument does not fit Svc.Key: javac picks r(Object), which must stay linked")
	}
}

func TestDispatch_OutOfScopeNestedTypeDoesNotHideImportedSupertype(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key { byte[] enc(byte[] d); }\n",
		// MyKey implements the imported Key; Unrelated.Key is not in scope.
		"com/acme/impl/MyKey.java": `package com.acme.impl;
import com.acme.sec.Key;
import java.security.MessageDigest;
public class MyKey implements Key {
  public byte[] enc(byte[] d) { try { return MessageDigest.getInstance("MD5").digest(d); } catch (Exception e) { return null; } }
}
class Unrelated { static class Key {} }
`,
		"com/acme/app/App.java": `package com.acme.app;
import com.acme.sec.Key;
public class App {
  public byte[] run(Key k, byte[] d) { return k.enc(d); }
}
`,
	})
	if !hasCaller(graph, "com.acme.impl.(MyKey).enc#1", "com.acme.app.(App).run#2") {
		t.Fatalf("MyKey implements com.acme.sec.Key, so the interface call must reach MyKey.enc")
	}
}

func TestDispatch_InheritedMemberTypeShadowsImport(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/sec/Key.java": "package com.acme.sec;\npublic interface Key {}\n",
		"com/other/Base.java": `package com.other;
public class Base { public static class Key {} }
`,
		// r(Key) takes the inherited Base.Key, not the imported com.acme.sec.Key.
		"com/other/Svc.java": `package com.other;
import com.acme.sec.Key;
import java.security.MessageDigest;
public class Svc extends Base {
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("MD5"); }
}
`,
		"com/other/App.java": `package com.other;
import com.acme.sec.Key;
public class App {
  public void run(Svc svc, Key k) throws Exception { svc.r(k); }
}
`,
	})
	if !hasCaller(graph, "com.other.(Svc).r#1$Object", "com.other.(App).run#2") {
		t.Fatalf("a com.acme.sec.Key argument does not fit Base.Key: javac picks r(Object), which must stay linked")
	}
}

func TestDispatch_TypeParameterAndLocalClassAreNotPackageTypes(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/other/Key.java": "package com.other;\npublic class Key {}\n",
		"com/other/Svc.java": `package com.other;
import java.security.MessageDigest;
public class Svc {
  public void r(Key k) {}
  public void r(Object o) throws Exception { MessageDigest.getInstance("MD5"); }
}
`,
		// Key here is App's type parameter, not com.other.Key.
		"com/other/App.java": `package com.other;
public class App<Key> {
  public void run(Svc svc, Key k) throws Exception { svc.r(k); }
}
`,
		// Key here is a local class, not com.other.Key.
		"com/other/Local.java": `package com.other;
public class Local {
  public void run(Svc svc) throws Exception {
    class Key {}
    Key k = new Key();
    svc.r(k);
  }
}
`,
	})
	for _, caller := range []string{"com.other.(App).run#2", "com.other.(Local).run#1"} {
		if !hasCaller(graph, "com.other.(Svc).r#1$Object", caller) {
			t.Errorf("%s: the argument is not com.other.Key, so r(Object) must stay linked", caller)
		}
	}
}

func TestDispatch_MemberTypeInheritedByEnclosingClassIsNotCertain(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/Key.java": "package com.acme;\npublic class Key {}\n",
		"com/acme/Base.java": `package com.acme;
public class Base { public static class Key {} }
`,
		"com/acme/Wrapper.java": `package com.acme;
import java.security.MessageDigest;
public class Wrapper {
  public void init(Key k) {}
  public void init(Object o) throws Exception { MessageDigest.getInstance("SHA-1"); }
}
`,
		// Inside Outer, Key means the Base.Key that Outer inherits, so javac
		// picks init(Object).
		"com/acme/Outer.java": `package com.acme;
public class Outer extends Base {
  static class Caller {
    void go() throws Exception { Key k = new Key(); new Wrapper().init(k); }
  }
}
`,
	})
	if !hasCaller(graph, "com.acme.(Wrapper).init#1$Object", "com.acme.(Outer.Caller).go#0") {
		t.Fatalf("Key inside Outer is Base.Key: init(Object) must stay linked")
	}
}

// roundNineSources builds W.run(Object) beside W.run(Base) (the crypto
// overload) and an unrelated, fully known com.acme.k.Key, plus one caller.
func roundNineSources(caller string) map[string]string {
	return map[string]string{
		"com/acme/k/Key.java": "package com.acme.k;\npublic class Key {}\n",
		"com/acme/Base.java":  "package com.acme;\npublic class Base {}\n",
		"com/acme/W.java": `package com.acme;
import java.security.MessageDigest;
public class W {
  public void run(Object o) {}
  public void run(Base b) throws Exception { MessageDigest.getInstance("SHA-1"); }
}
`,
		"com/acme/app/App.java": caller,
	}
}

func TestDispatch_UncertainArgumentTypeCannotRejectOverload(t *testing.T) {
	cases := map[string]string{
		"type parameter": `package com.acme.app;
import com.acme.Base;
import com.acme.W;
public class App {
  public <Key extends Base> void go(Key k) throws Exception { new W().run(k); }
}
`,
		"local class": `package com.acme.app;
import com.acme.Base;
import com.acme.W;
public class App {
  public void go() throws Exception {
    class Key extends Base {}
    Key k = new Key();
    new W().run(k);
  }
}
`,
		"import of an unindexed type": `package com.acme.app;
import com.acme.W;
import org.lib.Key;
public class App {
  public void go(Key k) throws Exception { new W().run(k); }
}
`,
	}
	for name, caller := range cases {
		t.Run(name, func(t *testing.T) {
			graph := buildJavaGraph(t, roundNineSources(caller))
			callerKey := ""
			for key, fn := range graph.Functions {
				if fn.ID.Type == "App" && BaseFunctionName(fn.ID.Name) == "go" {
					callerKey = key
				}
			}
			if !hasCaller(graph, "com.acme.(W).run#1$Base", callerKey) {
				t.Fatalf("the argument's Key is not the graph's com.acme.k.Key and may extend Base: run(Base) must stay linked")
			}
		})
	}
}

func TestDispatch_OverloadInheritedFromFartherAncestorIsLinked(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/A.java": `package com.acme;
import java.security.MessageDigest;
public class A {
  public void m(Object o) throws Exception { MessageDigest.getInstance("SHA-1"); }
}
`,
		// B declares a different overload of m; A.m(Object) is still inherited.
		"com/acme/B.java": "package com.acme;\npublic class B extends A {\n  public void m(String s) {}\n}\n",
		"com/acme/C.java": "package com.acme;\npublic class C extends B {\n  public void other() {}\n}\n",
		"com/acme/App.java": `package com.acme;
public class App {
  public void go(Object o) throws Exception { new C().m(o); }
}
`,
	})
	if !hasCaller(graph, "com.acme.(A).m#1", "com.acme.(App).go#1") {
		t.Fatalf("C inherits A.m(Object) past B's m(String) overload: javac runs A.m, which must stay linked")
	}
}

func TestDispatch_BoxedPrimitiveFitsConstable(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/W2.java": `package com.acme;
import java.lang.constant.Constable;
import java.security.MessageDigest;
public class W2 {
  public void f(Object o) {}
  public void f(Constable c) throws Exception { MessageDigest.getInstance("SHA-1"); }
}
`,
		"com/acme/App.java": "package com.acme;\npublic class App {\n  public void go() throws Exception { new W2().f(5); }\n}\n",
	})
	if !hasCaller(graph, "com.acme.(W2).f#1$Constable", "com.acme.(App).go#0") {
		t.Fatalf("5 boxes to Integer, which is a Constable: javac picks f(Constable), which must stay linked")
	}
}

func TestDispatch_TypeVariableSignatureDoesNotHideInheritedMethod(t *testing.T) {
	cases := map[string]map[string]string{
		// A.m(T) erases to m(Object): B's m(String) does not override it.
		"generic ancestor": {
			"com/acme/Key.java": "package com.acme;\npublic class Key {}\n",
			"com/acme/A.java": `package com.acme;
import javax.crypto.Cipher;
public class A<T> {
  public void m(T t) throws Exception { Cipher.getInstance("AES"); }
}
`,
			"com/acme/B.java":   "package com.acme;\npublic class B extends A<Key> {\n  public void m(String s) {}\n}\n",
			"com/acme/C.java":   "package com.acme;\npublic class C extends B {\n  public void other() {}\n}\n",
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void go(Key key) throws Exception { new C().m(key); }\n}\n",
		},
		// B<T>.m(T) erases to m(Object): it does not override A.m(String).
		"generic middle class": {
			"com/acme/A.java": `package com.acme;
import javax.crypto.Cipher;
public class A {
  public void m(String s) throws Exception { Cipher.getInstance("AES"); }
}
`,
			"com/acme/B.java":   "package com.acme;\npublic class B<T> extends A {\n  public void m(T t) {}\n}\n",
			"com/acme/C.java":   "package com.acme;\npublic class C extends B<Integer> {\n  public void other() {}\n}\n",
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void go() throws Exception { new C().m(\"x\"); }\n}\n",
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			graph := buildJavaGraph(t, files)
			target := ""
			for key, fn := range graph.Functions {
				if fn.ID.Type == "A" && BaseFunctionName(fn.ID.Name) == "m" {
					target = key
				}
			}
			callerKey := ""
			for key, fn := range graph.Functions {
				if fn.ID.Type == "App" {
					callerKey = key
				}
			}
			if !hasCaller(graph, target, callerKey) {
				t.Fatalf("javac runs A.m, which a type-variable signature does not override: %s must stay linked", target)
			}
		})
	}
}

func TestDispatch_ArrayArgumentFitsSerializableAndCloneable(t *testing.T) {
	for _, tc := range []struct{ iface, arg string }{{"java.io.Serializable", "byte[]"}, {"Cloneable", "int[]"}} {
		simple := tc.iface[strings.LastIndex(tc.iface, ".")+1:]
		graph := buildJavaGraph(t, map[string]string{
			"com/acme/M.java": `package com.acme;
import javax.crypto.Cipher;
public class M {
  public void m(` + tc.iface + ` s) throws Exception { Cipher.getInstance("AES"); }
  public void m(Object o) {}
  public void m(String s) {}
}
`,
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void go(M m, " + tc.arg + " k) throws Exception { m.m(k); }\n}\n",
		})
		target := ""
		for key, fn := range graph.Functions {
			if fn.ID.Type == "M" && strings.HasSuffix(fn.ID.Name, "$"+simple) {
				target = key
			}
		}
		if !hasCaller(graph, target, "com.acme.(App).go#2") {
			t.Errorf("a %s argument is a %s: javac picks m(%s), which must stay linked", tc.arg, simple, simple)
		}
	}
}

func TestDispatch_OverloadedReceiverStillDispatchesAndInherits(t *testing.T) {
	t.Run("override in a subtype", func(t *testing.T) {
		graph := buildJavaGraph(t, map[string]string{
			"com/acme/A.java": "package com.acme;\npublic class A {\n  public void m(String s) {}\n  public void m(Object o) {}\n}\n",
			"com/acme/B.java": `package com.acme;
import javax.crypto.Cipher;
public class B extends A {
  public void m(String s) { try { Cipher.getInstance("AES"); } catch (Exception e) {} }
}
`,
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run(A a) { a.m(\"x\"); }\n}\n",
		})
		if !hasCaller(graph, "com.acme.(B).m#1", "com.acme.(App).run#1") {
			t.Fatalf("a may be a B, whose m(String) overrides A's: B.m must stay linked")
		}
	})
	t.Run("method inherited past subclass overloads", func(t *testing.T) {
		graph := buildJavaGraph(t, map[string]string{
			"com/acme/A.java": `package com.acme;
import java.io.Serializable;
import javax.crypto.Cipher;
public class A {
  public void m(Serializable s) { try { Cipher.getInstance("AES"); } catch (Exception e) {} }
}
`,
			"com/acme/B.java":   "package com.acme;\npublic class B extends A {\n  public void m(String s) {}\n  public void m(Integer i) {}\n}\n",
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run(byte[] bytes) { new B().m(bytes); }\n}\n",
		})
		if !hasCaller(graph, "com.acme.(A).m#1", "com.acme.(App).run#1") {
			t.Fatalf("B inherits A.m(Serializable), which javac picks for a byte[]: A.m must stay linked")
		}
	})
}

func TestDispatch_StaticOwnOverloadsDoNotBlockInheritedInstanceDispatch(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/S.java": "package com.acme;\npublic class S {\n  public void m(Object o) {}\n}\n",
		"com/acme/A.java": "package com.acme;\npublic class A extends S {\n  public static void m(String s) {}\n  public static void m(Integer i) {}\n}\n",
		// B overrides the instance m(Object) A inherits from S.
		"com/acme/B.java": `package com.acme;
import javax.crypto.Cipher;
public class B extends A {
  public void m(Object o) { try { Cipher.getInstance("AES"); } catch (Exception e) {} }
}
`,
		"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run(A a) { a.m(new Object()); }\n}\n",
	})
	if !hasCaller(graph, "com.acme.(B).m#1", "com.acme.(App).run#1") {
		t.Fatalf("a may be a B overriding the inherited instance m(Object): B.m must stay linked")
	}
}

func TestDispatch_OwnStaticRedeclarationHidesInheritedStatic(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/A.java":   "package com.acme;\npublic class A {\n  public static void m(String s) {}\n  public static void m(Integer i) {}\n}\n",
		"com/acme/B.java":   "package com.acme;\npublic class B extends A {\n  public static void m(String s) {}\n  public static void m(Long l) {}\n}\n",
		"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run() { B.m(\"x\"); }\n}\n",
	})
	caller := "com.acme.(App).run#0"
	if !hasCaller(graph, "com.acme.(B).m#1$String", caller) {
		t.Fatalf("B.m(String) is the target")
	}
	if hasCaller(graph, "com.acme.(A).m#1$String", caller) {
		t.Fatalf("B's static m(String) hides A's: A.m(String) is not a target")
	}
}

func TestDispatch_StaticFamilyStillDispatchesWhenInstanceMethodMayBeInherited(t *testing.T) {
	t.Run("interface default method", func(t *testing.T) {
		graph := buildJavaGraph(t, map[string]string{
			"com/acme/I.java": "package com.acme;\npublic interface I {\n  default void m(Object o) {}\n}\n",
			"com/acme/A.java": "package com.acme;\npublic class A implements I {\n  public static void m(String s) {}\n  public static void m(Integer i) {}\n}\n",
			"com/acme/B.java": `package com.acme;
import javax.crypto.Cipher;
public class B extends A {
  public void m(Object o) { try { Cipher.getInstance("AES"); } catch (Exception e) {} }
}
`,
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run(A a) { a.m(new Object()); }\n}\n",
		})
		if !hasCaller(graph, "com.acme.(B).m#1", "com.acme.(App).run#1") {
			t.Fatalf("B overrides the default m(Object) A inherits from I: B.m must stay linked")
		}
	})
	t.Run("unindexed base class", func(t *testing.T) {
		graph := buildJavaGraph(t, map[string]string{
			"com/acme/A.java": `package com.acme;
import java.io.OutputStream;
public abstract class A extends OutputStream {
  public static void write(String s) {}
  public static void write(Long l) {}
}
`,
			"com/acme/B.java": `package com.acme;
import javax.crypto.Cipher;
public class B extends A {
  public void write(int b) { try { Cipher.getInstance("AES"); } catch (Exception e) {} }
}
`,
			"com/acme/App.java": "package com.acme;\npublic class App {\n  public void run(A a) throws Exception { a.write(5); }\n}\n",
		})
		if !hasCaller(graph, "com.acme.(B).write#1", "com.acme.(App).run#1") {
			t.Fatalf("A inherits OutputStream's instance write(int), which B overrides: B.write must stay linked")
		}
	})
}

func TestDispatch_StaticFamilyShadowingObjectMethodStillDispatches(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/A.java": "package com.acme;\npublic class A {\n  public static boolean equals(String s) { return false; }\n  public static boolean equals(Integer i) { return false; }\n}\n",
		// B overrides Object.equals, which A inherits outside the graph.
		"com/acme/B.java": `package com.acme;
import javax.crypto.Cipher;
public class B extends A {
  public boolean equals(Object o) { try { Cipher.getInstance("AES"); } catch (Exception e) {} return false; }
}
`,
		"com/acme/App.java": "package com.acme;\npublic class App {\n  public boolean run(A a, Object o) { return a.equals(o); }\n}\n",
	})
	if !hasCaller(graph, "com.acme.(B).equals#1", "com.acme.(App).run#2") {
		t.Fatalf("a may be a B overriding Object.equals: B.equals must stay linked")
	}
}

func TestDispatch_TypeQualifiedCallNeverDispatches(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/acme/Root.java": "package com.acme;\npublic class Root {\n  public static void make(String s) {}\n}\n",
		// Base declares no make: Base.make(..) resolves to the one it inherits.
		"com/acme/Base.java": "package com.acme;\npublic class Base extends Root {\n  public void other() {}\n}\n",
		"com/acme/Sub.java":  "package com.acme;\npublic class Sub extends Base {\n  public static void make(String s) {}\n}\n",
		"com/acme/App.java":  "package com.acme;\npublic class App extends Base {\n  public void run() { Base.make(\"x\"); }\n}\n",
	})
	caller := "com.acme.(App).run#0"
	if !hasCaller(graph, "com.acme.(Root).make#1", caller) {
		t.Fatalf("Base.make(..) binds to the inherited Root.make")
	}
	if hasCaller(graph, "com.acme.(Sub).make#1", caller) {
		t.Fatalf("a type-qualified call must not reach Sub.make, which only hides Root.make in Sub")
	}
}

func TestDispatch_UnqualifiedCallInStaticMethodNeverDispatches(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		// Base's static helper calls an unqualified get(..); Sub's get must
		// not be reached, a static method has no this to dispatch on.
		"com/acme/Base.java": `package com.acme;
public class Base extends java.io.InputStream {
  public static Base get(java.io.File f) { return get(f, "m"); }
  public static Base get(java.io.File f, String m) { return null; }
  public static Base get(byte[] b, String m) { return null; }
  public int read() { return 0; }
}
`,
		"com/acme/Other.java": `package com.acme;
public class Other {
  public Object get(long timeout, String unit) { return null; }
}
`,
	})
	for key := range graph.Functions {
		if strings.Contains(key, "(Base).get#1") {
			if hasCaller(graph, "com.acme.(Other).get#2", key) {
				t.Fatalf("the unqualified get(..) inside static %s must not reach Other.get", key)
			}
		}
	}
}
