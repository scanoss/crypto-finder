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

func writeJavaSources(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func buildJavaGraph(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	root := writeJavaSources(t, files)
	graph, err := NewBuilderForEcosystem(ecosystemJava, NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func hasCaller(graph *CallGraph, calleeKey, callerKey string) bool {
	for _, caller := range graph.Callers[calleeKey] {
		if caller == callerKey {
			return true
		}
	}
	return false
}

// edgeKindOf returns the recorded classification of the caller->callee edge,
// or "" when the builder recorded none.
func edgeKindOf(graph *CallGraph, callerKey, calleeKey string) EdgeKind {
	var best EdgeKind
	for key := range graph.EdgeResolutions {
		res := graph.EdgeResolutions[key]
		if res.callerKey == callerKey && res.calleeKey == calleeKey && edgeKindRank(res.Kind) > edgeKindRank(best) {
			best = res.Kind
		}
	}
	return best
}

// tikaShapedSources reproduces the shape of a real dependency chain: an
// overloaded parseToString whose File overload calls an overloaded static
// TikaInputStream.get(File, Metadata), next to an unrelated library in the same
// two-segment namespace root (org.apache) that declares get(long, TimeUnit).
var tikaShapedSources = map[string]string{
	"org/apache/tika/Tika.java": `package org.apache.tika;
import java.io.File;
import java.io.InputStream;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
public class Tika {
  public String parseToString(InputStream stream) { return parseToString(stream, new Metadata()); }
  public String parseToString(InputStream stream, Metadata md) { return "x"; }
  public String parseToString(File file) {
    Metadata metadata = new Metadata();
    InputStream s = TikaInputStream.get(file, metadata);
    return parseToString(s, metadata);
  }
}
`,
	"org/apache/tika/io/TikaInputStream.java": `package org.apache.tika.io;
import java.io.File;
import java.io.InputStream;
import org.apache.tika.metadata.Metadata;
public class TikaInputStream extends InputStream {
  public static TikaInputStream get(File file, Metadata md) { return null; }
  public static TikaInputStream get(byte[] data, Metadata md) { return null; }
}
`,
	// The JDK is indexed in a real scan; this stands in for it so the
	// receiver's ancestry is complete.
	"java/io/InputStream.java": "package java.io;\npublic abstract class InputStream {}\n",
	"org/apache/tika/metadata/Metadata.java": `package org.apache.tika.metadata;
public class Metadata { public Metadata() {} }
`,
	"org/apache/cxf/jaxrs/client/JaxrsResponseFuture.java": `package org.apache.cxf.jaxrs.client;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
public class JaxrsResponseFuture<T> implements Future<T> {
  public T get(long timeout, TimeUnit unit) { return null; }
  public T get() { return null; }
}
`,
	"com/app/Svc.java": `package com.app;
import java.io.InputStream;
import org.apache.tika.Tika;
public class Svc {
  private final Tika tika = new Tika();
  public String extract(InputStream in) { return tika.parseToString(in); }
}
`,
}

func TestDispatch_OverloadedStaticCallDoesNotLinkUnrelatedSameNameMethod(t *testing.T) {
	graph := buildJavaGraph(t, tikaShapedSources)

	caller := "org.apache.tika.(Tika).parseToString#1$File"
	unrelated := "org.apache.cxf.jaxrs.client.(JaxrsResponseFuture).get#2"
	if _, ok := graph.Functions[unrelated]; !ok {
		t.Fatalf("fixture: %s not in graph", unrelated)
	}
	if hasCaller(graph, unrelated, caller) {
		t.Fatalf("TikaInputStream.get(File, Metadata) must not link to the unrelated %s", unrelated)
	}

	want := "org.apache.tika.io.(TikaInputStream).get#2$File,Metadata"
	if !hasCaller(graph, want, caller) {
		t.Fatalf("Callers[%s] = %v, want %s", want, graph.Callers[want], caller)
	}
	if kind := edgeKindOf(graph, caller, want); kind != EdgeKindExact {
		t.Fatalf("edge kind to the selected overload = %q, want %q", kind, EdgeKindExact)
	}
	incompatible := "org.apache.tika.io.(TikaInputStream).get#2$byte[],Metadata"
	if hasCaller(graph, incompatible, caller) {
		t.Fatalf("a File argument must not select the byte[] overload %s", incompatible)
	}
}

func TestDispatch_OverloadSelectedByDeclaredArgumentType(t *testing.T) {
	graph := buildJavaGraph(t, tikaShapedSources)

	caller := "com.app.(Svc).extract#1"
	want := "org.apache.tika.(Tika).parseToString#1$InputStream"
	wrong := "org.apache.tika.(Tika).parseToString#1$File"
	if !hasCaller(graph, want, caller) {
		t.Fatalf("Callers[%s] = %v, want %s", want, graph.Callers[want], caller)
	}
	if hasCaller(graph, wrong, caller) {
		t.Fatalf("parseToString(InputStream) must not resolve to the File overload %s", wrong)
	}
}

func TestDispatch_OverloadAmbiguityKeepsOnlyCompatibleCandidates(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"com/lib/Codec.java": `package com.lib;
public class Codec {
  public static byte[] encode(byte[] data) { return data; }
  public static byte[] encode(String text) { return null; }
  public static byte[] encode(long value) { return null; }
}
`,
		"com/app/Use.java": `package com.app;
import com.lib.Codec;
import org.unindexed.Source;
public class Use {
  public byte[] unknown(Source src) { return Codec.encode(src.read()); }
  public byte[] literal() { return Codec.encode(42); }
}
`,
	})

	unknownCaller := "com.app.(Use).unknown#1"
	for _, overload := range []string{"encode#1$byte[]", "encode#1$String", "encode#1$long"} {
		key := "com.lib.(Codec)." + overload
		if !hasCaller(graph, key, unknownCaller) {
			t.Errorf("an argument of unknown type must keep overload %s", key)
		}
	}

	literalCaller := "com.app.(Use).literal#0"
	if !hasCaller(graph, "com.lib.(Codec).encode#1$long", literalCaller) {
		t.Errorf("an int literal widens to the long overload")
	}
	for _, overload := range []string{"encode#1$byte[]", "encode#1$String"} {
		if key := "com.lib.(Codec)." + overload; hasCaller(graph, key, literalCaller) {
			t.Errorf("an int literal must not select the incompatible overload %s", key)
		}
	}
}

var parserHierarchySources = map[string]string{
	"org/apache/tika/parser/Parser.java": `package org.apache.tika.parser;
import java.io.InputStream;
public interface Parser {
  void parse(InputStream stream, String md);
}
`,
	"org/apache/tika/parser/AbstractParser.java": `package org.apache.tika.parser;
public abstract class AbstractParser implements Parser {
  public void helper() {}
}
`,
	"org/apache/tika/parser/crypto/Pkcs7Parser.java": `package org.apache.tika.parser.crypto;
import java.io.InputStream;
import org.apache.tika.parser.AbstractParser;
public class Pkcs7Parser extends AbstractParser {
  public void parse(InputStream stream, String md) { digest(); }
  void digest() {}
}
`,
	"org/apache/tika/parser/ExtendedParser.java": `package org.apache.tika.parser;
public interface ExtendedParser extends Parser {}
`,
	"org/apache/tika/parser/pdf/PdfParser.java": `package org.apache.tika.parser.pdf;
import java.io.InputStream;
import org.apache.tika.parser.ExtendedParser;
public class PdfParser implements ExtendedParser {
  public void parse(InputStream stream, String md) {}
}
`,
	"org/apache/commons/compress/ExtraFieldUtils.java": `package org.apache.commons.compress;
import java.io.InputStream;
public class ExtraFieldUtils {
  public void parse(InputStream data, String md) {}
}
`,
	"com/app/Extract.java": `package com.app;
import java.io.InputStream;
import org.apache.tika.parser.Parser;
public class Extract {
  public void run(Parser parser, InputStream in) { parser.parse(in, "m"); }
}
`,
}

func TestDispatch_InterfaceCallStillReachesRealImplementations(t *testing.T) {
	graph := buildJavaGraph(t, parserHierarchySources)

	caller := "com.app.(Extract).run#2"
	for _, impl := range []string{
		// class Pkcs7Parser extends AbstractParser implements Parser (transitive)
		"org.apache.tika.parser.crypto.(Pkcs7Parser).parse#2",
		// class PdfParser implements ExtendedParser extends Parser
		"org.apache.tika.parser.pdf.(PdfParser).parse#2",
	} {
		if !hasCaller(graph, impl, caller) {
			t.Errorf("Callers[%s] = %v, want %s: a real implementation must stay linked", impl, graph.Callers[impl], caller)
			continue
		}
		if kind := edgeKindOf(graph, caller, impl); kind != EdgeKindInterfaceDispatch {
			t.Errorf("edge kind to %s = %q, want %q", impl, kind, EdgeKindInterfaceDispatch)
		}
	}

	unrelated := "org.apache.commons.compress.(ExtraFieldUtils).parse#2"
	if hasCaller(graph, unrelated, caller) {
		t.Errorf("Parser.parse must not link to %s, which does not implement Parser", unrelated)
	}
}

func TestDispatch_AbstractClassCallLinksSubclassesAndInheritedMethodOnly(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"org/example/base/Base.java": `package org.example.base;
public abstract class Base extends Root {
  public void run() { get(1L, "x"); }
}
`,
		"org/example/base/Root.java": `package org.example.base;
public class Root {
  public void describe(String label) {}
}
`,
		"org/example/impl/Sub.java": `package org.example.impl;
import org.example.base.Base;
public class Sub extends Base {
  public Object get(long timeout, String unit) { return null; }
}
`,
		"org/example/other/Other.java": `package org.example.other;
public class Other {
  public Object get(long timeout, String unit) { return null; }
  public void describe(String label) {}
}
`,
		"org/example/app/Main.java": `package org.example.app;
import org.example.base.Base;
public class Main {
  public void use(Base base) { base.describe("x"); }
}
`,
	})

	runKey := "org.example.base.(Base).run#0"
	if !hasCaller(graph, "org.example.impl.(Sub).get#2", runKey) {
		t.Errorf("an abstract this-call must reach the subclass override")
	}
	if hasCaller(graph, "org.example.other.(Other).get#2", runKey) {
		t.Errorf("an abstract this-call must not reach an unrelated class with the same method name and arity")
	}

	useKey := "org.example.app.(Main).use#1"
	inherited := "org.example.base.(Root).describe#1"
	if !hasCaller(graph, inherited, useKey) {
		t.Errorf("Callers[%s] = %v, want %s: a call on Base reaches the method it inherits", inherited, graph.Callers[inherited], useKey)
	} else if kind := edgeKindOf(graph, useKey, inherited); kind != EdgeKindExact {
		t.Errorf("edge kind to the inherited method = %q, want %q", kind, EdgeKindExact)
	}
	if hasCaller(graph, "org.example.other.(Other).describe#1", useKey) {
		t.Errorf("a call on Base must not reach Other.describe")
	}
}

func TestDispatch_UnrecordedHierarchyKeepsNameOnlyEdge(t *testing.T) {
	root := t.TempDir()
	caller := FunctionDecl{
		ID: FunctionID{Package: "app", Type: "Controller", Name: "handle#0"}, OwnerType: ownerTypeClass,
		Calls: []FunctionCall{{Callee: FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}, Line: 3}},
	}
	iface := FunctionDecl{ID: FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}, OwnerType: ownerTypeInterface}
	// Same name, arity and namespace root; nothing records its supertypes.
	stranger := FunctionDecl{ID: FunctionID{Package: "com.dep.other", Type: "Runner", Name: "run#0"}, OwnerType: ownerTypeClass}
	parser := &stubParser{sep: ".", analyses: map[string][]*FileAnalysis{root: {{Functions: []FunctionDecl{caller, iface, stranger}}}}}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCaller(graph, stranger.ID.String(), caller.ID.String()) {
		t.Fatalf("a class whose hierarchy is not recorded may implement Sink: the edge must stay")
	}
	if kind := edgeKindOf(graph, caller.ID.String(), stranger.ID.String()); kind != EdgeKindNameOnly {
		t.Fatalf("edge kind = %q, want %q", kind, EdgeKindNameOnly)
	}
}

func TestDispatch_GoInterfaceRequiresFullMethodSet(t *testing.T) {
	root := t.TempDir()
	pkg := "example.com/lib"
	caller := FunctionDecl{
		ID: FunctionID{Package: pkg, Name: "Use"}, OwnerType: "package",
		Calls: []FunctionCall{{Callee: FunctionID{Package: pkg, Type: "Signer", Name: "Sign"}, Line: 4}},
	}
	decls := []FunctionDecl{
		caller,
		{ID: FunctionID{Package: pkg, Type: "Signer", Name: "Sign"}, OwnerType: ownerTypeInterface},
		{ID: FunctionID{Package: pkg, Type: "Signer", Name: "Public"}, OwnerType: ownerTypeInterface},
		{ID: FunctionID{Package: pkg, Type: "*RSAKey", Name: "Sign"}, OwnerType: ownerTypeType},
		{ID: FunctionID{Package: pkg, Type: "*RSAKey", Name: "Public"}, OwnerType: ownerTypeType},
		// Has Sign but not Public: it does not satisfy Signer.
		{ID: FunctionID{Package: pkg, Type: "Hasher", Name: "Sign"}, OwnerType: ownerTypeType},
	}
	parser := &stubParser{sep: "/", analyses: map[string][]*FileAnalysis{root: {{Functions: decls}}}}
	graph, err := NewBuilderForEcosystem(ecosystemGo, parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: pkg}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	callerKey := caller.ID.String()
	if !hasCaller(graph, FunctionID{Package: pkg, Type: "*RSAKey", Name: "Sign"}.String(), callerKey) {
		t.Errorf("*RSAKey implements Signer and must stay linked")
	}
	if hasCaller(graph, FunctionID{Package: pkg, Type: "Hasher", Name: "Sign"}.String(), callerKey) {
		t.Errorf("Hasher lacks Public, so it does not implement Signer")
	}
}
