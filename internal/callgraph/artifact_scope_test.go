// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"
)

// artifactFixture is one dependency's sources: its coordinate, its version
// ("" for the scanned project) and its files.
type artifactFixture struct {
	module, version string
	files           map[string]string
}

func buildArtifactGraph(t *testing.T, requires map[string][]string, artifacts ...artifactFixture) *CallGraph {
	t.Helper()
	packages := make([]PackageDir, 0, len(artifacts))
	for _, a := range artifacts {
		packages = append(packages, PackageDir{
			Dir:              writeJavaSources(t, a.files),
			ImportPath:       a.module,
			DistributionName: a.module,
			Version:          a.version,
		})
	}
	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetArtifactDependencies(requires)
	graph, err := builder.BuildFromDirectories(packages, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// Three artifacts share the org.apache root. tika-core calls its own Parser
// interface; commons-math3 and a Tika parser module each declare a parse
// method on a class whose supertype is not in the graph, so neither is
// proven to implement Parser nor proven not to.
var (
	tikaCore = artifactFixture{module: "org.apache.tika:tika-core", version: "1.28.5", files: map[string]string{
		"org/apache/tika/Parser.java": `package org.apache.tika;
public interface Parser { void parse(byte[] d); }
`,
		"org/apache/tika/Tika.java": `package org.apache.tika;
public class Tika {
  public void parseToString(Parser parser, byte[] d) { parser.parse(d); }
  public String text(WriteOut handler) { return handler.describe(); }
}
`,
		"org/apache/tika/WriteOut.java": `package org.apache.tika;
import org.xml.sax.helpers.DefaultHandler;
public class WriteOut extends DefaultHandler {
  public void write(String s) {}
}
`,
		"org/apache/tika/Local.java": `package org.apache.tika;
import org.external.Unindexed;
public class Local extends Unindexed {
  public void parse(byte[] d) {}
  public String describe() { return ""; }
}
`,
	}}
	commonsMath = artifactFixture{module: "org.apache.commons:commons-math3", version: "3.6.1", files: map[string]string{
		"org/apache/commons/math3/Vector1D.java": `package org.apache.commons.math3;
import org.external.Unindexed;
public class Vector1D extends Unindexed {
  public void parse(byte[] d) {}
  public String describe() { return ""; }
}
`,
	}}
	tikaPDF = artifactFixture{module: "org.apache.tika:tika-parser-pdf", version: "1.28.5", files: map[string]string{
		"org/apache/tika/parser/pdf/PDFParser.java": `package org.apache.tika.parser.pdf;
import org.external.Unindexed;
public class PDFParser extends Unindexed {
  public void parse(byte[] d) {}
  public String describe() { return ""; }
}
`,
	}}
	tikaRequires = map[string][]string{
		"org.apache.tika:tika-parser-pdf": {"org.apache.tika:tika-core", "org.apache.commons:commons-math3"},
	}
)

// TestArtifactScope_NameOnlyInterfaceDispatchStaysInCompilingArtifacts: a
// call on an interface of artifact X links as name_only only to a class of an
// artifact that compiles against X, never to a same-named method of an
// unrelated artifact that merely shares X's namespace root.
func TestArtifactScope_NameOnlyInterfaceDispatchStaysInCompilingArtifacts(t *testing.T) {
	graph := buildArtifactGraph(t, tikaRequires, tikaCore, commonsMath, tikaPDF)
	caller := "org.apache.tika.(Tika).parseToString#2"

	if hasCaller(graph, "org.apache.commons.math3.(Vector1D).parse#1", caller) {
		t.Errorf("commons-math3 does not depend on tika-core, so Vector1D cannot implement Parser")
	}
	for _, callee := range []string{
		"org.apache.tika.(Local).parse#1",                // same artifact as Parser
		"org.apache.tika.parser.pdf.(PDFParser).parse#1", // depends on tika-core
	} {
		if !hasCaller(graph, callee, caller) {
			t.Errorf("Callers[%s] missing %s: its artifact compiles against Parser", callee, caller)
		} else if kind := edgeKindOf(graph, caller, callee); kind != EdgeKindNameOnly {
			t.Errorf("edge kind to %s = %q, want %q", callee, kind, EdgeKindNameOnly)
		}
	}
}

// TestArtifactScope_NameOnlyAbstractDispatchStaysInCompilingArtifacts: the
// same bound for a call on a class that declares no such method (the
// WriteOutContentHandler.toString shape): the candidate is a guessed subtype
// or a missed ancestor, so one of the two artifacts must compile against the
// other's.
func TestArtifactScope_NameOnlyAbstractDispatchStaysInCompilingArtifacts(t *testing.T) {
	graph := buildArtifactGraph(t, tikaRequires, tikaCore, commonsMath, tikaPDF)
	caller := "org.apache.tika.(Tika).text#1"

	if hasCaller(graph, "org.apache.commons.math3.(Vector1D).describe#0", caller) {
		t.Errorf("commons-math3 and tika-core do not depend on each other, so Vector1D cannot be related to WriteOut")
	}
	for _, callee := range []string{
		"org.apache.tika.(Local).describe#0",
		"org.apache.tika.parser.pdf.(PDFParser).describe#0",
	} {
		if !hasCaller(graph, callee, caller) {
			t.Errorf("Callers[%s] missing %s", callee, caller)
		} else if kind := edgeKindOf(graph, caller, callee); kind != EdgeKindNameOnly {
			t.Errorf("edge kind to %s = %q, want %q", callee, kind, EdgeKindNameOnly)
		}
	}
}

// TestArtifactScope_NoDependencyGraphKeepsOwnArtifactOnly: without a resolved
// dependency graph a name_only guess stays inside the declared type's artifact.
func TestArtifactScope_NoDependencyGraphKeepsOwnArtifactOnly(t *testing.T) {
	graph := buildArtifactGraph(t, nil, tikaCore, commonsMath, tikaPDF)
	caller := "org.apache.tika.(Tika).parseToString#2"
	if !hasCaller(graph, "org.apache.tika.(Local).parse#1", caller) {
		t.Errorf("a same-artifact candidate must stay linked")
	}
	for _, callee := range []string{"org.apache.commons.math3.(Vector1D).parse#1", "org.apache.tika.parser.pdf.(PDFParser).parse#1"} {
		if hasCaller(graph, callee, caller) {
			t.Errorf("%s is in another artifact and nothing says it compiles against tika-core", callee)
		}
	}
}

// TestArtifactScope_ProvenDispatchCrossesArtifacts is the CHAIN-01 shape: an
// application handler calls oauth2-oidc-sdk, which calls a nimbus-jose-jwt
// interface whose implementation records its ancestry. A proven subtype is
// linked whatever the artifacts, and a project class may implement any
// dependency's interface.
func TestArtifactScope_ProvenDispatchCrossesArtifacts(t *testing.T) {
	app := artifactFixture{module: "com.acme:ledger-api", files: map[string]string{
		"com/acme/ServiceAuthHandler.java": `package com.acme;
import com.nimbusds.openid.connect.sdk.IDTokenValidator;
public class ServiceAuthHandler {
  public void handle(IDTokenValidator validator, byte[] token) { validator.validate(token); }
}
`,
		"com/acme/LocalVerifier.java": `package com.acme;
import org.external.Unindexed;
public class LocalVerifier extends Unindexed {
  public boolean verify(byte[] d) { return true; }
}
`,
	}}
	oidc := artifactFixture{module: "com.nimbusds:oauth2-oidc-sdk", version: "9.35", files: map[string]string{
		"com/nimbusds/openid/connect/sdk/IDTokenValidator.java": `package com.nimbusds.openid.connect.sdk;
import com.nimbusds.jose.JWSVerifier;
public class IDTokenValidator {
  private JWSVerifier verifier;
  public boolean validate(byte[] token) { return verifier.verify(token); }
}
`,
	}}
	jose := artifactFixture{module: "com.nimbusds:nimbus-jose-jwt", version: "9.22", files: map[string]string{
		"com/nimbusds/jose/JWSVerifier.java": `package com.nimbusds.jose;
public interface JWSVerifier { boolean verify(byte[] d); }
`,
		"com/nimbusds/jose/crypto/RSASSAVerifier.java": `package com.nimbusds.jose.crypto;
import com.nimbusds.jose.JWSVerifier;
import org.external.Provider;
public class RSASSAVerifier extends Provider implements JWSVerifier {
  public boolean verify(byte[] d) { return true; }
}
`,
	}}
	// No dependency graph: the proven edge must not depend on one.
	graph := buildArtifactGraph(t, nil, app, oidc, jose)

	handle := "com.acme.(ServiceAuthHandler).handle#2"
	validate := "com.nimbusds.openid.connect.sdk.(IDTokenValidator).validate#1"
	verify := "com.nimbusds.jose.crypto.(RSASSAVerifier).verify#1"
	if !hasCaller(graph, validate, handle) {
		t.Fatalf("Callers[%s] = %v, want %s", validate, graph.Callers[validate], handle)
	}
	if !hasCaller(graph, verify, validate) {
		t.Fatalf("Callers[%s] = %v, want %s: RSASSAVerifier implements JWSVerifier", verify, graph.Callers[verify], validate)
	}
	if kind := edgeKindOf(graph, validate, verify); kind != EdgeKindInterfaceDispatch {
		t.Errorf("edge kind = %q, want %q", kind, EdgeKindInterfaceDispatch)
	}
}

func TestArtifactScope_CompilesAgainst(t *testing.T) {
	scope := newArtifactScope(map[string][]string{"b": {"c"}, "c": {"d"}})
	scope.typeArtifact = map[string]string{
		"p.Project": projectArtifact, "a.A": "a", "b.B": "b", "d.D": "d", "x.Shared": "",
	}
	cases := []struct {
		sub, super string
		want       bool
	}{
		{"b.B", "d.D", true},          // transitive dependency
		{"d.D", "b.B", false},         // the other way round
		{"a.A", "b.B", false},         // unrelated
		{"p.Project", "a.A", true},    // the project compiles against everything
		{"a.A", "p.Project", false},   // no dependency compiles against the project
		{"x.Shared", "a.A", true},     // declared by two artifacts: unknown
		{"q.Unrecorded", "a.A", true}, // not a graph type: unknown
	}
	for _, tc := range cases {
		if got := scope.compilesAgainst(tc.sub, tc.super); got != tc.want {
			t.Errorf("compilesAgainst(%s, %s) = %v, want %v", tc.sub, tc.super, got, tc.want)
		}
	}
}

// TestArtifactScope_SimpleNameBytecodeRewriteStaysInCompilingArtifacts: the
// parser keys `new Holder(queue)` on a private nested class as a same-package
// Holder no graph declares, and the bytecode index repairs such a call by the
// type's simple name. BouncyCastle's x509 Holder is the only Holder the index
// has, but ehcache does not compile against BouncyCastle, so the call must not
// be rewritten to it: that link chained ehcache into bcprov findings.
func TestArtifactScope_SimpleNameBytecodeRewriteStaysInCompilingArtifacts(t *testing.T) {
	ehcache := artifactFixture{module: "net.sf.ehcache:ehcache-core", version: "2.6.2", files: map[string]string{
		"net/sf/ehcache/util/lang/VicariousThreadLocal.java": `package net.sf.ehcache.util.lang;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
public class VicariousThreadLocal {
  private final ReferenceQueue<Object> queue = new ReferenceQueue<Object>();
  private Holder createHolder() { return new Holder(queue); }
  private static class Holder extends WeakReference<Object> {
    Holder(ReferenceQueue<Object> queue) { super(null, queue); }
  }
}
`,
	}}
	bcprov := artifactFixture{module: "org.bouncycastle:bcprov-jdk15on", version: "1.70", files: map[string]string{
		"org/bouncycastle/asn1/x509/Holder.java": `package org.bouncycastle.asn1.x509;
public class Holder {
  public Holder(Object o) {}
}
`,
	}}
	index := map[string][]methodSignature{
		"org.bouncycastle.asn1.x509.Holder.<init>": {{
			className: "Holder", methodName: "<init>", fullClass: "org.bouncycastle.asn1.x509.Holder", paramTypes: []string{"Object"},
		}},
	}
	caller := "net.sf.ehcache.util.lang.(VicariousThreadLocal).createHolder#0"
	bcHolder := "org.bouncycastle.asn1.x509.(Holder).<init>#1"

	graph := buildArtifactGraph(t, nil, ehcache, bcprov)
	rewriteJavaCallsFromIndex(graph, buildJavaMethodLookup(index))
	if hasCaller(graph, bcHolder, caller) {
		t.Fatalf("Callers[%s] = %v: ehcache does not compile against bcprov", bcHolder, graph.Callers[bcHolder])
	}

	// The same repair across a real dependency still applies.
	graph = buildArtifactGraph(t, map[string][]string{"net.sf.ehcache:ehcache-core": {"org.bouncycastle:bcprov-jdk15on"}}, ehcache, bcprov)
	rewriteJavaCallsFromIndex(graph, buildJavaMethodLookup(index))
	if !hasCaller(graph, bcHolder, caller) {
		t.Fatalf("Callers[%s] = %v, want %s when ehcache depends on bcprov", bcHolder, graph.Callers[bcHolder], caller)
	}
}
