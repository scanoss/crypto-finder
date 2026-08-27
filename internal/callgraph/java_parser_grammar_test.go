package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseJavaSourceCalls parses one Java source file and returns every call it
// records, keyed as "<package>.<Type>.<name>".
func parseJavaSourceCalls(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "P.java"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "com.example")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var keys []string
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				callee := &fn.Calls[j].Callee
				keys = append(keys, callee.Package+"."+callee.Type+"."+callee.Name)
			}
		}
	}
	return keys
}

func assertJavaCall(t *testing.T, src, want string) {
	t.Helper()
	keys := parseJavaSourceCalls(t, src)
	for _, key := range keys {
		if key == want {
			return
		}
	}
	t.Fatalf("missing call %q; recorded: %v", want, keys)
}

// TestJavaParser_EnumAndRecordDeclarations covers the type declarations the
// walk used to skip outright: an enum, a record and their bodies produced no
// FunctionDecls at all, so crypto inside them was invisible. JLS 8.9, 8.10.
func TestJavaParser_EnumAndRecordDeclarations(t *testing.T) {
	tests := []struct {
		name string
		want string
		src  string
	}{
		{
			name: "enum method",
			want: "javax.crypto.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.Cipher;
enum Provider { INSTANCE; Cipher make() throws Exception { return Cipher.getInstance("AES"); } }`,
		},
		{
			name: "record method",
			want: "javax.crypto.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.Cipher;
record Key(byte[] material) { Cipher make() throws Exception { return Cipher.getInstance("AES"); } }`,
		},
		{
			name: "enum constant body",
			want: "java.security.MessageDigest.getInstance#1",
			src: `package com.example;
import java.security.MessageDigest;
enum Hash {
    MD5 { public MessageDigest get() throws Exception { return MessageDigest.getInstance("MD5"); } };
    public abstract MessageDigest get() throws Exception;
}`,
		},
		{
			name: "enum nested in class",
			want: "javax.crypto.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.Cipher;
class Outer { enum Inner { ONE; Cipher make() throws Exception { return Cipher.getInstance("AES"); } } }`,
		},
		{
			name: "enum static initializer",
			want: "java.security.MessageDigest.getInstance#1",
			src: `package com.example;
import java.security.MessageDigest;
enum Registry {
    INSTANCE;
    static final MessageDigest MD;
    static { try { MD = MessageDigest.getInstance("MD5"); } catch (Exception e) { throw new RuntimeException(e); } }
}`,
		},
		{
			name: "record compact constructor",
			want: "java.security.MessageDigest.getInstance#1",
			src: `package com.example;
import java.security.MessageDigest;
record Digest(byte[] b) { Digest { try { MessageDigest.getInstance("SHA-256"); } catch (Exception e) {} } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertJavaCall(t, tt.src, tt.want) })
	}
}

// TestJavaParser_PatternVariableBindings pins the receiver type of a pattern
// variable. Without the binding the walk adopted the variable's NAME as its
// type, yielding a fabricated `com.example.(c)` that matches no real class.
// JLS 14.30.1 (instanceof), 14.11.1 (switch patterns).
func TestJavaParser_PatternVariableBindings(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "instanceof pattern",
			src: `package com.example;
import javax.crypto.Cipher;
class C { void go(Object o) throws Exception { if (o instanceof Cipher c) { c.doFinal(new byte[0]); } } }`,
		},
		{
			name: "instanceof pattern with guard",
			src: `package com.example;
import javax.crypto.Cipher;
class C { void go(Object o) throws Exception { if (o instanceof Cipher c && c.getBlockSize() > 0) { c.doFinal(new byte[0]); } } }`,
		},
		{
			name: "switch pattern",
			src: `package com.example;
import javax.crypto.Cipher;
class C { void go(Object o) throws Exception { switch (o) { case Cipher c -> c.doFinal(new byte[0]); default -> {} } } }`,
		},
		{
			name: "record pattern component",
			src: `package com.example;
import javax.crypto.Cipher;
record Box(Cipher c) {}
class C { void go(Object o) throws Exception { if (o instanceof Box(Cipher c)) { c.doFinal(new byte[0]); } } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJavaCall(t, tt.src, "javax.crypto.Cipher.doFinal#1")
		})
	}
}

// TestJavaParser_ThisQualifiedReceivers pins receivers qualified by `this`.
// `this` is a keyword, never a type name, so left as text it became the
// package or type of the callee: `this.(cipher).doFinal`. JLS 15.8.3, 15.8.4.
func TestJavaParser_ThisQualifiedReceivers(t *testing.T) {
	tests := []struct {
		name string
		want string
		src  string
	}{
		{
			name: "bare field receiver stays resolved",
			want: "javax.crypto.Cipher.doFinal#1",
			src: `package com.example;
import javax.crypto.Cipher;
class C { Cipher cipher; void go() throws Exception { cipher.doFinal(new byte[0]); } }`,
		},
		{
			name: "this qualified field",
			want: "javax.crypto.Cipher.doFinal#1",
			src: `package com.example;
import javax.crypto.Cipher;
class C { Cipher cipher; void go() throws Exception { this.cipher.doFinal(new byte[0]); } }`,
		},
		{
			name: "this qualified method",
			want: "com.example.C.id#1",
			src: `package com.example;
class C { <T> T id(T t) { return t; } void go() { this.id("x"); } }`,
		},
		{
			name: "qualified this method",
			want: "com.example.Outer.enc#0",
			src: `package com.example;
class Outer { void enc() {} class In { void go() { Outer.this.enc(); } } }`,
		},
		{
			name: "identifier merely starting with this is untouched",
			want: "com.example.C.m#0",
			src: `package com.example;
class C { C thisHolder; void m() {} void go() { thisHolder.m(); } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertJavaCall(t, tt.src, tt.want) })
	}
}

// TestJavaParser_BlockScopedDeclarations pins lexical scoping. A single flat
// map per method let the last declaration of a name win for every call in the
// method, so two sibling blocks that both declare `c` resolved to whichever
// came last — reporting an AES Cipher as a Mac. JLS 6.3, 14.14.
func TestJavaParser_BlockScopedDeclarations(t *testing.T) {
	t.Run("sibling blocks", func(t *testing.T) {
		keys := parseJavaSourceCalls(t, `package com.example;
import javax.crypto.Cipher;
import javax.crypto.Mac;
class C {
    void go() throws Exception {
        { Cipher c = Cipher.getInstance("AES");        c.doFinal(new byte[0]); }
        { Mac    c = Mac.getInstance("HmacSHA256");    c.doFinal(new byte[0]); }
    }
}`)
		assertContains(t, keys, "javax.crypto.Cipher.doFinal#1")
		assertContains(t, keys, "javax.crypto.Mac.doFinal#1")
	})

	t.Run("sibling loop variables", func(t *testing.T) {
		keys := parseJavaSourceCalls(t, `package com.example;
import javax.crypto.Cipher;
import javax.crypto.Mac;
class C {
    void go(Cipher[] cs, Mac[] ms) throws Exception {
        for (Cipher x : cs) { x.doFinal(new byte[0]); }
        for (Mac    x : ms) { x.doFinal(new byte[0]); }
    }
}`)
		assertContains(t, keys, "javax.crypto.Cipher.doFinal#1")
		assertContains(t, keys, "javax.crypto.Mac.doFinal#1")
	})

	t.Run("nested block shadows only within itself", func(t *testing.T) {
		keys := parseJavaSourceCalls(t, `package com.example;
import javax.crypto.Cipher;
import javax.crypto.Mac;
class C {
    void go() throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.doFinal(new byte[0]);
        { Mac m = Mac.getInstance("HmacSHA256"); m.doFinal(new byte[0]); }
        c.doFinal(new byte[1]);
    }
}`)
		outer := 0
		for _, key := range keys {
			if key == "javax.crypto.Cipher.doFinal#1" {
				outer++
			}
		}
		if outer != 2 {
			t.Fatalf("outer Cipher receiver resolved %d times, want 2; recorded: %v", outer, keys)
		}
		assertContains(t, keys, "javax.crypto.Mac.doFinal#1")
	})
}

// TestJavaParser_BlockScopedArgumentTracing is the argument-tracing half of the
// scoping fix: the same flat map backed the data flow, so a shadowed name made
// a call trace to another block's literal — reporting an AES transformation
// string as a DES one, in the field rules delegate to this layer to resolve.
func TestJavaParser_BlockScopedArgumentTracing(t *testing.T) {
	dir := t.TempDir()
	src := `package com.example;
import javax.crypto.Cipher;
class C {
    void go() throws Exception {
        { String alg = "AES/GCM/NoPadding";    Cipher.getInstance(alg); }
        { String alg = "DES/ECB/PKCS5Padding"; Cipher.getInstance(alg); }
    }
}`
	if err := os.WriteFile(filepath.Join(dir, "P.java"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "com.example")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	traced := map[int]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				for _, sources := range call.ArgumentSources {
					for k := range sources {
						for _, inner := range sources[k].SourceNodes {
							traced[call.Line] = strings.Trim(inner.Value, `"`)
						}
					}
				}
			}
		}
	}
	if got := traced[5]; got != "AES/GCM/NoPadding" {
		t.Fatalf("line 5 traced to %q, want AES/GCM/NoPadding (traced: %v)", got, traced)
	}
	if got := traced[6]; got != "DES/ECB/PKCS5Padding" {
		t.Fatalf("line 6 traced to %q, want DES/ECB/PKCS5Padding (traced: %v)", got, traced)
	}
}

// TestJavaParser_MethodReferences records a method reference as a call to its
// target. The name carries no arity suffix: a reference fixes its arity through
// the functional interface it is assigned to, not at this site. JLS 15.13.
func TestJavaParser_MethodReferences(t *testing.T) {
	tests := []struct {
		name string
		want string
		src  string
	}{
		{
			name: "static method reference",
			want: "javax.crypto.Cipher.getInstance",
			src: `package com.example;
import javax.crypto.Cipher;
import java.util.function.Function;
class C { void go() { Function<String, Cipher> f = Cipher::getInstance; } }`,
		},
		{
			name: "constructor reference",
			want: "java.security.MessageDigest.<init>",
			src: `package com.example;
import java.security.MessageDigest;
import java.util.function.Supplier;
class C { void go() { Supplier<MessageDigest> s = MessageDigest::new; } }`,
		},
		{
			name: "this bound reference",
			want: "com.example.C.helper",
			src: `package com.example;
import java.util.function.Supplier;
class C { String helper() { return ""; } void go() { Supplier<String> s = this::helper; } }`,
		},
		{
			name: "instance bound reference",
			want: "javax.crypto.Cipher.doFinal",
			src: `package com.example;
import javax.crypto.Cipher;
import java.util.function.Function;
class C { void go(Cipher c) { Function<byte[], byte[]> f = c::doFinal; } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertJavaCall(t, tt.src, tt.want) })
	}
}

func assertContains(t *testing.T, keys []string, want string) {
	t.Helper()
	for _, key := range keys {
		if key == want {
			return
		}
	}
	t.Fatalf("missing call %q; recorded: %v", want, keys)
}

// TestJavaParser_DeclaredTypeShadowsWildcardImport pins JLS 6.4.1 / 7.5.2: a
// type declared in this compilation unit shadows an on-demand import of the
// same simple name. Checked the other way round, a user class named `Cipher`
// next to `import javax.crypto.*;` was attributed to javax.crypto, inventing a
// library finding for code that never touches the library. BouncyCastle's own
// `org.bouncycastle.util.Arrays` is a real instance of this shape.
func TestJavaParser_DeclaredTypeShadowsWildcardImport(t *testing.T) {
	tests := []struct {
		name string
		want string
		src  string
	}{
		{
			name: "declared before use",
			want: "com.example.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.*;
class Cipher { static Cipher getInstance(String s) { return null; } }
class C { void go() { Cipher.getInstance("AES"); } }`,
		},
		{
			name: "declared after use",
			want: "com.example.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.*;
class C { void go() { Cipher.getInstance("AES"); } }
class Cipher { static Cipher getInstance(String s) { return null; } }`,
		},
		{
			name: "wildcard still wins when nothing is declared",
			want: "javax.crypto.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.*;
class C { void go() throws Exception { Cipher.getInstance("AES"); } }`,
		},
		{
			name: "single type import still wins",
			want: "org.mine.Cipher.getInstance#1",
			src: `package com.example;
import javax.crypto.*;
import org.mine.Cipher;
class C { void go() throws Exception { Cipher.getInstance("AES"); } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertJavaCall(t, tt.src, tt.want) })
	}
}

// TestJavaParser_TypeParameterErasure pins JLS 4.4: a receiver typed by a class
// type parameter erases to that parameter's first bound. Unerased, `T` reached
// the fallback and was emitted as a fabricated `com.example.(T)`.
func TestJavaParser_TypeParameterErasure(t *testing.T) {
	tests := []struct {
		name string
		want string
		src  string
	}{
		{
			name: "bounded type parameter",
			want: "javax.crypto.Cipher.doFinal#1",
			src: `package com.example;
import javax.crypto.Cipher;
class C<T extends Cipher> { void go(T t) throws Exception { t.doFinal(new byte[0]); } }`,
		},
		{
			name: "first of several bounds",
			want: "javax.crypto.Cipher.doFinal#1",
			src: `package com.example;
import javax.crypto.Cipher;
import java.io.Serializable;
class C<T extends Cipher & Serializable> { void go(T t) throws Exception { t.doFinal(new byte[0]); } }`,
		},
		{
			name: "real class sharing a parameter name is untouched",
			want: "com.example.T.m#0",
			src: `package com.example;
class T { void m() {} }
class C { void go(T t) { t.m(); } }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertJavaCall(t, tt.src, tt.want) })
	}
}
