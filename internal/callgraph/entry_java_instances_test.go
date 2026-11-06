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

import "testing"

// javaInstanceApp is a Java program whose main never touches Handler, an
// application class with an uncalled instance method that reaches the
// crypto. handler is the Handler class declaration line (annotations,
// modifiers, extends) and extra are more files.
func javaInstanceApp(main, handler string, extra map[string]string) scopeCase {
	files := map[string]string{
		"pom.xml": "<project/>\n",
		"src/main/java/app/Main.java": `package app;

public final class Main {
    public static void main(String[] args) {
` + main + `
    }
}
`,
		"src/main/java/app/Digests.java": `package app;

import java.security.MessageDigest;

final class Digests {
    static byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
`,
		"src/main/java/app/Handler.java": `package app;

` + handler + ` {
    private final int size = 1;

    public byte[] apply(byte[] data) throws Exception {
        return Digests.digest(data);
    }
}
`,
	}
	for name, content := range extra {
		files[name] = content
	}
	return scopeCase{ecosystem: "java", parser: javaParser, target: "digest", dirs: []string{"src/main/java"}, files: files}
}

// TestUncalledRoots_JavaInstanceMethodOfAClassNothingCreates: an instance
// method runs only on an instance; when the application never creates its
// class, registers it or lets a framework do so, it is dead code.
func TestUncalledRoots_JavaInstanceMethodOfAClassNothingCreates(t *testing.T) {
	t.Parallel()
	hello := `        System.out.println("GET /apply?data=hello");`
	for name, c := range map[string]scopeCase{
		"plain class":         javaInstanceApp(hello, "public class Handler", nil),
		"inert annotation":    javaInstanceApp(hello, "@Deprecated\n@SuppressWarnings(\"unused\")\npublic class Handler", nil),
		"application parent":  javaInstanceApp(hello, "public class Handler extends Base", map[string]string{"src/main/java/app/Base.java": "package app;\n\nabstract class Base {}\n"}),
		"application iface":   javaInstanceApp(hello, "public class Handler implements Op", map[string]string{"src/main/java/app/Op.java": "package app;\n\ninterface Op { byte[] apply(byte[] d) throws Exception; }\n"}),
		"other class created": javaInstanceApp("        new Other().run();", "public class Handler", map[string]string{"src/main/java/app/Other.java": "package app;\n\nclass Other { void run() {} }\n"}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantUnreachable(t, c.trace(t))
		})
	}
}

// TestUncalledRoots_JavaInstanceMethodOfALiveClassStaysARoot: a class the
// application creates, names reflectively or in configuration, a framework
// may manage, or that reaches outside the application keeps its uncalled
// instance methods roots.
func TestUncalledRoots_JavaInstanceMethodOfALiveClassStaysARoot(t *testing.T) {
	t.Parallel()
	hello := `        System.out.println("hello");`
	sub := map[string]string{"src/main/java/app/Special.java": "package app;\n\nclass Special extends Handler {}\n"}
	for name, c := range map[string]scopeCase{
		"new":                   javaInstanceApp(`        Object h = new Handler();`, "public class Handler", nil),
		"anonymous subclass":    javaInstanceApp(`        Object h = new Handler() {};`, "public class Handler", nil),
		"constructor reference": javaInstanceApp(`        java.util.function.Supplier<Object> s = Handler::new;`, "public class Handler", nil),
		"class literal":         javaInstanceApp(`        register(Handler.class);`, "public class Handler", nil),
		"type argument":         javaInstanceApp(`        Object r = new Ref<Handler>() {};`, "public class Handler", nil),
		"reflection string":     javaInstanceApp(`        Class.forName("app.Handler");`, "public class Handler", nil),
		"subclass created":      javaInstanceApp(`        Object h = new Special();`, "public class Handler", sub),
		"framework annotation":  javaInstanceApp(hello, "@RestController\npublic class Handler", nil),
		"unknown annotation":    javaInstanceApp(hello, "@Managed public class Handler", nil),
		"external interface":    javaInstanceApp(hello, "public class Handler implements java.util.function.Supplier<String>", nil),
		"external parent":       javaInstanceApp(hello, "public class Handler extends Thread", nil),
		"external via app parent": javaInstanceApp(hello, "public class Handler extends Base", map[string]string{
			"src/main/java/app/Base.java": "package app;\n\nabstract class Base implements Runnable {}\n",
		}),
		"spring xml": javaInstanceApp(hello, "public class Handler", map[string]string{
			"src/main/resources/beans.xml": "<beans><bean id=\"h\" class=\"app.Handler\"/></beans>\n",
		}),
		"service loader": javaInstanceApp(hello, "public class Handler", map[string]string{
			"src/main/resources/META-INF/services/app.Op": "app.Handler\n",
		}),
		"created in a package named build": javaInstanceApp(hello, "public class Handler", map[string]string{
			"src/main/java/app/build/Factory.java": "package app.build;\n\nimport app.Handler;\n\npublic class Factory {\n    public static Object make() { return new Handler(); }\n}\n",
		}),
		"enum": javaInstanceApp(hello, "public enum Handler", nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			trace := c
			if name == "enum" {
				// An enum body starts with its constants.
				trace.files = map[string]string{}
				for k, v := range c.files {
					trace.files[k] = v
				}
				trace.files["src/main/java/app/Handler.java"] = "package app;\n\npublic enum Handler {\n    ONE;\n\n    public byte[] apply(byte[] data) throws Exception {\n        return Digests.digest(data);\n    }\n}\n"
			}
			wantNoCallersRoot(t, trace.trace(t), "apply")
		})
	}
}

// TestJavaClassFacts_DuplicateClassIsLive: two modules declaring the same
// fully qualified class leave it unknown which one a method belongs to, so
// the class is live whichever file is read first.
func TestJavaClassFacts_DuplicateClassIsLive(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"a/src/main/java/app/Handler.java": "package app;\n\n@Component\npublic class Handler {}\n",
		"b/src/main/java/app/Handler.java": "package app;\n\npublic class Handler {}\n",
	})
	for _, order := range [][]string{{"a", "b"}, {"b", "a"}} {
		sources := []string{
			root + "/" + order[0] + "/src/main/java/app/Handler.java",
			root + "/" + order[1] + "/src/main/java/app/Handler.java",
		}
		if !newJavaClassFacts(sources, nil).live("app.Handler") {
			t.Errorf("read %v first: app.Handler not live, want live", order[0])
		}
	}
}
