// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	jcaKPG       = "java.security.KeyPairGenerator.initialize"
	jcaKPGGet    = "java.security.KeyPairGenerator.getInstance"
	jcaKG        = "javax.crypto.KeyGenerator.init"
	jcaKGGet     = "javax.crypto.KeyGenerator.getInstance"
	javaKGHeader = `package demo;
import javax.crypto.KeyGenerator;
public class K {
`
	javaKPGHeader = `package demo;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
public class K {
    static class Pair implements java.security.spec.AlgorithmParameterSpec {
        Pair(java.security.spec.AlgorithmParameterSpec a, java.security.spec.AlgorithmParameterSpec b) {}
    }
`
)

func kgSource(params, body string) string {
	return javaKGHeader + "    void f(" + params + ") throws Exception {\n" +
		"        KeyGenerator kg = KeyGenerator.getInstance(\"AES\");\n" + body + "    }\n}\n"
}

func kpgSource(body string) string {
	return javaKPGHeader + "    void f() throws Exception {\n" +
		"        KeyPairGenerator g = KeyPairGenerator.getInstance(\"EC\");\n" + body + "    }\n}\n"
}

// TestJavaLocalKeyLength_OnlyASingleSourceResolves pins that a Java local or
// parameter written again after its declaration has no single source: the
// declaration's value is only one of the values the key generator may see, so
// the size stays absent. A local written once, at its declaration, still
// resolves, and so does a final one.
func TestJavaLocalKeyLength_OnlyASingleSourceResolves(t *testing.T) {
	type tc struct {
		name     string
		source   string
		match    string
		api      string
		wantFunc string
		wantBits int
	}
	kgMatch := `KeyGenerator.getInstance("AES")`
	kpgMatch := `KeyPairGenerator.getInstance("EC")`
	cases := []tc{
		{"single assignment resolves", kgSource("", "        int n = 256;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 256},
		{"final local resolves", kgSource("", "        final int n = 192;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 192},
		{"reassigned int", kgSource("", "        int n = 128;\n        n = 256;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"reassigned in a branch", kgSource("boolean b", "        int n = 128;\n        if (b) { n = 256; }\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"reassigned in a loop", kgSource("", "        int n = 128;\n        for (int i = 0; i < 2; i++) { n = 256; }\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"compound assignment", kgSource("", "        int n = 128;\n        n += 128;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"increment", kgSource("", "        int n = 127;\n        n++;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"reassigned parameter", kgSource("int n", "        n = 256;\n        kg.init(n);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{"ternary", kgSource("boolean b", "        kg.init(b ? 128 : 256);\n"), kgMatch, jcaKGGet, jcaKG, 0},
		{
			"declared in a nested block and reassigned",
			kgSource("", "        {\n            int n = 128;\n            n = 256;\n            kg.init(n);\n        }\n"),
			kgMatch, jcaKGGet, jcaKG, 0,
		},
		{
			"declared in a nested block, single assignment",
			kgSource("", "        {\n            int n = 192;\n            kg.init(n);\n        }\n"),
			kgMatch, jcaKGGet, jcaKG, 192,
		},
		{
			"reassigned ECGenParameterSpec",
			kpgSource("        ECGenParameterSpec s = new ECGenParameterSpec(\"secp256r1\");\n        s = new ECGenParameterSpec(\"secp384r1\");\n        g.initialize(s);\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 0,
		},
		{
			"single ECGenParameterSpec",
			kpgSource("        ECGenParameterSpec s = new ECGenParameterSpec(\"secp384r1\");\n        g.initialize(s);\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 384,
		},
		{
			"reassigned BouncyCastle X9ECParameters",
			bcECDomainSource("", `        X9ECParameters p = ECNamedCurveTable.getByName("secp256r1");
        p = ECNamedCurveTable.getByName("secp384r1");
        ECDomainParameters d = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0,
		},
		{
			"look-alike lookup in another package",
			strings.Replace(bcECDomainSource("", `        X9ECParameters p = ECNamedCurveTable.getByName("secp256r1");
        ECDomainParameters d = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
`+bcECGeneratorTail), "import org.bouncycastle.asn1.x9.ECNamedCurveTable;", "import com.acme.ECNamedCurveTable;", 1),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0,
		},
		// Producers behind one argument must agree, whatever library they are from.
		{
			"two ECGenParameterSpec producers that disagree",
			kpgSource("        g.initialize(new Pair(new ECGenParameterSpec(\"secp256r1\"), new ECGenParameterSpec(\"secp384r1\")));\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 0,
		},
		{
			"two ECGenParameterSpec producers that agree",
			kpgSource("        g.initialize(new Pair(new ECGenParameterSpec(\"secp256r1\"), new ECGenParameterSpec(\"secp256r1\")));\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 256,
		},
		{
			"two RSAKeyGenParameterSpec producers that disagree",
			kpgSource("        g.initialize(new Pair(new RSAKeyGenParameterSpec(2048, BigInteger.TEN), new RSAKeyGenParameterSpec(3072, BigInteger.TEN)));\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 0,
		},
		{
			"two RSAKeyGenParameterSpec producers that agree",
			kpgSource("        g.initialize(new Pair(new RSAKeyGenParameterSpec(3072, BigInteger.TEN), new RSAKeyGenParameterSpec(3072, BigInteger.TEN)));\n"),
			kpgMatch, jcaKPGGet, jcaKPG, 3072,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := bcECLineOf(c.source, c.match)
			if line == 0 {
				t.Fatalf("fixture does not contain %q: an absent size would be vacuous", c.match)
			}
			exports := terminalExports(t, "java", "K.java", c.source, line, c.match, c.api, "")
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, c.wantFunc),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, c.wantFunc),
			} {
				if c.wantBits == 0 {
					if got != nil && got.Bits != nil {
						t.Fatalf("%s: resolved_key_length bits = %d, want absent", name, *got.Bits)
					}
					continue
				}
				if got == nil || got.Bits == nil || *got.Bits != c.wantBits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, c.wantBits)
				}
			}
			for i := range exports.live.SupportingCalls {
				call := exports.live.SupportingCalls[i].SupportingCall
				if call == nil || call.ResolvedKeyLength == nil || call.ResolvedKeyLength.Bits == nil {
					continue
				}
				if c.wantBits == 0 {
					t.Fatalf("supporting call %s carries %d bits, want none", call.FunctionName, *call.ResolvedKeyLength.Bits)
				}
			}
		})
	}
}
