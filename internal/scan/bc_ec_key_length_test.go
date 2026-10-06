// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const bcECHeader = `package demo;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
public class K {
`

// bcECDomainSource wraps the body of one method in a class that imports every
// BouncyCastle EC type the cases use.
func bcECDomainSource(params, body string) string {
	return bcECHeader + "    void f(" + params + ") {\n" + body + "    }\n}\n"
}

const bcECGeneratorTail = `        ECKeyPairGenerator g = new ECKeyPairGenerator();
        g.init(new ECKeyGenerationParameters(d, new SecureRandom()));
`

const (
	bcECTable   = "org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName"
	bcECDomain  = "org.bouncycastle.crypto.params.ECDomainParameters.<init>"
	bcECParams  = "org.bouncycastle.crypto.params.ECKeyGenerationParameters.<init>"
	bcECGen     = "org.bouncycastle.crypto.generators.ECKeyPairGenerator.<init>"
	bcECGenInit = "org.bouncycastle.crypto.generators.ECKeyPairGenerator.init"
)

const (
	bcJceSpecHeader = `package demo;
import java.security.KeyPairGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
public class K {
    void f() throws Exception {
`
	bcJceNamedSpec = bcJceSpecHeader + `        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp384r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        g.initialize(spec);
    }
}
`
	bcJceGenSpec = bcJceSpecHeader + `        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        g.initialize(new ECNamedCurveGenParameterSpec("secp256k1"));
    }
}
`
	bcJceGenSpecUnknown = bcJceSpecHeader + `        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        g.initialize(new ECNamedCurveGenParameterSpec("curveX"));
    }
}
`
)

// TestBouncyCastleECKeyLength_ExactBitsThroughSupportingCallIDs pins the curve
// size a BouncyCastle EC key generator reports when the curve is named by a
// literal, read the way consumers read it: finding_graphs[].supporting_call_ids
// joined to supporting_calls[].supporting_call.resolved_key_length, live and
// stitched. A zero wantBits asserts the size is absent, never guessed. Every
// carrier on a graph must agree.
func TestBouncyCastleECKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	type tc struct {
		name     string
		source   string
		match    string
		api      string
		wantFunc string
		wantBits int
	}
	named := func(table, curve string) string {
		return bcECDomainSource("", fmt.Sprintf(`        X9ECParameters p = %s.getByName("%s");
        ECDomainParameters d = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
`, table, curve)+bcECGeneratorTail)
	}
	cases := []tc{
		// Generator, parameters, domain and lookup all name one curve.
		{"generator init(params)", named("ECNamedCurveTable", "secp256r1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 256},
		{"key generation parameters", named("ECNamedCurveTable", "secp256r1"), "new ECKeyGenerationParameters(d, new SecureRandom())", bcECParams, bcECParams, 256},
		{"domain parameters", named("ECNamedCurveTable", "secp256r1"), "new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH())", bcECDomain, bcECDomain, 256},
		{"named curve lookup", named("ECNamedCurveTable", "secp256r1"), `ECNamedCurveTable.getByName("secp256r1")`, bcECTable, bcECTable, 256},
		{"secp384r1", named("ECNamedCurveTable", "secp384r1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 384},
		{"secp521r1 is 521 bits", named("ECNamedCurveTable", "secp521r1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 521},
		{"NIST alias P-256", named("ECNamedCurveTable", "P-256"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 256},
		{"binary curve sect163k1", named("ECNamedCurveTable", "sect163k1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 163},
		{"SECNamedCurves", named("SECNamedCurves", "secp256k1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 256},
		{"NISTNamedCurves", named("NISTNamedCurves", "P-384"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 384},
		{"TeleTrusTNamedCurves", named("TeleTrusTNamedCurves", "brainpoolP512r1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 512},
		{"CustomNamedCurves", named("CustomNamedCurves", "secp521r1"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 521},
		{"unknown curve name", named("ECNamedCurveTable", "curveX"), "new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0},
		{"unknown curve name lookup", named("ECNamedCurveTable", "curveX"), `ECNamedCurveTable.getByName("curveX")`, bcECTable, bcECTable, 0},
		{
			"constructor from X9ECParameters",
			bcECDomainSource("", `        X9ECParameters p = NISTNamedCurves.getByName("P-384");
        ECDomainParameters d = new ECDomainParameters(p);
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 384,
		},
		{
			"three-argument domain constructor",
			bcECDomainSource("", `        X9ECParameters p = ECNamedCurveTable.getByName("secp256r1");
        ECDomainParameters d = new ECDomainParameters(p.getCurve(), p.getG(), p.getN());
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 256,
		},
		{
			"curve name passed in",
			bcECDomainSource("String name", `        X9ECParameters p = ECNamedCurveTable.getByName(name);
        ECDomainParameters d = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0,
		},
		{
			"domain parameters passed in",
			bcECDomainSource("ECDomainParameters d", bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0,
		},
		// Two lookups feed one domain: neither curve is the key's size.
		{
			"disagreeing lookups: generator",
			bcECDomainSource("", `        X9ECParameters a = ECNamedCurveTable.getByName("secp256r1");
        X9ECParameters b = ECNamedCurveTable.getByName("secp384r1");
        ECDomainParameters d = new ECDomainParameters(a.getCurve(), b.getG(), b.getN(), b.getH());
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 0,
		},
		{
			"disagreeing lookups: domain",
			bcECDomainSource("", `        X9ECParameters a = ECNamedCurveTable.getByName("secp256r1");
        X9ECParameters b = ECNamedCurveTable.getByName("secp384r1");
        ECDomainParameters d = new ECDomainParameters(a.getCurve(), b.getG(), b.getN(), b.getH());
`+bcECGeneratorTail),
			"new ECDomainParameters(a.getCurve(), b.getG(), b.getN(), b.getH())", bcECDomain, bcECDomain, 0,
		},
		{
			"agreeing lookups",
			bcECDomainSource("", `        X9ECParameters a = ECNamedCurveTable.getByName("secp256r1");
        X9ECParameters b = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters d = new ECDomainParameters(a.getCurve(), b.getG(), b.getN(), b.getH());
`+bcECGeneratorTail),
			"new ECKeyPairGenerator()", bcECGen, bcECGenInit, 256,
		},

		// The JCA with the BouncyCastle provider.
		{"jce named parameter spec", bcJceNamedSpec, `g.initialize(spec)`, "java.security.KeyPairGenerator.initialize", "java.security.KeyPairGenerator.initialize", 384},
		{"jce named parameter spec lookup", bcJceNamedSpec, `ECNamedCurveTable.getParameterSpec("secp384r1")`, "org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec", "org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec", 384},
		{"jce gen parameter spec initialize", bcJceGenSpec, `g.initialize(new ECNamedCurveGenParameterSpec("secp256k1"))`, "java.security.KeyPairGenerator.initialize", "java.security.KeyPairGenerator.initialize", 256},
		{"jce gen parameter spec constructor", bcJceGenSpec, `new ECNamedCurveGenParameterSpec("secp256k1")`, "org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec.<init>", "org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec.<init>", 256},
		{"jce unknown curve initialize", bcJceGenSpecUnknown, `g.initialize(new ECNamedCurveGenParameterSpec("curveX"))`, "java.security.KeyPairGenerator.initialize", "java.security.KeyPairGenerator.initialize", 0},
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
				if got.Provenance != keyLengthProvenanceConstant {
					t.Fatalf("%s: provenance = %q, want constant", name, got.Provenance)
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
				if *call.ResolvedKeyLength.Bits != c.wantBits {
					t.Fatalf("supporting call %s carries %d bits, want every carrier on the graph to agree on %d", call.FunctionName, *call.ResolvedKeyLength.Bits, c.wantBits)
				}
			}
		})
	}
}

// bcECLineOf returns the 1-based line of source that contains match, or 0.
func bcECLineOf(source, match string) int {
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, match) {
			return i + 1
		}
	}
	return 0
}
