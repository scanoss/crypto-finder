// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	javaECSpec = `package demo;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
    }
}
`
	javaECSpecUnknownCurve = `package demo;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("curveX"));
    }
}
`
	javaECSpecVariable = `package demo;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1");
        g.initialize(spec);
    }
}
`
	javaBCRSA = `package demo;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
public class K {
    void f() {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 3072, 80));
    }
}
`
	javaBCRSAUnresolved = `package demo;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
public class K {
    void f(int strength) {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), strength, 80));
    }
}
`
	javaBCDSAParameters = `package demo;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
public class K {
    void f() {
        DSAParametersGenerator g = new DSAParametersGenerator();
        g.init(1024, 80, new SecureRandom());
    }
}
`
	javaBCDSAGenerationParameters = `package demo;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
public class K {
    void f() {
        DSAParametersGenerator g = new DSAParametersGenerator();
        g.init(new DSAParameterGenerationParameters(2048, 256, 80, new SecureRandom()));
    }
}
`
	javaBCDH = `package demo;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
public class K {
    void f() {
        DHParametersGenerator g = new DHParametersGenerator();
        g.init(2048, 80, new SecureRandom());
    }
}
`
	javaBCElGamal = `package demo;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
public class K {
    void f() {
        ElGamalParametersGenerator g = new ElGamalParametersGenerator();
        g.init(3072, 80, new SecureRandom());
    }
}
`
	pythonECConstructor = `from cryptography.hazmat.primitives.asymmetric import ec

def f():
    return ec.generate_private_key(ec.%s())
`
	pythonECKeyword = `from cryptography.hazmat.primitives.asymmetric import ec

def f():
    return ec.generate_private_key(curve=ec.SECP256R1())
`
	pythonECVariable = `from cryptography.hazmat.primitives.asymmetric import ec

def f():
    curve = ec.SECP521R1()
    return ec.generate_private_key(curve)
`
	pythonECUnresolved = `from cryptography.hazmat.primitives.asymmetric import ec

def f(curve):
    return ec.generate_private_key(curve)
`
	goECDSA = `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func f() {
	ecdsa.GenerateKey(elliptic.%s(), rand.Reader)
}

func main() { f() }
`
	goECDSAUnresolved = `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func f(c elliptic.Curve) {
	ecdsa.GenerateKey(c, rand.Reader)
}

func main() { f(nil) }
`
	goDSAParameters = `package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func f() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.%s)
}

func main() { f() }
`
	goDSAUnresolved = `package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func f(size dsa.ParameterSizes) {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, size)
}

func main() { f(dsa.L1024N160) }
`
)

// TestKeygenParameterKeyLength_ExactBitsThroughSupportingCallIDs pins the key
// size each key-generation parameter shape reports, read the way consumers read
// it: the finding graph's supporting_call_ids joined to
// supporting_calls[].supporting_call.resolved_key_length. A zero wantBits
// asserts the size is absent, never guessed.
func TestKeygenParameterKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	const (
		ecInit   = "java.security.spec.ECGenParameterSpec.<init>"
		jcaInit  = "java.security.KeyPairGenerator.initialize"
		bcRSA    = "org.bouncycastle.crypto.params.RSAKeyGenerationParameters.<init>"
		bcRSAGen = "org.bouncycastle.crypto.generators.RSAKeyPairGenerator.init"
		bcDSAGen = "org.bouncycastle.crypto.generators.DSAParametersGenerator.init"
		pyEC     = "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key"
	)
	type tc struct {
		name      string
		ecosystem string
		file      string
		source    string
		line      int
		match     string
		api       string
		wantFunc  string
		wantIndex int
		wantBits  int
	}
	cases := []tc{
		// Java JCA EC: the spec constructor and the initialize call that
		// receives it must agree, and neither may read the curve name as a size.
		{"jca ec spec constructor", "java", "K.java", javaECSpec, 7, `new ECGenParameterSpec("secp256r1")`, ecInit, ecInit, 0, 256},
		{"jca ec initialize(spec)", "java", "K.java", javaECSpec, 7, `g.initialize(new ECGenParameterSpec("secp256r1"))`, jcaInit, jcaInit, 0, 256},
		{"jca ec initialize(spec variable)", "java", "K.java", javaECSpecVariable, 8, "g.initialize(spec)", jcaInit, jcaInit, 0, 384},
		{"jca ec unknown curve spec constructor", "java", "K.java", javaECSpecUnknownCurve, 7, `new ECGenParameterSpec("curveX")`, ecInit, ecInit, 0, 0},
		{"jca ec unknown curve initialize(spec)", "java", "K.java", javaECSpecUnknownCurve, 7, `g.initialize(new ECGenParameterSpec("curveX"))`, jcaInit, jcaInit, 0, 0},

		// BouncyCastle: strength is index 2 of RSAKeyGenerationParameters and
		// reaches the generator's init(params) through the argument source.
		{"bc rsa parameters constructor", "java", "K.java", javaBCRSA, 9, "new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 3072, 80)", bcRSA, bcRSA, 2, 3072},
		{"bc rsa generator init(params)", "java", "K.java", javaBCRSA, 9, "g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 3072, 80))", bcRSAGen, bcRSAGen, 2, 3072},
		{"bc rsa unresolved strength", "java", "K.java", javaBCRSAUnresolved, 9, "g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), strength, 80))", bcRSAGen, bcRSAGen, 2, 0},
		{"bc dsa parameters generator", "java", "K.java", javaBCDSAParameters, 7, "g.init(1024, 80, new SecureRandom())", bcDSAGen, bcDSAGen, 0, 1024},
		{"bc dsa generation parameters", "java", "K.java", javaBCDSAGenerationParameters, 8, "g.init(new DSAParameterGenerationParameters(2048, 256, 80, new SecureRandom()))", "org.bouncycastle.crypto.generators.DSAParametersGenerator.init", "org.bouncycastle.crypto.generators.DSAParametersGenerator.init", 0, 2048},
		{"bc dh parameters generator", "java", "K.java", javaBCDH, 7, "g.init(2048, 80, new SecureRandom())", "org.bouncycastle.crypto.generators.DHParametersGenerator.init", "org.bouncycastle.crypto.generators.DHParametersGenerator.init", 0, 2048},
		{"bc elgamal parameters generator", "java", "K.java", javaBCElGamal, 7, "g.init(3072, 80, new SecureRandom())", "org.bouncycastle.crypto.generators.ElGamalParametersGenerator.init", "org.bouncycastle.crypto.generators.ElGamalParametersGenerator.init", 0, 3072},

		// Python cryptography EC: the curve constructor names the size.
		{"python ec keyword curve", "python", "k.py", pythonECKeyword, 4, "ec.generate_private_key(curve=ec.SECP256R1())", pyEC, pyEC, 0, 256},
		// The Python parser keeps no source for a local variable, so a curve bound
		// to a name is not traced; the size stays absent.
		{"python ec curve local variable", "python", "k.py", pythonECVariable, 5, "ec.generate_private_key(curve)", pyEC, pyEC, 0, 0},
		{"python ec curve parameter", "python", "k.py", pythonECUnresolved, 4, "ec.generate_private_key(curve)", pyEC, pyEC, 0, 0},
	}
	for _, curve := range []struct {
		name string
		bits int
	}{
		{"SECP192R1", 192},
		{"SECP224R1", 224},
		{"SECP256K1", 256},
		{"SECP256R1", 256},
		{"SECP384R1", 384},
		{"SECP521R1", 521},
		{"BrainpoolP256R1", 256},
		{"BrainpoolP384R1", 384},
		{"BrainpoolP512R1", 512},
		{"SECT163K1", 163},
		{"SECT283R1", 283},
		{"SECT571K1", 571},
		{"SECP999R9", 0},
	} {
		source := fmt.Sprintf(pythonECConstructor, curve.name)
		cases = append(cases, tc{"python ec " + curve.name, "python", "k.py", source, 4, fmt.Sprintf("ec.generate_private_key(ec.%s())", curve.name), pyEC, pyEC, 0, curve.bits})
	}
	for _, curve := range []struct {
		name string
		bits int
	}{{"P224", 224}, {"P256", 256}, {"P384", 384}, {"P521", 521}, {"P999", 0}} {
		source := fmt.Sprintf(goECDSA, curve.name)
		cases = append(cases, tc{"go ecdsa " + curve.name, "go", "k.go", source, 10, fmt.Sprintf("ecdsa.GenerateKey(elliptic.%s(), rand.Reader)", curve.name), "crypto/ecdsa.GenerateKey", "crypto/ecdsa.GenerateKey", 0, curve.bits})
	}
	cases = append(cases, tc{"go ecdsa curve variable", "go", "k.go", goECDSAUnresolved, 10, "ecdsa.GenerateKey(c, rand.Reader)", "crypto/ecdsa.GenerateKey", "crypto/ecdsa.GenerateKey", 0, 0})
	for _, set := range []struct {
		name string
		bits int
	}{{"L1024N160", 1024}, {"L2048N224", 2048}, {"L2048N256", 2048}, {"L3072N256", 3072}} {
		source := fmt.Sprintf(goDSAParameters, set.name)
		cases = append(cases, tc{"go dsa " + set.name, "go", "k.go", source, 10, fmt.Sprintf("dsa.GenerateParameters(&params, rand.Reader, dsa.%s)", set.name), "crypto/dsa.GenerateParameters", "crypto/dsa.GenerateParameters", 2, set.bits})
	}
	cases = append(cases, tc{"go dsa parameter-set variable", "go", "k.go", goDSAUnresolved, 10, "dsa.GenerateParameters(&params, rand.Reader, size)", "crypto/dsa.GenerateParameters", "crypto/dsa.GenerateParameters", 2, 0})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(strings.Split(c.source, "\n")[c.line-1], c.match) {
				t.Fatalf("line %d of the fixture does not contain %q: an absent size would be vacuous", c.line, c.match)
			}
			exports := terminalExports(t, c.ecosystem, c.file, c.source, c.line, c.match, c.api, "")
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
				if got.Provenance != keyLengthProvenanceConstant || got.SourceCall.ParameterIndex != c.wantIndex {
					t.Fatalf("%s: provenance/source = %#v, want constant at parameter %d", name, got, c.wantIndex)
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

// TestKeygenParameterKeyLength_SpecOverloadIsNotTypedAsInt pins the root of the
// EC initialize defect: initialize(new ECGenParameterSpec(..)) must not export
// the contract's initialize(int) signature, which is a different overload.
func TestKeygenParameterKeyLength_SpecOverloadIsNotTypedAsInt(t *testing.T) {
	exports := terminalExports(t, "java", "K.java", javaECSpec, 7, `g.initialize(new ECGenParameterSpec("secp256r1"))`, "java.security.KeyPairGenerator.initialize", "")
	found := false
	for i := range exports.live.SupportingCalls {
		call := exports.live.SupportingCalls[i].SupportingCall
		if call == nil || call.FunctionName != "java.security.KeyPairGenerator.initialize" {
			continue
		}
		found = true
		for _, parameterType := range call.ParameterTypes {
			if parameterType == "int" {
				t.Fatalf("initialize(spec) exported as %s, want no int overload", call.CanonicalSignature)
			}
		}
	}
	if !found {
		t.Fatal("no initialize supporting call exported")
	}
}
