package contracts_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestJavaPQCContracts covers the post-quantum contracts of the Java KB:
// javax.crypto.KEM in jdk-crypto.yaml and the Bouncy Castle ML-KEM, ML-DSA,
// SLH-DSA and LMS/HSS files (bouncycastle-pqc, bouncycastle-pqc-1.84,
// bouncycastle-lms, bouncycastle-lms-1.86, bouncycastle-pqc-jcajce), one
// representative entry per file and per package spelling.
func TestJavaPQCContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method     string
		arity      int
		wantLib    string
		wantRole   string
		wantReturn string
	}{
		// JDK 21+ javax.crypto.KEM (nested classes in the dotted Owner.Nested form).
		{"javax.crypto.KEM.getInstance", 1, "jdk-crypto", "factory", "javax.crypto.KEM"},
		{"javax.crypto.KEM.getInstance", 2, "jdk-crypto", "factory", "javax.crypto.KEM"},
		{"javax.crypto.KEM.newEncapsulator", 1, "jdk-crypto", "factory", "javax.crypto.KEM.Encapsulator"},
		{"javax.crypto.KEM.newEncapsulator", 3, "jdk-crypto", "factory", "javax.crypto.KEM.Encapsulator"},
		{"javax.crypto.KEM.newDecapsulator", 2, "jdk-crypto", "factory", "javax.crypto.KEM.Decapsulator"},
		{"javax.crypto.KEM.Encapsulator.encapsulate", 0, "jdk-crypto", "operation", "javax.crypto.KEM.Encapsulated"},
		{"javax.crypto.KEM.Encapsulator.encapsulate", 3, "jdk-crypto", "operation", "javax.crypto.KEM.Encapsulated"},
		{"javax.crypto.KEM.Encapsulated.<init>", 3, "jdk-crypto", "factory", "javax.crypto.KEM.Encapsulated"},
		{"javax.crypto.KEM.Encapsulated.key", 0, "jdk-crypto", "output", "javax.crypto.SecretKey"},
		{"javax.crypto.KEM.Encapsulated.encapsulation", 0, "jdk-crypto", "output", "byte[]"},
		{"javax.crypto.KEM.Decapsulator.decapsulate", 1, "jdk-crypto", "operation", "javax.crypto.SecretKey"},
		{"javax.crypto.KEM.Decapsulator.decapsulate", 4, "jdk-crypto", "operation", "javax.crypto.SecretKey"},
		{"java.security.spec.NamedParameterSpec.<init>", 1, "jdk-crypto", "factory", "java.security.spec.AlgorithmParameterSpec"},

		// Bouncy Castle 1.79 to 1.85 package spelling (org.bouncycastle.pqc.crypto.*).
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator.<init>", 1, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator.generateEncapsulated", 1, "bouncycastle-pqc", "operation", "org.bouncycastle.crypto.SecretWithEncapsulation"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor.<init>", 1, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor.extractSecret", 1, "bouncycastle-pqc", "operation", "byte[]"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator.generateKeyPair", 0, "bouncycastle-pqc", "operation", "org.bouncycastle.crypto.AsymmetricCipherKeyPair"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters.<init>", 2, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters.<init>", 7, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters"},
		{"org.bouncycastle.pqc.crypto.mldsa.MLDSASigner.<init>", 0, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.mldsa.MLDSASigner"},
		{"org.bouncycastle.pqc.crypto.mldsa.MLDSASigner.init", 2, "bouncycastle-pqc", "config", "void"},
		{"org.bouncycastle.pqc.crypto.mldsa.MLDSASigner.generateMuSignature", 1, "bouncycastle-pqc", "operation", "byte[]"},
		{"org.bouncycastle.pqc.crypto.mldsa.HashMLDSASigner.verifySignature", 2, "bouncycastle-pqc", "operation", "boolean"},
		{"org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator.generateKeyPair", 0, "bouncycastle-pqc", "operation", "org.bouncycastle.crypto.AsymmetricCipherKeyPair"},
		{"org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner.<init>", 0, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner"},
		{"org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters.<init>", 2, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters"},
		{"org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters.<init>", 5, "bouncycastle-pqc", "factory", "org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters"},

		// Bouncy Castle 1.84 onwards package spelling (org.bouncycastle.crypto.*).
		{"org.bouncycastle.crypto.kems.MLKEMGenerator.<init>", 1, "bouncycastle-pqc-1.84", "factory", "org.bouncycastle.crypto.kems.MLKEMGenerator"},
		{"org.bouncycastle.crypto.kems.MLKEMGenerator.generateEncapsulated", 1, "bouncycastle-pqc-1.84", "operation", "org.bouncycastle.crypto.SecretWithEncapsulation"},
		{"org.bouncycastle.crypto.kems.MLKEMExtractor.extractSecret", 1, "bouncycastle-pqc-1.84", "operation", "byte[]"},
		{"org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator.generateKeyPair", 0, "bouncycastle-pqc-1.84", "operation", "org.bouncycastle.crypto.AsymmetricCipherKeyPair"},
		{"org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters.<init>", 2, "bouncycastle-pqc-1.84", "factory", "org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters"},
		{"org.bouncycastle.crypto.signers.MLDSASigner.<init>", 0, "bouncycastle-pqc-1.84", "factory", "org.bouncycastle.crypto.signers.MLDSASigner"},
		{"org.bouncycastle.crypto.signers.HashMLDSASigner.generateSignature", 1, "bouncycastle-pqc-1.84", "operation", "byte[]"},
		{"org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator.init", 1, "bouncycastle-pqc-1.84", "config", "void"},
		{"org.bouncycastle.crypto.signers.SLHDSASigner.<init>", 0, "bouncycastle-pqc-1.84", "factory", "org.bouncycastle.crypto.signers.SLHDSASigner"},
		{"org.bouncycastle.crypto.signers.HashSLHDSASigner.init", 2, "bouncycastle-pqc-1.84", "config", "void"},
		{"org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters.<init>", 2, "bouncycastle-pqc-1.84", "factory", "org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters"},
		{"org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters.getEncoded", 0, "bouncycastle-pqc-1.84", "output", "byte[]"},

		// LMS / HSS, org.bouncycastle.pqc.crypto.lms (1.65 onwards, deprecated in 1.86).
		{"org.bouncycastle.pqc.crypto.lms.LMSSigner.<init>", 0, "bouncycastle-lms", "factory", "org.bouncycastle.pqc.crypto.lms.LMSSigner"},
		{"org.bouncycastle.pqc.crypto.lms.HSSSigner.<init>", 0, "bouncycastle-lms", "factory", "org.bouncycastle.pqc.crypto.lms.HSSSigner"},
		{"org.bouncycastle.pqc.crypto.lms.LMSSigner.init", 2, "bouncycastle-lms", "config", "void"},
		{"org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator.generateKeyPair", 0, "bouncycastle-lms", "operation", "org.bouncycastle.crypto.AsymmetricCipherKeyPair"},
		{"org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters.<init>", 2, "bouncycastle-lms", "factory", "org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters"},
		{"org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters.<init>", 2, "bouncycastle-lms", "factory", "org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters"},
		{"org.bouncycastle.pqc.crypto.lms.LMSParameters.<init>", 2, "bouncycastle-lms", "factory", "org.bouncycastle.pqc.crypto.lms.LMSParameters"},
		{"org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner.generateSignature", 1, "bouncycastle-lms", "operation", "byte[]"},
		{"org.bouncycastle.pqc.crypto.lms.LMSContextBasedVerifier.verify", 1, "bouncycastle-lms", "operation", "boolean"},
		{"org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters.getPublicKey", 0, "bouncycastle-lms", "output", "org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters"},

		// LMS / HSS, org.bouncycastle.crypto.* (1.86 onwards).
		{"org.bouncycastle.crypto.signers.LMSSigner.<init>", 0, "bouncycastle-lms-1.86", "factory", "org.bouncycastle.crypto.signers.LMSSigner"},
		{"org.bouncycastle.crypto.signers.LMSSigner.generateSignature", 1, "bouncycastle-lms-1.86", "operation", "byte[]"},
		{"org.bouncycastle.crypto.signers.HSSSigner.verifySignature", 2, "bouncycastle-lms-1.86", "operation", "boolean"},
		{"org.bouncycastle.crypto.generators.HSSKeyPairGenerator.generateKeyPair", 0, "bouncycastle-lms-1.86", "operation", "org.bouncycastle.crypto.AsymmetricCipherKeyPair"},
		{"org.bouncycastle.crypto.params.LMSKeyGenerationParameters.<init>", 2, "bouncycastle-lms-1.86", "factory", "org.bouncycastle.crypto.params.LMSKeyGenerationParameters"},
		{"org.bouncycastle.crypto.params.LMSPrivateKeyParameters.generate", 2, "bouncycastle-lms-1.86", "factory", "org.bouncycastle.crypto.params.LMSPrivateKeyParameters"},
		{"org.bouncycastle.crypto.signers.LMSContextBasedSigner.generateLMSContext", 0, "bouncycastle-lms-1.86", "factory", "org.bouncycastle.crypto.signers.lms.LMSContext"},

		// Provider-side specs (org.bouncycastle.jcajce.spec).
		{"org.bouncycastle.jcajce.spec.MLKEMParameterSpec.fromName", 1, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.MLKEMParameterSpec"},
		{"org.bouncycastle.jcajce.spec.MLDSAParameterSpec.fromName", 1, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.MLDSAParameterSpec"},
		{"org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.fromName", 1, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.SLHDSAParameterSpec"},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.<init>", 2, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.KEMGenerateSpec"},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.<init>", 3, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.KEMGenerateSpec"},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder.<init>", 3, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder"},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder.build", 0, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.KEMGenerateSpec"},
		{"org.bouncycastle.jcajce.spec.KEMExtractSpec.<init>", 4, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.KEMExtractSpec"},
		{"org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder.withKdfAlgorithm", 1, "bouncycastle-pqc-jcajce", "config", "org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder"},
		{"org.bouncycastle.jcajce.spec.KEMKDFSpec.getKeyAlgorithmName", 0, "bouncycastle-pqc-jcajce", "output", "java.lang.String"},
		{"org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec.<init>", 3, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec"},
		{"org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec.<init>", 2, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec"},
		{"org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec.fromNames", 2, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec"},
		{"org.bouncycastle.jcajce.spec.LMSHSSKeyGenParameterSpec.<init>", 1, "bouncycastle-pqc-jcajce", "factory", "org.bouncycastle.jcajce.spec.LMSHSSKeyGenParameterSpec"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.SourceLibrary != tt.wantLib || c.Role != tt.wantRole || c.Return.Type != tt.wantReturn {
				t.Fatalf("%s#%d = lib %q role %q return %q, want lib %q role %q return %q",
					tt.method, tt.arity, c.SourceLibrary, c.Role, c.Return.Type, tt.wantLib, tt.wantRole, tt.wantReturn)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
		})
	}
}

// TestJavaPQCContracts_ParameterRoles checks the argument positions that
// select the algorithm or parameter set.
func TestJavaPQCContracts_ParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method    string
		arity     int
		index     int
		wantRole  string
		wantProp  string
		wantDeriv string
	}{
		{"javax.crypto.KEM.getInstance", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"javax.crypto.KEM.getInstance", 2, 1, "metadata-contributing", "provider", "argument_value"},
		{"javax.crypto.KEM.Encapsulator.encapsulate", 3, 2, "metadata-contributing", "algorithm", "argument_value"},
		{"java.security.spec.NamedParameterSpec.<init>", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters.<init>", 2, 1, "operation-determining", "parameters", "argument_value"},
		{"org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters.<init>", 2, 1, "operation-determining", "parameters", "argument_value"},
		{"org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters.<init>", 2, 0, "operation-determining", "parameters", "argument_value"},
		{"org.bouncycastle.pqc.crypto.lms.LMSParameters.<init>", 2, 1, "operation-determining", "parameters", "argument_value"},
		{"org.bouncycastle.crypto.params.LMSPrivateKeyParameters.<init>", 6, 5, "metadata-contributing", "keySize", "argument_bit_length"},
		{"org.bouncycastle.jcajce.spec.MLDSAParameterSpec.fromName", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.<init>", 3, 2, "metadata-contributing", "keySize", "argument_value"},
		{"org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder.<init>", 4, 2, "metadata-contributing", "algorithm", "argument_value"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d[%d]", tt.method, tt.arity, tt.index), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			var found bool
			for _, p := range got[0].Parameters {
				if p.Index == nil || *p.Index != tt.index {
					continue
				}
				found = true
				if p.Role != tt.wantRole || p.Contributes == nil || p.Contributes.Property != tt.wantProp || p.Contributes.Derivation != tt.wantDeriv {
					t.Fatalf("%s#%d parameter %d = %#v, want role %q property %q derivation %q",
						tt.method, tt.arity, tt.index, p, tt.wantRole, tt.wantProp, tt.wantDeriv)
				}
			}
			if !found {
				t.Fatalf("%s#%d has no parameter role at index %d: %#v", tt.method, tt.arity, tt.index, got[0].Parameters)
			}
		})
	}
}

// TestJavaPQCContracts_Negative asserts that lookalike and non-existent keys
// resolve to nothing: wrong arity, wrong receiver, the $ nested-class
// spelling, a package mix of the two Bouncy Castle layouts, pre-FIPS names,
// and static parameter-set fields (which are not methods).
func TestJavaPQCContracts_Negative(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	absent := []struct {
		method string
		arity  int
	}{
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator.generateEncapsulated", 2},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator.<init>", 0},
		{"org.bouncycastle.crypto.kems.MLKEMExtractor.extractSecret", 0},
		{"javax.crypto.KEM.encapsulate", 0},
		{"javax.crypto.KEM.decapsulate", 1},
		{"javax.crypto.KEM$Encapsulator.encapsulate", 0},
		{"javax.crypto.KEM.Encapsulator.encapsulate", 1},
		{"javax.crypto.KEM.newEncapsulator", 0},
		{"org.bouncycastle.pqc.crypto.kems.MLKEMGenerator.<init>", 1},
		{"org.bouncycastle.crypto.mlkem.MLKEMGenerator.<init>", 1},
		{"org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator.<init>", 1},
		{"org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner.<init>", 0},
		{"org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner.<init>", 0},
		{"org.bouncycastle.pqc.crypto.mldsa.MLDSASigner.init", 1},
		{"org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner.<init>", 1},
		{"org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyParameters.<init>", 2},
		{"org.bouncycastle.pqc.crypto.lms.LMSSigner.<init>", 1},
		{"org.bouncycastle.crypto.signers.LMSSigner.generateSignature", 2},
		{"org.bouncycastle.pqc.crypto.lms.LMSParameters.create", 2},
		{"org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters.ml_kem_768", 0},
		{"org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_768", 0},
		{"org.bouncycastle.jcajce.spec.MLDSAParameterSpec", 0},
		{"org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.fromName", 2},
		{"SLHDSAParameterSpec.fromName", 1},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec.<init>", 1},
		{"org.bouncycastle.jcajce.spec.KEMGenerateSpec$Builder.build", 0},
		{"java.security.spec.NamedParameterSpec.<init>", 0},
	}
	for _, tt := range absent {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("%s#%d contracts = %d, want 0: %#v", tt.method, tt.arity, len(got), got)
		}
	}

	// The two Bouncy Castle package spellings are separate libraries.
	oldGen := kb.ContractsFor("org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator.<init>", 1)
	newGen := kb.ContractsFor("org.bouncycastle.crypto.kems.MLKEMGenerator.<init>", 1)
	if len(oldGen) != 1 || len(newGen) != 1 {
		t.Fatalf("MLKEMGenerator.<init>#1 contracts: old %d, new %d, want 1 each", len(oldGen), len(newGen))
	}
	if oldGen[0].SourceLibrary == newGen[0].SourceLibrary {
		t.Fatalf("old and new MLKEMGenerator spellings share SourceLibrary %q, want distinct libraries", oldGen[0].SourceLibrary)
	}
	if oldGen[0].SourceLibrary != "bouncycastle-pqc" || newGen[0].SourceLibrary != "bouncycastle-pqc-1.84" {
		t.Fatalf("MLKEMGenerator.<init>#1 libraries = %q / %q, want bouncycastle-pqc / bouncycastle-pqc-1.84", oldGen[0].SourceLibrary, newGen[0].SourceLibrary)
	}
	oldLMS := kb.ContractsFor("org.bouncycastle.pqc.crypto.lms.LMSSigner.<init>", 0)
	newLMS := kb.ContractsFor("org.bouncycastle.crypto.signers.LMSSigner.<init>", 0)
	if len(oldLMS) != 1 || len(newLMS) != 1 || oldLMS[0].SourceLibrary == newLMS[0].SourceLibrary {
		t.Fatalf("LMSSigner.<init>#0: old %#v, new %#v, want one contract each from distinct libraries", oldLMS, newLMS)
	}
}

// TestJavaPQCContracts_MergeSanity checks that the PQC files merge with the
// rest of the Java KB: the shared interface contracts and hierarchy edges they
// redeclare are identical across files, so Merge keeps exactly one copy.
func TestJavaPQCContracts_MergeSanity(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	// Shared interface operations declared by more than one PQC file.
	for _, tt := range []struct {
		method string
		arity  int
	}{
		{"org.bouncycastle.pqc.crypto.MessageSigner.generateSignature", 1},
		{"org.bouncycastle.pqc.crypto.MessageSigner.verifySignature", 2},
		{"org.bouncycastle.crypto.Signer.update", 1},
		{"org.bouncycastle.crypto.Signer.update", 3},
		{"org.bouncycastle.crypto.Signer.generateSignature", 0},
		{"org.bouncycastle.crypto.Signer.verifySignature", 1},
	} {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 || got[0].Role != "operation" {
			t.Errorf("%s#%d = %#v, want exactly one operation contract after merge", tt.method, tt.arity, got)
		}
	}

	// Hierarchy edges redeclared by the PQC files must match bouncycastle.yaml
	// and jdk-crypto.yaml, and the PQC types must reach the shared bases.
	for child, wantParents := range map[string][]string{
		"org.bouncycastle.crypto.params.AsymmetricKeyParameter":      {"org.bouncycastle.crypto.CipherParameters"},
		"org.bouncycastle.crypto.CipherParameters":                   {"java.lang.Object"},
		"org.bouncycastle.crypto.Signer":                             {"java.lang.Object"},
		"org.bouncycastle.crypto.KEMParameters":                      {"org.bouncycastle.crypto.CipherParameters"},
		"org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters": {"org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters"},
		"org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters":       {"org.bouncycastle.crypto.params.AsymmetricKeyParameter"},
		"org.bouncycastle.crypto.params.MLKEMKeyParameters":          {"org.bouncycastle.crypto.params.AsymmetricKeyParameter"},
		"org.bouncycastle.pqc.crypto.mldsa.MLDSASigner":              {"org.bouncycastle.crypto.Signer"},
		"org.bouncycastle.crypto.signers.SLHDSASigner":               {"org.bouncycastle.pqc.crypto.MessageSigner"},
		"org.bouncycastle.pqc.crypto.lms.LMSSigner":                  {"org.bouncycastle.pqc.crypto.MessageSigner"},
		"org.bouncycastle.crypto.signers.LMSSigner":                  {"org.bouncycastle.crypto.Signer"},
		"org.bouncycastle.crypto.signers.lms.LMSContext":             {"org.bouncycastle.crypto.Digest"},
		"javax.crypto.KEM.Encapsulator":                              {"java.lang.Object"},
		"java.security.spec.NamedParameterSpec":                      {"java.security.spec.AlgorithmParameterSpec"},
		"org.bouncycastle.jcajce.spec.MLKEMParameterSpec":            {"java.security.spec.AlgorithmParameterSpec"},
		"org.bouncycastle.jcajce.spec.KEMGenerateSpec":               {"org.bouncycastle.jcajce.spec.KEMKDFSpec", "java.security.spec.AlgorithmParameterSpec"},
	} {
		got := kb.Hierarchy[child]
		if !slices.Equal(got, wantParents) {
			t.Errorf("hierarchy[%s] = %v, want %v", child, got, wantParents)
		}
	}
	for _, child := range []string{
		"org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters",
		"org.bouncycastle.crypto.params.HSSPrivateKeyParameters",
	} {
		got := kb.Hierarchy[child]
		if len(got) != 2 || !slices.Contains(got, "org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner") && !slices.Contains(got, "org.bouncycastle.crypto.signers.LMSContextBasedSigner") {
			t.Errorf("hierarchy[%s] = %v, want the LMSKeyParameters and LMSContextBasedSigner parents", child, got)
		}
	}
}
