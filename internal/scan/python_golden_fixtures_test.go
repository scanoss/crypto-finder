// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// python_golden_fixtures_test.go — T-4.2 golden fixture per Tier-0 Python library
//
// For each Tier-0 library expected to produce crypto_entry_points (coverage
// class ✅ or 🔴 in docs/crypto-tier0-python.md), this file asserts:
//
//   - crypto_entry_points is non-empty (REQ-7.2.c)
//   - supporting_calls is non-empty OR documented as empty with clear rationale
//     (REQ-7.2.d, per the "realistic resolvable shape" note)
//
// Libraries WITH contracts + role methods (pyca/cryptography, pycryptodome,
// pycryptodomex, paramiko) exercise both assertions (c) and (d) via detection
// findings over fluent-chain source.  Libraries WITHOUT contracts (bcrypt,
// PyJWT, argon2-cffi, PyNaCl) are rule-only by design; no fluent chain
// pattern exists so supporting_calls = 0 is the realistic resolvable shape
// and is documented.
//
// Each fixture source is a representative stub of the library's terminal
// crypto API, mirroring what mining the library's own source would produce.

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// syntheticRuleEntry describes a minimal inline rule for synthesis.
type syntheticRuleEntry struct {
	ruleID    string
	api       string
	primitive string
	family    string
	operation string
}

// buildInlineRuleYAML returns a minimal Semgrep rule YAML stub suitable for
// SynthesizeRuleCryptoEntryPoints.
func buildInlineRuleYAML(ruleID, api, primitive, family, operation string) string {
	return "rules:\n" +
		"  - id: " + ruleID + "\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: " + primitive + "\n" +
		"        algorithmFamily: " + family + "\n" +
		"        operation: " + operation + "\n" +
		"        api: " + api + "\n"
}

// buildPythonLibraryFragment builds a decoded Fragment for a Python library
// fixture. It uses buildModuleFragmentFor (T-4.1 harness) internally.
// If syntheticRules is non-empty, rule-based synthesis is run so that
// library-mined source stub stubs produce crypto_entry_points without requiring
// a live scanner.
// report may be nil; detection findings are pre-assigned IDs.
func buildPythonLibraryFragment(
	t *testing.T,
	importPath, file, src string,
	report *entities.InterimReport,
	syntheticRules []syntheticRuleEntry,
) graphfrag.Fragment {
	t.Helper()

	resolver := callgraph.NewPythonContractTypeResolverFromEmbedded()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	b.SetTypeResolver(resolver)
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(%s): %v", importPath, err)
	}

	if report == nil {
		report = &entities.InterimReport{}
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	// Run synthesis for each rule stub.
	for _, entry := range syntheticRules {
		ruleDir := t.TempDir()
		ruleBody := buildInlineRuleYAML(entry.ruleID, entry.api, entry.primitive, entry.family, entry.operation)
		rulePath := filepath.Join(ruleDir, "rule.yaml")
		if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
			t.Fatal(err)
		}
		engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: dir,
		RootModule:  importPath,
		Ecosystem:   "python",
	})

	raw, merr := json.Marshal(export)
	if merr != nil {
		t.Fatalf("marshal export(%s): %v", importPath, merr)
	}
	key := graphfrag.ComponentKey{Purl: "pkg:pypi/" + importPath, Version: "test"}
	frag, derr := graphfrag.DecodeFragment(key, raw)
	if derr != nil {
		t.Fatalf("DecodeFragment(%s): %v", importPath, derr)
	}
	return frag
}

// assertGoldenShape validates the dep-tree-shaped output for a Tier-0 lib golden
// fixture. wantSupportingCalls controls whether the test asserts supporting_calls
// > 0. For rule-only libs without a fluent chain, pass false and the rationale is
// logged.
func assertGoldenShape(t *testing.T, lib string, frag graphfrag.Fragment, wantSupportingCalls bool) {
	t.Helper()
	if len(frag.CryptoEntryPoints) == 0 {
		t.Errorf("[%s] golden: crypto_entry_points is empty; expected >=1 (REQ-7.2.c)", lib)
	} else {
		t.Logf("[%s] golden: crypto_entry_points = %d", lib, len(frag.CryptoEntryPoints))
	}
	if wantSupportingCalls {
		if len(frag.SupportingCalls) == 0 {
			t.Errorf("[%s] golden: supporting_calls is empty; expected >=1 (REQ-7.2.d)", lib)
		} else {
			t.Logf("[%s] golden: supporting_calls = %d", lib, len(frag.SupportingCalls))
		}
	} else {
		t.Logf("[%s] golden: supporting_calls = %d (realistic resolvable shape — no fluent chain / no contract role for this rule-only lib; documented limitation)", lib, len(frag.SupportingCalls))
	}
}

// --- T-4.2 Golden fixture tests per Tier-0 lib ---

// TestPythonGolden_Pyca_Cryptography_AES is the golden fixture for
// pyca/cryptography (REQ-7.2). The fixture mines the Cipher class with its
// encryptor/update/finalize lifecycle methods. A detection finding at the Cipher
// constructor line drives the supporting-call derivation via the fluent chain
// (encryptor → update → finalize share the ChainID). This mirrors mining
// cryptography's own hazmat.primitives.ciphers module.
func TestPythonGolden_Pyca_Cryptography_AES(t *testing.T) {
	t.Parallel()

	// Fixture: mining cryptography.hazmat.primitives.ciphers — Cipher class stub
	// with its terminal constructor and lifecycle methods as definitions.
	// Line 10 is where Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor().update(data)
	// occurs in the user function, which the detection report targets.
	src := `"""pyca/cryptography Cipher stub — golden fixture for mining."""
from cryptography.hazmat.primitives.ciphers import algorithms, modes


class Cipher:
    """AES cipher builder. Constructor is the crypto entry point."""

    def __init__(self, algorithm, mode):
        self._algorithm = algorithm
        self._mode = mode

    def encryptor(self):
        """Return an encryption context."""
        return CipherContext(self._algorithm, self._mode)

    def decryptor(self):
        """Return a decryption context."""
        return CipherContext(self._algorithm, self._mode)


class CipherContext:
    """Encryption/decryption context returned by Cipher.encryptor/decryptor."""

    def __init__(self, algorithm, mode):
        self._algorithm = algorithm
        self._mode = mode

    def update(self, data):
        """Encrypt or decrypt data."""
        return b""

    def finalize(self):
        """Finalize and return remaining bytes."""
        return b""


def do_encrypt(key, iv, data):
    """Representative consumer — uses the Cipher fluent chain."""
    result = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor().update(data)
    return result
`
	// Detection report: the scanner found AES-GCM at line 36 (the Cipher call in do_encrypt).
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "cipher.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 36,
				EndLine:   36,
				Match:     "Cipher(algorithms.AES(key), modes.GCM(iv))",
				Rules:     []entities.RuleInfo{{ID: "python.cryptography.algorithm.ae.aes-gcm"}},
				Metadata: map[string]string{
					"api":                "cryptography.hazmat.primitives.ciphers.Cipher.<init>",
					"assetType":          "algorithm",
					"algorithmFamily":    "AES",
					"algorithmPrimitive": "ae",
					"operation":          "encrypt",
				},
			}},
		}},
	}

	// Also run synthesis for the Cipher constructor so the mined-lib scenario
	// (no detection, only mining) also produces crypto_entry_points.
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.cryptography.algorithm.ae.aes-gcm.synth",
		api:       "cryptography.hazmat.primitives.ciphers.Cipher.<init>",
		primitive: "ae",
		family:    "AES",
		operation: "encrypt",
	}}

	frag := buildPythonLibraryFragment(t,
		"cryptography.hazmat.primitives.ciphers", "cipher.py", src, report, synthRules)

	// pyca/cryptography has a contract with role methods; the fluent chain also
	// provides object-lifecycle supporting calls — both paths contribute.
	assertGoldenShape(t, "pyca/cryptography", frag, true /* wantSupportingCalls */)
}

// TestPythonGolden_Pycryptodome_AES is the golden fixture for pycryptodome.
// Mines Crypto.Cipher.AES — the `new` factory function and cipher context
// methods (encrypt, decrypt). Detection finding drives supporting-call
// derivation.
func TestPythonGolden_Pycryptodome_AES(t *testing.T) {
	t.Parallel()

	// Fixture: mining Crypto.Cipher.AES module — new() factory + context methods.
	src := `"""pycryptodome AES stub — golden fixture for mining."""


class AESCipher:
    """AES cipher context object returned by AES.new()."""

    def __init__(self, key, mode, **kwargs):
        self._key = key
        self._mode = mode

    def encrypt(self, data):
        """Encrypt plaintext."""
        return b""

    def decrypt(self, data):
        """Decrypt ciphertext."""
        return b""

    def encrypt_and_digest(self, data):
        """Encrypt and produce authentication tag."""
        return b"", b""

    def decrypt_and_verify(self, ciphertext, tag):
        """Decrypt and verify authentication tag."""
        return b""


def new(key, mode, **kwargs):
    """Create a new AES cipher object."""
    return AESCipher(key, mode, **kwargs)


def do_encrypt_gcm(key, nonce, data):
    """Representative consumer — uses AES.new() with GCM mode."""
    from Crypto.Cipher import AES
    cipher = new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, tag
`
	// Detection finding for AES.new at line 32 (do_encrypt_gcm calls new()).
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "aes.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 37,
				EndLine:   37,
				Match:     "new(key, AES.MODE_GCM, nonce=nonce)",
				Rules:     []entities.RuleInfo{{ID: "python.pycryptodome.algorithm.ae.aes-gcm"}},
				Metadata: map[string]string{
					"api":                "Crypto.Cipher.AES.new",
					"assetType":          "algorithm",
					"algorithmFamily":    "AES",
					"algorithmPrimitive": "ae",
					"operation":          "encrypt",
				},
			}},
		}},
	}

	// Synthesis: mine Crypto.Cipher.AES — new() is a module-level function.
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.pycryptodome.algorithm.ae.aes-gcm.synth",
		api:       "Crypto.Cipher.AES.new",
		primitive: "ae",
		family:    "AES",
		operation: "encrypt",
	}}

	frag := buildPythonLibraryFragment(t,
		"Crypto.Cipher.AES", "aes.py", src, report, synthRules)

	// pycryptodome has a contract with role methods for AESCipher; the consumer
	// function also has a chain (cipher → encrypt_and_digest) providing supporting calls.
	assertGoldenShape(t, "pycryptodome", frag, true /* wantSupportingCalls */)
}

// TestPythonGolden_Pycryptodomex_AES is the golden fixture for pycryptodomex
// (Cryptodome.* namespace). Mirrors pycryptodome — same API, different namespace.
func TestPythonGolden_Pycryptodomex_AES(t *testing.T) {
	t.Parallel()

	// Fixture: mining Cryptodome.Cipher.AES module — identical to pycryptodome
	// but under Cryptodome.* namespace.
	src := `"""pycryptodomex AES stub — golden fixture for mining."""


class AESCipher:
    """AES cipher context object returned by AES.new() (Cryptodome namespace)."""

    def __init__(self, key, mode, **kwargs):
        self._key = key
        self._mode = mode

    def encrypt(self, data):
        """Encrypt plaintext."""
        return b""

    def decrypt(self, data):
        """Decrypt ciphertext."""
        return b""

    def encrypt_and_digest(self, data):
        """Encrypt and produce authentication tag."""
        return b"", b""

    def decrypt_and_verify(self, ciphertext, tag):
        """Decrypt and verify authentication tag."""
        return b""


def new(key, mode, **kwargs):
    """Create a new AES cipher object (Cryptodome namespace)."""
    return AESCipher(key, mode, **kwargs)


def do_encrypt_gcm(key, nonce, data):
    """Representative consumer."""
    from Cryptodome.Cipher import AES
    cipher = new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, tag
`
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "aes.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 37,
				EndLine:   37,
				Match:     "new(key, AES.MODE_GCM, nonce=nonce)",
				Rules:     []entities.RuleInfo{{ID: "python.pycryptodomex.algorithm.ae.aes-gcm"}},
				Metadata: map[string]string{
					"api":                "Cryptodome.Cipher.AES.new",
					"assetType":          "algorithm",
					"algorithmFamily":    "AES",
					"algorithmPrimitive": "ae",
					"operation":          "encrypt",
				},
			}},
		}},
	}

	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.pycryptodomex.algorithm.ae.aes-gcm.synth",
		api:       "Cryptodome.Cipher.AES.new",
		primitive: "ae",
		family:    "AES",
		operation: "encrypt",
	}}

	frag := buildPythonLibraryFragment(t,
		"Cryptodome.Cipher.AES", "aes.py", src, report, synthRules)

	assertGoldenShape(t, "pycryptodomex", frag, true /* wantSupportingCalls */)
}

// TestPythonGolden_Paramiko_RSAKey is the golden fixture for paramiko.
// Mines paramiko.rsakey.RSAKey — generate (classmethod) + sign_ssh_data lifecycle.
func TestPythonGolden_Paramiko_RSAKey(t *testing.T) {
	t.Parallel()

	// Fixture: mining paramiko/rsakey.py — RSAKey class with generate + sign_ssh_data.
	src := `"""Paramiko RSAKey stub — golden fixture for mining."""


class RSAKey:
    """Paramiko RSA key implementation."""

    @classmethod
    def generate(cls, bits=2048, progress_func=None):
        """Generate a new RSA private key.

        Returns an RSAKey instance.
        """
        return cls()

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        """Load an RSA key from a private key file."""
        return cls()

    @classmethod
    def from_private_key(cls, file_obj, password=None):
        """Load an RSA key from a file-like object."""
        return cls()

    def sign_ssh_data(self, data):
        """Sign data using this RSA key for SSH authentication."""
        return b""

    def get_name(self):
        """Return the key type name."""
        return "ssh-rsa"


def demo_generate_and_sign(bits, data):
    """Representative: generate a key and sign data."""
    key = RSAKey.generate(bits=bits)
    sig = key.sign_ssh_data(data)
    return sig
`
	// Detection finding: RSAKey.generate is called at line 37 in demo_generate_and_sign.
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "rsakey.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 37,
				EndLine:   37,
				Match:     "RSAKey.generate(bits=bits)",
				Rules:     []entities.RuleInfo{{ID: "python.paramiko.algorithm.signature.rsa"}},
				Metadata: map[string]string{
					"api":                "paramiko.rsakey.RSAKey.generate",
					"assetType":          "algorithm",
					"algorithmFamily":    "RSASSA-PKCS1",
					"algorithmPrimitive": "signature",
					"operation":          "keygen",
				},
			}},
		}},
	}

	// Synthesis: mine paramiko.rsakey.RSAKey — generate is a classmethod.
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.paramiko.algorithm.signature.rsa.synth",
		api:       "paramiko.rsakey.RSAKey.generate",
		primitive: "signature",
		family:    "RSASSA-PKCS1",
		operation: "keygen",
	}}

	frag := buildPythonLibraryFragment(t,
		"paramiko.rsakey", "rsakey.py", src, report, synthRules)

	// paramiko has a contract with role methods (sign_ssh_data as output role);
	// the consumer function key.sign_ssh_data(data) is a lifecycle sibling of
	// RSAKey.generate via the assigned variable "key".
	assertGoldenShape(t, "paramiko", frag, true /* wantSupportingCalls */)
}

// TestPythonGolden_PyNaCl_SigningKey is the golden fixture for PyNaCl.
// Mines nacl.signing.SigningKey — rule-only lib, no contract, no fluent chain.
// supporting_calls = 0 is the realistic resolvable shape (documented).
func TestPythonGolden_PyNaCl_SigningKey(t *testing.T) {
	t.Parallel()

	// Fixture: mining nacl/signing.py — SigningKey class with generate method.
	src := `"""PyNaCl SigningKey stub — golden fixture for mining."""


class SigningKey:
    """Ed25519 signing key. generate() produces a new key."""

    def __init__(self, seed, encoder=None):
        self._seed = seed

    @classmethod
    def generate(cls):
        """Generate a new Ed25519 signing key."""
        return cls(b"0" * 32)

    def sign(self, message, encoder=None):
        """Sign a message and return the signed bytes."""
        return b""

    @property
    def verify_key(self):
        """The corresponding verify key."""
        return VerifyKey(b"0" * 32)


class VerifyKey:
    """Ed25519 verify key."""

    def __init__(self, key, encoder=None):
        self._key = key

    def verify(self, smessage, signature=None, encoder=None):
        """Verify a signed message."""
        return b""
`
	// Synthesis: mine nacl.signing.SigningKey.generate (3 dots → passes gate).
	// The Python parser emits FunctionDecl with Package="nacl.signing",
	// Type="SigningKey", Name="generate"; the dotted FQN is
	// "nacl.signing.SigningKey.generate" which matches this api.
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.pynacl.algorithm.signature.eddsa.signing-key.synth",
		api:       "nacl.signing.SigningKey.generate",
		primitive: "signature",
		family:    "EdDSA",
		operation: "keygen",
	}}

	frag := buildPythonLibraryFragment(t,
		"nacl.signing", "signing.py", src, nil, synthRules)

	// PyNaCl is rule-only (no contract): supporting_calls = 0 is expected.
	// Synthesis fires because SigningKey is defined as a class in scanned source.
	assertGoldenShape(t, "PyNaCl", frag, false /* wantSupportingCalls: rule-only, no lifecycle */)
}

// TestPythonGolden_Argon2cffi_PasswordHasher is the golden fixture for argon2-cffi.
// Mines argon2.PasswordHasher — rule-only lib, no contract, no fluent chain.
func TestPythonGolden_Argon2cffi_PasswordHasher(t *testing.T) {
	t.Parallel()

	// Fixture: mining argon2/__init__.py or the PasswordHasher class.
	src := `"""argon2-cffi PasswordHasher stub — golden fixture for mining."""


class PasswordHasher:
    """High-level Argon2 password hashing.

    Default parameters: argon2id, time_cost=2, memory_cost=65536, parallelism=2.
    """

    def __init__(self, time_cost=2, memory_cost=65536, parallelism=2,
                 hash_len=32, salt_len=16, encoding="utf-8", type=None):
        self.time_cost = time_cost
        self.memory_cost = memory_cost

    def hash(self, password):
        """Hash a password and return the encoded hash string."""
        return "$argon2id$..."

    def verify(self, hash, password):
        """Verify a password against a hash. Returns True or raises."""
        return True

    def check_needs_rehash(self, hash):
        """Return True if the hash needs to be regenerated."""
        return False
`
	// Synthesis: mine argon2.PasswordHasher.hash (2 dots → passes gate).
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.argon2-cffi.algorithm.kdf.argon2.hash.synth",
		api:       "argon2.PasswordHasher.hash",
		primitive: "kdf",
		family:    "Argon2",
		operation: "keyderive",
	}}

	frag := buildPythonLibraryFragment(t,
		"argon2", "password_hasher.py", src, nil, synthRules)

	// argon2-cffi is rule-only: supporting_calls = 0 is expected.
	assertGoldenShape(t, "argon2-cffi", frag, false /* wantSupportingCalls: rule-only */)
}

// TestPythonGolden_Bcrypt_Hashpw is the golden fixture for bcrypt.
// Mines bcrypt — rule-only lib (1-dot api bcrypt.hashpw), no fluent chain.
func TestPythonGolden_Bcrypt_Hashpw(t *testing.T) {
	t.Parallel()

	// Fixture: mining bcrypt/__init__.py — hashpw + checkpw + gensalt.
	src := `"""bcrypt stub — golden fixture for mining."""


def hashpw(password, salt):
    """Hash a password using bcrypt."""
    return b"$2b$..."


def checkpw(password, hashed_password):
    """Check that a password matches a hashed password."""
    return True


def gensalt(rounds=12, prefix=b"2b"):
    """Generate a random bcrypt salt."""
    return b"$2b$12$..."
`
	// Synthesis: mine bcrypt.hashpw (1-dot Python gate).
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.bcrypt.algorithm.kdf.bcrypt.hashpw.synth",
		api:       "bcrypt.hashpw",
		primitive: "kdf",
		family:    "bcrypt",
		operation: "keyderive",
	}}

	frag := buildPythonLibraryFragment(t,
		"bcrypt", "__init__.py", src, nil, synthRules)

	// bcrypt is rule-only (no contract): supporting_calls = 0 is expected.
	assertGoldenShape(t, "bcrypt", frag, false /* wantSupportingCalls: rule-only */)
}

// TestPythonGolden_PyJWT_Encode is the golden fixture for PyJWT.
// Mines jwt — rule-only lib (1-dot api jwt.encode), no fluent chain.
func TestPythonGolden_PyJWT_Encode(t *testing.T) {
	t.Parallel()

	// Fixture: mining jwt/api.py — encode + decode module-level functions.
	src := `"""PyJWT api stub — golden fixture for mining."""


def encode(payload, key, algorithm="HS256", headers=None, json_encoder=None):
    """Encode a JWT token."""
    return ""


def decode(jwt_token, key, algorithms=None, options=None,
           audience=None, issuer=None):
    """Decode a JWT token."""
    return {}
`
	// Synthesis: mine jwt.encode (1-dot Python gate).
	synthRules := []syntheticRuleEntry{{
		ruleID:    "python.pyjwt.algorithm.mac.jwt.encode.synth",
		api:       "jwt.encode",
		primitive: "mac",
		family:    "HMAC",
		operation: "tag",
	}}

	frag := buildPythonLibraryFragment(t,
		"jwt", "api.py", src, nil, synthRules)

	// PyJWT is rule-only: supporting_calls = 0 is expected.
	assertGoldenShape(t, "PyJWT", frag, false /* wantSupportingCalls: rule-only */)
}

// TestPyNaCl_SigningKey_FidelityWithDeployedRule validates the REAL deployed rule
// from crypto_finder_poc/semgrep-rules/python/pynacl/algorithm/signature/eddsa/rules.yaml
// against a representative PyNaCl fixture.
//
// WHY THIS TEST EXISTS (fidelity gap):
//
// The golden test TestPythonGolden_PyNaCl_SigningKey uses buildInlineRuleYAML to
// construct an idealized rule with api: "nacl.signing.SigningKey.generate" (the
// correct 3-dot method FQN). It passes regardless of what the deployed rule says.
// This test mines a fixture against the ACTUAL artifact in the sibling repository,
// catching any divergence where the deployed api form would fail synthesis.
//
// RED→GREEN history: this test went RED against the original deployed rule
// (api: "nacl.signing.SigningKey" — bare class, 2 dots). The synthesis engine's
// declsByFQN lookup cannot match a bare class name to any method definition; the
// implicitCtorRep path is not triggered because the api lacks the ".<init>" suffix.
// Zero entry points were produced. After fixing the rule to use per-method FQNs
// (nacl.signing.SigningKey.generate and nacl.signing.SigningKey.<init>), this test
// turns GREEN.
//
// If crypto_finder_poc is not present at the expected sibling path, the test is
// skipped with a clear message so CI without the sibling repo does not break.
func TestPyNaCl_SigningKey_FidelityWithDeployedRule(t *testing.T) {
	t.Parallel()

	// Locate the deployed rule in the sibling repo. The sibling repo
	// crypto_finder_poc is expected alongside crypto-finder:
	//   .../scanoss/crypto-finder  (this repo)
	//   .../scanoss/crypto_finder_poc  (sibling)
	// Use runtime.Caller to get the source file's absolute directory so the
	// path is stable regardless of `go test` cwd.
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = .../crypto-finder/internal/scan/python_golden_fixtures_test.go
	// Navigate: scan/ → internal/ → crypto-finder/ → scanoss/ → crypto_finder_poc/
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	ruleFile := filepath.Join(repoRoot, "..", "crypto_finder_poc",
		"semgrep-rules", "python", "pynacl", "algorithm", "signature", "eddsa", "rules.yaml")
	if _, statErr := os.Stat(ruleFile); statErr != nil {
		t.Skipf("sibling repo not present at %s — skipping fidelity test (run with crypto_finder_poc checked out alongside)", ruleFile)
	}

	// Representative PyNaCl signing.py stub: the class as it appears when the
	// library's own source is mined. The @classmethod generate is the primary
	// key-generation entry point that the deployed rule must synthesize.
	src := `"""PyNaCl signing.py stub — fidelity fixture for the deployed rule."""


class SigningKey:
    """Ed25519 signing key."""

    def __init__(self, seed, encoder=None):
        self._seed = seed

    @classmethod
    def generate(cls):
        """Generate a new random Ed25519 signing key."""
        return cls(b"0" * 32)

    def sign(self, message, encoder=None):
        """Sign a message."""
        return b""
`

	// Build the callgraph from the fixture source.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "signing.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	resolver := callgraph.NewPythonContractTypeResolverFromEmbedded()
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	b.SetTypeResolver(resolver)
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "nacl.signing"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	report := &entities.InterimReport{}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	// Run synthesis against the REAL deployed rule file (not an inline stub).
	added := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{ruleFile}, "python")

	// Re-run EnsureFindingSources + AssignFindingIDs after synthesis so the
	// synthetic assets receive FindingIDs (required for the fragment decoder to
	// produce non-empty crypto_entry_points — same pattern as buildPythonLibraryFragment).
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	// Decode and check the fragment.
	export := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: dir,
		RootModule:  "nacl.signing",
		Ecosystem:   "python",
	})
	raw, merr := json.Marshal(export)
	if merr != nil {
		t.Fatalf("marshal export: %v", merr)
	}
	key := graphfrag.ComponentKey{Purl: "pkg:pypi/pynacl", Version: "test"}
	frag, derr := graphfrag.DecodeFragment(key, raw)
	if derr != nil {
		t.Fatalf("DecodeFragment: %v", derr)
	}

	t.Logf("fidelity: synthesis added %d entry points from deployed rule", added)
	t.Logf("fidelity: crypto_entry_points=%d supporting_calls=%d", len(frag.CryptoEntryPoints), len(frag.SupportingCalls))

	if len(frag.CryptoEntryPoints) == 0 {
		t.Errorf("fidelity FAIL: deployed rule produced 0 crypto_entry_points for nacl.signing.SigningKey fixture; " +
			"the rule's api FQN does not join against any definition in the callgraph — " +
			"check that api uses the specific method symbol (e.g. nacl.signing.SigningKey.generate), " +
			"NOT the bare class name (nacl.signing.SigningKey)")
	}
}
