// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// python_fidelity_deployed_rules_test.go — batch 10: deployed-rule fidelity for all synthesis Tier-0 libs.
//
// WARNING-2 from the verify-report: only PyNaCl had a fidelity test that reads
// the REAL deployed rule from the sibling crypto_finder_poc repository. The
// other 7 synthesis Tier-0 libs used inline rule stubs (buildInlineRuleYAML),
// so a bare-class / fail-open regression in those deployed rule files would not
// be caught by the golden tests.
//
// This file closes that gap by adding one deployed-rule fidelity test per lib:
//
//   - TestFidelity_Cryptography_AES_GCM          — pyca/cryptography
//   - TestFidelity_Pycryptodome_AES_GCM           — pycryptodome
//   - TestFidelity_Pycryptodomex_AES_GCM          — pycryptodomex
//   - TestFidelity_Paramiko_RSAKey                — paramiko
//   - TestFidelity_Bcrypt_Hashpw                  — bcrypt
//   - TestFidelity_PyJWT_Encode                   — PyJWT
//   - TestFidelity_Argon2cffi_PasswordHasher       — argon2-cffi
//
// Mechanism (mirrors TestPyNaCl_SigningKey_FidelityWithDeployedRule):
//  1. runtime.Caller(0) locates this file → navigates to the sibling repo.
//  2. The real rules.yaml is passed directly to SynthesizeRuleCryptoEntryPoints.
//  3. EnsureFindingSources + AssignFindingIDs are called after synthesis so that
//     synthetic assets receive FindingIDs (otherwise fragment export yields 0).
//  4. The test asserts crypto_entry_points > 0.
//  5. If the sibling repo is absent, the test skips gracefully so CI stays green.
//
// A RED result here means the deployed rule's api string does NOT join against any
// definition in the callgraph. That is a live deployed-rule bug — do not fix it by
// weakening the test; fix the rule and report it.

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

// pocRuleFile resolves a rule path relative to the crypto_finder_poc sibling
// repository. Returns ("", false) when the sibling repo is absent so callers
// can skip gracefully.
func pocRuleFile(parts ...string) (string, bool) {
	_, thisFile, _, _ := runtime.Caller(1)
	// thisFile: .../crypto-finder/internal/scan/python_fidelity_deployed_rules_test.go
	// Navigate: scan/ → internal/ → crypto-finder/ → scanoss/ → crypto_finder_poc/
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	pocRoot := filepath.Join(repoRoot, "..", "crypto_finder_poc")
	all := append([]string{pocRoot, "semgrep-rules"}, parts...)
	p := filepath.Join(all...)
	if _, err := os.Stat(p); err != nil {
		return p, false
	}
	return p, true
}

// assertDeployedRuleSynthesizes builds a callgraph from src (a minimal fixture
// that represents the library's mined source), runs SynthesizeRuleCryptoEntryPoints
// against the REAL deployed ruleFile, and asserts that at least one
// crypto_entry_point is produced.
//
// importPath is the Go-style dotted import path used as the callgraph module key
// (e.g. "Crypto.Cipher.AES").
// fileName is the Python file name written to the temp dir.
//
// This helper is the shared contract for all batch-10 fidelity tests. Any RED
// result here means the deployed rule contains an api string that silently fails
// synthesis (the known bare-class / method-level FQN mismatch bug).
func assertDeployedRuleSynthesizes(
	t *testing.T,
	lib, ruleFile, importPath, fileName, src string,
) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	resolver := callgraph.NewPythonContractTypeResolverFromEmbedded()
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	b.SetTypeResolver(resolver)
	graph, err := b.BuildFromDirectories(
		[]callgraph.PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("[%s] BuildFromDirectories(%s): %v", lib, importPath, err)
	}

	report := &entities.InterimReport{}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	// Synthesize against the REAL deployed rule (not an inline stub).
	added := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{ruleFile}, "python")

	// Must re-run after synthesis: synthetic assets get empty FindingID until
	// AssignFindingIDs is called again — the fragment exporter skips empty IDs,
	// producing 0 crypto_entry_points without this second call.
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
		t.Fatalf("[%s] marshal export: %v", lib, merr)
	}
	key := graphfrag.ComponentKey{Purl: "pkg:pypi/" + lib, Version: "test"}
	frag, derr := graphfrag.DecodeFragment(key, raw)
	if derr != nil {
		t.Fatalf("[%s] DecodeFragment: %v", lib, derr)
	}

	t.Logf("[%s] fidelity: synthesis added %d entry points from deployed rule", lib, added)
	t.Logf("[%s] fidelity: crypto_entry_points=%d supporting_calls=%d",
		lib, len(frag.CryptoEntryPoints), len(frag.SupportingCalls))

	if len(frag.CryptoEntryPoints) == 0 {
		t.Errorf("[%s] fidelity FAIL: deployed rule %s produced 0 crypto_entry_points — "+
			"the rule's api FQN does not join against any definition in the callgraph. "+
			"This is a deployed-rule bug: verify that api uses the specific method symbol "+
			"(e.g. Module.Type.method or pkg.func), NOT a bare class name.",
			lib, ruleFile)
	}
}

// TestFidelity_Cryptography_AES_GCM validates the deployed rule
// python/cryptography/algorithm/ae/aes-gcm/rules.yaml against a representative
// pyca/cryptography fixture (Cipher class stub matching the library's own source).
//
// The deployed api is: cryptography.hazmat.primitives.ciphers.Cipher.<init>
// The fixture mines cryptography.hazmat.primitives.ciphers with a Cipher class
// that has an __init__ method, so .<init> synthesis should fire.
func TestFidelity_Cryptography_AES_GCM(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "cryptography", "algorithm", "ae", "aes-gcm", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test (run with crypto_finder_poc checked out alongside)", ruleFile)
	}

	// Representative fixture: Cipher class as it appears when mining
	// cryptography.hazmat.primitives.ciphers.
	src := `"""pyca/cryptography Cipher stub — fidelity fixture for the deployed rule."""


class Cipher:
    """AES cipher builder. __init__ is the synthesis entry point."""

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
    """Cipher context returned by encryptor()/decryptor()."""

    def __init__(self, algorithm, mode):
        self._algorithm = algorithm
        self._mode = mode

    def update(self, data):
        """Encrypt or decrypt data."""
        return b""

    def finalize(self):
        """Finalize encryption."""
        return b""
`

	assertDeployedRuleSynthesizes(t,
		"cryptography",
		ruleFile,
		"cryptography.hazmat.primitives.ciphers",
		"cipher.py",
		src,
	)
}

// TestFidelity_Pycryptodome_AES_GCM validates the deployed rule
// python/pycryptodome/algorithm/ae/aes-gcm/rules.yaml against a representative
// pycryptodome fixture (Crypto.Cipher.AES module stub).
//
// The deployed api is: Crypto.Cipher.AES.new
// The fixture defines a module-level new() function under Crypto.Cipher.AES
// import path so synthesis matches FQN Crypto.Cipher.AES.new.
func TestFidelity_Pycryptodome_AES_GCM(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "pycryptodome", "algorithm", "ae", "aes-gcm", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: Crypto.Cipher.AES module — new() factory function.
	src := `"""pycryptodome AES stub — fidelity fixture for the deployed rule."""


class AESCipher:
    """AES cipher context returned by AES.new()."""

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
        """Encrypt and return authentication tag."""
        return b"", b""

    def decrypt_and_verify(self, ciphertext, tag):
        """Decrypt and verify authentication tag."""
        return b""


def new(key, mode, **kwargs):
    """Create a new AES cipher object. This is the synthesis target."""
    return AESCipher(key, mode, **kwargs)
`

	assertDeployedRuleSynthesizes(t,
		"pycryptodome",
		ruleFile,
		"Crypto.Cipher.AES",
		"aes.py",
		src,
	)
}

// TestFidelity_Pycryptodomex_AES_GCM validates the deployed rule
// python/pycryptodomex/algorithm/ae/aes-gcm/rules.yaml against a representative
// pycryptodomex fixture (Cryptodome.Cipher.AES module stub, mirroring pycryptodome).
//
// The deployed api is: Cryptodome.Cipher.AES.new.
func TestFidelity_Pycryptodomex_AES_GCM(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "pycryptodomex", "algorithm", "ae", "aes-gcm", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: Cryptodome.Cipher.AES module — new() factory.
	src := `"""pycryptodomex AES stub — fidelity fixture for the deployed rule."""


class AESCipher:
    """AES cipher context (Cryptodome namespace)."""

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
        """Encrypt and return authentication tag."""
        return b"", b""

    def decrypt_and_verify(self, ciphertext, tag):
        """Decrypt and verify authentication tag."""
        return b""


def new(key, mode, **kwargs):
    """Create a new AES cipher object (Cryptodome namespace)."""
    return AESCipher(key, mode, **kwargs)
`

	assertDeployedRuleSynthesizes(t,
		"pycryptodomex",
		ruleFile,
		"Cryptodome.Cipher.AES",
		"aes.py",
		src,
	)
}

// TestFidelity_Paramiko_RSAKey validates the deployed rule
// python/paramiko/algorithm/signature/rsa/rules.yaml against a representative
// paramiko fixture (RSAKey class stub matching the library's rsakey module).
//
// The deployed api is: paramiko.rsakey.RSAKey.generate
// The fixture mines paramiko.rsakey with an RSAKey class that has a generate
// classmethod, matching the 3-dot FQN.
func TestFidelity_Paramiko_RSAKey(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "paramiko", "algorithm", "signature", "rsa", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: paramiko/rsakey.py — RSAKey with generate classmethod.
	src := `"""Paramiko RSAKey stub — fidelity fixture for the deployed rule."""


class RSAKey:
    """Paramiko RSA key implementation."""

    @classmethod
    def generate(cls, bits=2048, progress_func=None):
        """Generate a new RSA private key. This is the synthesis target."""
        return cls()

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        """Load an RSA key from a private key file."""
        return cls()

    def sign_ssh_data(self, data):
        """Sign data using this RSA key for SSH authentication."""
        return b""

    def get_name(self):
        """Return the key type name."""
        return "ssh-rsa"
`

	assertDeployedRuleSynthesizes(t,
		"paramiko",
		ruleFile,
		"paramiko.rsakey",
		"rsakey.py",
		src,
	)
}

// TestFidelity_Bcrypt_Hashpw validates the deployed rule
// python/bcrypt/algorithm/kdf/bcrypt/rules.yaml against a representative
// bcrypt fixture.
//
// The deployed apis are: bcrypt.hashpw, bcrypt.checkpw, bcrypt.gensalt (1-dot Python gate).
// The fixture mines bcrypt with hashpw/checkpw/gensalt module-level functions.
func TestFidelity_Bcrypt_Hashpw(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "bcrypt", "algorithm", "kdf", "bcrypt", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: bcrypt/__init__.py — module-level functions.
	src := `"""bcrypt stub — fidelity fixture for the deployed rule."""


def hashpw(password, salt):
    """Hash a password using bcrypt. Primary synthesis target."""
    return b"$2b$..."


def checkpw(password, hashed_password):
    """Check that a password matches a hashed password."""
    return True


def gensalt(rounds=12, prefix=b"2b"):
    """Generate a random bcrypt salt."""
    return b"$2b$12$..."
`

	assertDeployedRuleSynthesizes(t,
		"bcrypt",
		ruleFile,
		"bcrypt",
		"__init__.py",
		src,
	)
}

// TestFidelity_PyJWT_Encode validates the deployed rule
// python/pyjwt/algorithm/mac/jwt/rules.yaml against a representative
// PyJWT fixture.
//
// The deployed apis are: jwt.encode, jwt.decode (1-dot Python gate).
// The fixture mines jwt with encode/decode module-level functions.
func TestFidelity_PyJWT_Encode(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "pyjwt", "algorithm", "mac", "jwt", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: jwt/api.py — encode + decode.
	src := `"""PyJWT api stub — fidelity fixture for the deployed rule."""


def encode(payload, key, algorithm="HS256", headers=None, json_encoder=None):
    """Encode a JWT token. Primary synthesis target."""
    return ""


def decode(jwt_token, key, algorithms=None, options=None,
           audience=None, issuer=None):
    """Decode a JWT token."""
    return {}
`

	assertDeployedRuleSynthesizes(t,
		"pyjwt",
		ruleFile,
		"jwt",
		"api.py",
		src,
	)
}

// TestFidelity_Argon2cffi_PasswordHasher validates the deployed rule
// python/argon2-cffi/algorithm/kdf/argon2/rules.yaml against a representative
// argon2-cffi fixture.
//
// The deployed apis include: argon2.PasswordHasher.<init>, argon2.PasswordHasher.hash,
// argon2.PasswordHasher.verify, argon2.low_level.hash_secret.
// The fixture mines argon2 with the PasswordHasher class and hash_secret function.
func TestFidelity_Argon2cffi_PasswordHasher(t *testing.T) {
	t.Parallel()

	ruleFile, ok := pocRuleFile("python", "argon2-cffi", "algorithm", "kdf", "argon2", "rules.yaml")
	if !ok {
		t.Skipf("sibling repo not present at %s — skipping fidelity test", ruleFile)
	}

	// Representative fixture: argon2 module — PasswordHasher class + low_level stub.
	src := `"""argon2-cffi stub — fidelity fixture for the deployed rule."""


class PasswordHasher:
    """High-level Argon2 password hashing.

    Constructor and hash/verify methods are the synthesis targets.
    Default: argon2id, time_cost=2, memory_cost=65536, parallelism=2.
    """

    def __init__(self, time_cost=2, memory_cost=65536, parallelism=2,
                 hash_len=32, salt_len=16, encoding="utf-8", type=None):
        self.time_cost = time_cost
        self.memory_cost = memory_cost

    def hash(self, password):
        """Hash a password. Synthesis target: argon2.PasswordHasher.hash."""
        return "$argon2id$..."

    def verify(self, hash, password):
        """Verify a password. Synthesis target: argon2.PasswordHasher.verify."""
        return True

    def check_needs_rehash(self, hash):
        """Return True if hash needs regeneration."""
        return False
`

	assertDeployedRuleSynthesizes(t,
		"argon2-cffi",
		ruleFile,
		"argon2",
		"password_hasher.py",
		src,
	)
}
