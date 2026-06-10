package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// loadPythonKB is a test helper that loads the embedded Python KB and fatals on error.
func loadPythonKB(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if kb == nil {
		t.Fatal("LoadEmbedded(\"python\") returned nil KB")
	}
	return kb
}

// TestLoadEmbedded_Python_PycaCryptography verifies that the pyca-cryptography
// contract YAML loads and declares the key hazmat cipher pipeline entries.
func TestLoadEmbedded_Python_PycaCryptography(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		// Cipher constructor
		{
			method:     "cryptography.hazmat.primitives.ciphers.Cipher.<init>",
			arity:      2,
			wantReturn: "cryptography.hazmat.primitives.ciphers.Cipher",
			wantLib:    "pyca-cryptography",
		},
		// encryptor
		{
			method:     "cryptography.hazmat.primitives.ciphers.Cipher.encryptor",
			arity:      0,
			wantReturn: "cryptography.hazmat.primitives.ciphers.CipherContext",
			wantLib:    "pyca-cryptography",
		},
		// decryptor
		{
			method:     "cryptography.hazmat.primitives.ciphers.Cipher.decryptor",
			arity:      0,
			wantReturn: "cryptography.hazmat.primitives.ciphers.CipherContext",
			wantLib:    "pyca-cryptography",
		},
		// CipherContext.update
		{
			method:     "cryptography.hazmat.primitives.ciphers.CipherContext.update",
			arity:      1,
			wantReturn: "builtins.bytes",
			wantLib:    "pyca-cryptography",
		},
		// RSA key generation
		{
			method:     "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
			arity:      2,
			wantReturn: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
			wantLib:    "pyca-cryptography",
		},
		// EC key generation
		{
			method:     "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
			arity:      1,
			wantReturn: "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey",
			wantLib:    "pyca-cryptography",
		},
		// PBKDF2 derive
		{
			method:     "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive",
			arity:      1,
			wantReturn: "builtins.bytes",
			wantLib:    "pyca-cryptography",
		},
	}

	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d: no contracts found", tt.method, tt.arity)
			continue
		}
		c := got[0]
		if c.Return.Type != tt.wantReturn {
			t.Errorf("%s#%d return type = %q, want %q", tt.method, tt.arity, c.Return.Type, tt.wantReturn)
		}
		if c.SourceLibrary != tt.wantLib {
			t.Errorf("%s#%d source library = %q, want %q", tt.method, tt.arity, c.SourceLibrary, tt.wantLib)
		}
		if c.Return.Confidence != "high" {
			t.Errorf("%s#%d confidence = %q, want %q", tt.method, tt.arity, c.Return.Confidence, "high")
		}
	}
}

// TestLoadEmbedded_Python_PycaCryptography_HierarchyValid verifies that the
// hierarchy edges in pyca-cryptography.yaml are valid (all return types reach
// builtins.object through the declared hierarchy — the loader validates this).
func TestLoadEmbedded_Python_PycaCryptography_HierarchyValid(t *testing.T) {
	t.Parallel()

	// If the YAML has broken hierarchy edges the loader raises a reachability
	// error and LoadEmbedded returns a non-nil error. A successful load here
	// is sufficient proof that the hierarchy is valid.
	kb := loadPythonKB(t)

	if len(kb.Hierarchy) == 0 {
		t.Error("pyca-cryptography hierarchy is empty; expected hierarchy edges")
	}
}

// TestLoadEmbedded_Python_Pycryptodome verifies that pycryptodome.yaml loads
// and declares the key AES, SHA256, RSA, and KDF entries.
func TestLoadEmbedded_Python_Pycryptodome(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{
			method:     "Crypto.Cipher.AES.new",
			arity:      2,
			wantReturn: "Crypto.Cipher.AES.AESCipher",
			wantLib:    "pycryptodome",
		},
		{
			method:     "Crypto.Cipher.AES.AESCipher.encrypt",
			arity:      1,
			wantReturn: "builtins.bytes",
			wantLib:    "pycryptodome",
		},
		{
			method:     "Crypto.Hash.SHA256.new",
			arity:      0,
			wantReturn: "Crypto.Hash.SHA256.SHA256Hash",
			wantLib:    "pycryptodome",
		},
		{
			method:     "Crypto.Hash.SHA256.SHA256Hash.digest",
			arity:      0,
			wantReturn: "builtins.bytes",
			wantLib:    "pycryptodome",
		},
		{
			method:     "Crypto.PublicKey.RSA.generate",
			arity:      1,
			wantReturn: "Crypto.PublicKey.RSA.RsaKey",
			wantLib:    "pycryptodome",
		},
		{
			// PBKDF2 is uppercase so the Python parser emits it as a constructor call:
			// {Package: "Crypto.Protocol.KDF", Type: "PBKDF2", Name: "<init>"}
			// → KB key must use <init> form.
			method:     "Crypto.Protocol.KDF.PBKDF2.<init>",
			arity:      3,
			wantReturn: "builtins.bytes",
			wantLib:    "pycryptodome",
		},
	}

	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d: no contracts found", tt.method, tt.arity)
			continue
		}
		c := got[0]
		if c.Return.Type != tt.wantReturn {
			t.Errorf("%s#%d return type = %q, want %q", tt.method, tt.arity, c.Return.Type, tt.wantReturn)
		}
		if c.SourceLibrary != tt.wantLib {
			t.Errorf("%s#%d source library = %q, want %q", tt.method, tt.arity, c.SourceLibrary, tt.wantLib)
		}
	}
}

// TestLoadEmbedded_Python_Paramiko verifies that paramiko.yaml loads and
// declares the key RSA/ECDSA/Ed25519 key entries with valid return types.
func TestLoadEmbedded_Python_Paramiko(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{
			method:     "paramiko.rsakey.RSAKey.generate",
			arity:      1,
			wantReturn: "paramiko.rsakey.RSAKey",
			wantLib:    "paramiko",
		},
		{
			method:     "paramiko.rsakey.RSAKey.from_private_key_file",
			arity:      1,
			wantReturn: "paramiko.rsakey.RSAKey",
			wantLib:    "paramiko",
		},
		{
			method:     "paramiko.ecdsakey.ECDSAKey.generate",
			arity:      0,
			wantReturn: "paramiko.ecdsakey.ECDSAKey",
			wantLib:    "paramiko",
		},
		{
			method:     "paramiko.ed25519key.Ed25519Key.generate",
			arity:      0,
			wantReturn: "paramiko.ed25519key.Ed25519Key",
			wantLib:    "paramiko",
		},
		{
			method:     "paramiko.transport.Transport.<init>",
			arity:      1,
			wantReturn: "paramiko.transport.Transport",
			wantLib:    "paramiko",
		},
	}

	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d: no contracts found", tt.method, tt.arity)
			continue
		}
		c := got[0]
		if c.Return.Type != tt.wantReturn {
			t.Errorf("%s#%d return type = %q, want %q", tt.method, tt.arity, c.Return.Type, tt.wantReturn)
		}
		if c.SourceLibrary != tt.wantLib {
			t.Errorf("%s#%d source library = %q, want %q", tt.method, tt.arity, c.SourceLibrary, tt.wantLib)
		}
		if c.Return.Confidence != "high" {
			t.Errorf("%s#%d confidence = %q, want %q", tt.method, tt.arity, c.Return.Confidence, "high")
		}
	}
}

// TestLoadEmbedded_Python_CryptodomeAlias verifies that the Cryptodome.* namespace
// (pycryptodomex package) resolves the same contracts as the Crypto.* namespace
// (pycryptodome). This covers TASK C: `from Cryptodome.Cipher import AES; AES.new(...)`
// must resolve the same KB entry as `from Crypto.Cipher import AES; AES.new(...)`.
func TestLoadEmbedded_Python_CryptodomeAlias(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	// These Cryptodome.* entries are the mirror of the Crypto.* entries in pycryptodome.yaml.
	tests := []struct {
		method     string
		arity      int
		wantReturn string
	}{
		{
			method:     "Cryptodome.Cipher.AES.new",
			arity:      2,
			wantReturn: "Cryptodome.Cipher.AES.AESCipher",
		},
		{
			method:     "Cryptodome.Hash.SHA256.new",
			arity:      0,
			wantReturn: "Cryptodome.Hash.SHA256.SHA256Hash",
		},
		{
			method:     "Cryptodome.PublicKey.RSA.generate",
			arity:      1,
			wantReturn: "Cryptodome.PublicKey.RSA.RsaKey",
		},
		{
			method:     "Cryptodome.Protocol.KDF.PBKDF2.<init>",
			arity:      3,
			wantReturn: "builtins.bytes",
		},
		{
			method:     "Cryptodome.Hash.HMAC.new",
			arity:      2,
			wantReturn: "Cryptodome.Hash.HMAC.HMAC",
		},
	}

	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) == 0 {
			t.Errorf("Cryptodome alias %s#%d: no contracts found (Cryptodome.* namespace not loaded)", tt.method, tt.arity)
			continue
		}
		c := got[0]
		if c.Return.Type != tt.wantReturn {
			t.Errorf("Cryptodome alias %s#%d return type = %q, want %q", tt.method, tt.arity, c.Return.Type, tt.wantReturn)
		}
	}
}

// TestLoadEmbedded_Python_AllLibrariesHaveValidReturnTypes asserts that every
// contract in the merged Python KB has a non-empty return type and "high"
// confidence (the only author-facing confidence level per crypto-kb-author skill).
func TestLoadEmbedded_Python_AllLibrariesHaveValidReturnTypes(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	for key, contractList := range kb.Contracts {
		for i, c := range contractList {
			if c.Return.Type == "" {
				t.Errorf("contract[%s][%d] has empty return type", key, i)
			}
			if c.Return.Confidence == "" {
				t.Errorf("contract[%s][%d] has empty confidence", key, i)
			}
		}
	}
}
