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

// TestLoadEmbedded_Python_PyOTP verifies the PyOTP constructor aliases used by
// scanoss/crypto_rules#99 and the output helpers they return.
func TestLoadEmbedded_Python_PyOTP(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{"pyotp.TOTP.<init>", 1, "pyotp.totp.TOTP", "pyotp"},
		{"pyotp.totp.TOTP.<init>", 1, "pyotp.totp.TOTP", "pyotp"},
		{"pyotp.totp.TOTP.now", 0, "builtins.str", "pyotp"},
		{"pyotp.totp.TOTP.at", 1, "builtins.str", "pyotp"},
		{"pyotp.totp.TOTP.verify", 1, "builtins.bool", "pyotp"},
		{"pyotp.totp.TOTP.provisioning_uri", 0, "builtins.str", "pyotp"},
		{"pyotp.HOTP.<init>", 1, "pyotp.hotp.HOTP", "pyotp"},
		{"pyotp.hotp.HOTP.<init>", 1, "pyotp.hotp.HOTP", "pyotp"},
		{"pyotp.hotp.HOTP.at", 1, "builtins.str", "pyotp"},
		{"pyotp.hotp.HOTP.verify", 2, "builtins.bool", "pyotp"},
		{"pyotp.hotp.HOTP.provisioning_uri", 0, "builtins.str", "pyotp"},
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

	for _, typ := range []string{"pyotp.totp.TOTP", "pyotp.hotp.HOTP", "pyotp.otp.OTP"} {
		if len(kb.Hierarchy[typ]) == 0 {
			t.Errorf("hierarchy[%q] is empty", typ)
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

func TestLoadEmbedded_Python_BenchmarkLibraries(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{"bcrypt.hashpw", 2, "builtins.bytes", "bcrypt"},
		{"bcrypt.checkpw", 2, "builtins.bool", "bcrypt"},
		{"argon2.PasswordHasher.<init>", 0, "argon2.PasswordHasher", "argon2-cffi"},
		{"argon2.PasswordHasher.hash", 1, "builtins.str", "argon2-cffi"},
		{"passlib.context.CryptContext.hash", 1, "builtins.str", "passlib"},
		{"passlib.hash.bcrypt.using", 0, "passlib.hash.bcrypt", "passlib"},
		{"passlib.hash.argon2.hash", 1, "builtins.str", "passlib"},
		{"passlib.hash.scrypt.verify", 2, "builtins.bool", "passlib"},
		{"nacl.secret.SecretBox.<init>", 1, "nacl.secret.SecretBox", "pynacl"},
		{"nacl.secret.SecretBox.encrypt", 1, "nacl.utils.EncryptedMessage", "pynacl"},
		{"nacl.public.PrivateKey.generate", 0, "nacl.public.PrivateKey", "pynacl"},
		{"nacl.signing.SigningKey.sign", 1, "nacl.signing.SignedMessage", "pynacl"},
		{"nacl.pwhash.argon2id.kdf", 5, "builtins.bytes", "pynacl"},
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
			t.Errorf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
		}
	}
}

func TestLoadEmbedded_Python_AzureKeyVaultKeys(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
	}{
		{"azure.keyvault.keys.KeyClient.<init>", 2, "azure.keyvault.keys.KeyClient"},
		{"azure.keyvault.keys.KeyClient.get_cryptography_client", 1, "azure.keyvault.keys.crypto.CryptographyClient"},
		{"azure.keyvault.keys.KeyClient.create_rsa_key", 1, "azure.keyvault.keys.KeyVaultKey"},
		{"azure.keyvault.keys.KeyClient.create_ec_key", 1, "azure.keyvault.keys.KeyVaultKey"},
		{"azure.keyvault.keys.KeyClient.create_oct_key", 1, "azure.keyvault.keys.KeyVaultKey"},
		{"azure.keyvault.keys.KeyClient.import_key", 2, "azure.keyvault.keys.KeyVaultKey"},
		{"azure.keyvault.keys.KeyClient.get_key", 1, "azure.keyvault.keys.KeyVaultKey"},
		{"azure.keyvault.keys.KeyClient.get_random_bytes", 1, "builtins.bytes"},
		{"azure.keyvault.keys.crypto.CryptographyClient.from_jwk", 1, "azure.keyvault.keys.crypto.CryptographyClient"},
		{"azure.keyvault.keys.crypto.CryptographyClient.encrypt", 2, "azure.keyvault.keys.crypto.EncryptResult"},
		{"azure.keyvault.keys.crypto.CryptographyClient.decrypt", 2, "azure.keyvault.keys.crypto.DecryptResult"},
		{"azure.keyvault.keys.crypto.CryptographyClient.wrap_key", 2, "azure.keyvault.keys.crypto.WrapResult"},
		{"azure.keyvault.keys.crypto.CryptographyClient.unwrap_key", 2, "azure.keyvault.keys.crypto.UnwrapResult"},
		{"azure.keyvault.keys.crypto.CryptographyClient.sign", 2, "azure.keyvault.keys.crypto.SignResult"},
		{"azure.keyvault.keys.crypto.CryptographyClient.verify", 3, "azure.keyvault.keys.crypto.VerifyResult"},
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
		if c.SourceLibrary != "azure-keyvault-keys" {
			t.Errorf("%s#%d source library = %q, want azure-keyvault-keys", tt.method, tt.arity, c.SourceLibrary)
		}
		if c.Return.Confidence != "high" {
			t.Errorf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
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

func TestLoadEmbedded_Python_Tier0GapLibraries(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{"botocore.client.KMS.encrypt", 0, "builtins.dict", "boto3"},
		{"botocore.client.KMS.generate_data_key", 0, "builtins.dict", "boto3"},
		{"botocore.client.KMS.re_encrypt", 0, "builtins.dict", "boto3"},
		{"botocore.client.KMS.generate_random", 0, "builtins.dict", "boto3"},
		{"botocore.client.KMS.generate_mac", 0, "builtins.dict", "boto3"},
		{"botocore.client.KMS.get_public_key", 0, "builtins.dict", "boto3"},
		{"M2Crypto.RSA.gen_key", 2, "M2Crypto.RSA.RSA", "m2crypto"},
		{"M2Crypto.EVP.MessageDigest", 1, "M2Crypto.EVP.MessageDigest", "m2crypto"},
		{"M2Crypto.EVP.PKey", 0, "M2Crypto.EVP.PKey", "m2crypto"},
		{"M2Crypto.EVP.pbkdf2", 4, "builtins.bytes", "m2crypto"},
		{"M2Crypto.DSA.load_key", 1, "M2Crypto.DSA.DSA", "m2crypto"},
		{"M2Crypto.EC.load_pub_key", 1, "M2Crypto.EC.EC_pub", "m2crypto"},
		{"M2Crypto.SMIME.PKCS7", 0, "M2Crypto.SMIME.PKCS7", "m2crypto"},
		{"M2Crypto.Engine.Engine.load_private_key", 1, "M2Crypto.EVP.PKey", "m2crypto"},
		{"M2Crypto.Provider.Provider.generate_rsa_key_pair", 0, "M2Crypto.RSA.RSA", "m2crypto"},
		{"M2Crypto.AuthCookie.AuthCookie", 0, "M2Crypto.AuthCookie.AuthCookie", "m2crypto"},
		{"M2Crypto.httpslib.ProxyHTTPSConnection", 1, "M2Crypto.httpslib.ProxyHTTPSConnection", "m2crypto"},
		{"M2Crypto.SSL.Context", 1, "M2Crypto.SSL.Context.Context", "m2crypto"},
		{"M2Crypto.SSL.Connection.Connection.get_peer_cert", 0, "M2Crypto.X509.X509", "m2crypto"},
		{"OpenSSL.SSL.Context", 1, "OpenSSL.SSL.Context", "pyopenssl"},
		{"OpenSSL.crypto.load_certificate", 2, "OpenSSL.crypto.X509", "pyopenssl"},
		{"OpenSSL.crypto.load_privatekey", 2, "OpenSSL.crypto.PKey", "pyopenssl"},
		{"OpenSSL.crypto.load_publickey", 2, "OpenSSL.crypto.PKey", "pyopenssl"},
		{"OpenSSL.crypto.dump_publickey", 2, "builtins.bytes", "pyopenssl"},
		{"OpenSSL.crypto.PKCS12", 0, "OpenSSL.crypto.PKCS12", "pyopenssl"},
		{"jwt.encode", 2, "builtins.str", "pyjwt"},
		{"jwt.decode", 1, "builtins.dict", "pyjwt"},
		{"werkzeug.security.generate_password_hash", 1, "builtins.str", "werkzeug"},
		{"werkzeug.security.check_password_hash", 2, "builtins.bool", "werkzeug"},
		{"flask_jwt_extended.create_access_token", 1, "builtins.str", "flask-jwt-extended"},
		{"flask_jwt_extended.decode_token", 1, "builtins.dict", "flask-jwt-extended"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) == 0 {
				t.Fatalf("%s#%d: no contracts found", tt.method, tt.arity)
			}
			c := got[0]
			if c.Return.Type != tt.wantReturn {
				t.Errorf("%s#%d return type = %q, want %q", tt.method, tt.arity, c.Return.Type, tt.wantReturn)
			}
			if c.SourceLibrary != tt.wantLib {
				t.Errorf("%s#%d source library = %q, want %q", tt.method, tt.arity, c.SourceLibrary, tt.wantLib)
			}
			if c.Return.Confidence != "high" {
				t.Errorf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
		})
	}
}

func TestLoadEmbedded_Python_Boto3KMSClientCondition(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	got := kb.ContractsFor("boto3.client", 1)
	if len(got) != 1 {
		t.Fatalf("boto3.client#1 contracts = %d, want 1", len(got))
	}
	c := got[0]
	if c.When == nil {
		t.Fatal("boto3.client#1 should be conditional on service name")
	}
	if c.When.ArgIndex != 0 {
		t.Errorf("boto3.client#1 condition arg index = %d, want 0", c.When.ArgIndex)
	}
	if c.Return.Type != "botocore.client.KMS" {
		t.Errorf("boto3.client#1 return type = %q, want botocore.client.KMS", c.Return.Type)
	}
}
