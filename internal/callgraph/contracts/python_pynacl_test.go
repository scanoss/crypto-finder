package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const pynaclLibrary = "pynacl"

// renderPynaclContract renders every field the loader parses, so a mutation to
// any of them changes the line. Index is a *int and Contributes is nil for a
// parameter without a contribution, so both are nil-guarded.
func renderPynaclContract(key string, c contracts.Contract) string {
	paramRoles := "-"
	if len(c.Parameters) > 0 {
		rendered := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprintf("%d", *p.Index)
			}
			property, derivation := "-", "-"
			if p.Contributes != nil {
				property = p.Contributes.Property
				derivation = p.Contributes.Derivation
			}
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s", idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	params := "-"
	if len(c.ParameterTypes) > 0 {
		params = strings.Join(c.ParameterTypes, "|")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, paramRoles, c.Varargs, when, c.SourceLibrary)
}

func loadedPynaclContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == pynaclLibrary {
				lines = append(lines, renderPynaclContract(key, list[i]))
			}
		}
	}
	if len(lines) == 0 {
		t.Fatal("no pynacl contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

const (
	pynaclSymmetricKeyParam = "0:key:metadata-contributing:keySize:argument_bit_length"
	pynaclKdfSizeParam      = "0:size:metadata-contributing:keySize:argument_byte_length"
	pynaclKdfTypes          = "builtins.int|builtins.bytes|builtins.bytes|builtins.int|builtins.int"
	pynaclOutputLengthParam = "0:size:metadata-contributing:outputLength:argument_value"
)

// pynaclLine builds one expected line; the fields are the ones the renderer
// prints, in order.
func pynaclLine(key, method, role, ret, types, params string) string {
	return fmt.Sprintf("%s %s/%s/%s/high/%s/params=%s/varargs=false/when=-/lib=pynacl", key, method, role, ret, types, params)
}

// wantPynaclContracts is written by hand from the PyNaCl 1.5.0 sources, never
// from the YAML: deriving it from the YAML would keep the comparison green on
// a corrupted contract. `import nacl.x; nacl.x.C(..)` emits the attribute path
// and `from nacl.x import C; C(..)` emits .<init>, so each constructor has
// both spellings.
func wantPynaclContracts() []string {
	return []string{
		// secret.py:59 SecretBox(key, encoder), :76 encrypt, :119 decrypt.
		pynaclLine("nacl.secret.SecretBox#1", "nacl.secret.SecretBox", "factory", "nacl.secret.SecretBox", "-", pynaclSymmetricKeyParam),
		pynaclLine("nacl.secret.SecretBox.<init>#1", "nacl.secret.SecretBox.<init>", "factory", "nacl.secret.SecretBox", "-", pynaclSymmetricKeyParam),
		pynaclLine("nacl.secret.SecretBox.encrypt#1", "nacl.secret.SecretBox.encrypt", "operation", "nacl.utils.EncryptedMessage", "-", "-"),
		pynaclLine("nacl.secret.SecretBox.decrypt#1", "nacl.secret.SecretBox.decrypt", "operation", "builtins.bytes", "-", "-"),
		// secret.py:200 Aead(key, encoder), :219 encrypt, :270 decrypt.
		pynaclLine("nacl.secret.Aead#1", "nacl.secret.Aead", "factory", "nacl.secret.Aead", "-", pynaclSymmetricKeyParam),
		pynaclLine("nacl.secret.Aead.<init>#1", "nacl.secret.Aead.<init>", "factory", "nacl.secret.Aead", "-", pynaclSymmetricKeyParam),
		pynaclLine("nacl.secret.Aead.encrypt#1", "nacl.secret.Aead.encrypt", "operation", "nacl.utils.EncryptedMessage", "-", "-"),
		pynaclLine("nacl.secret.Aead.decrypt#1", "nacl.secret.Aead.decrypt", "operation", "builtins.bytes", "-", "-"),

		// public.py:36 PublicKey, :87 PrivateKey, :111 from_seed, :161 generate.
		pynaclLine("nacl.public.PublicKey#1", "nacl.public.PublicKey", "factory", "nacl.public.PublicKey", "-", "-"),
		pynaclLine("nacl.public.PublicKey.<init>#1", "nacl.public.PublicKey.<init>", "factory", "nacl.public.PublicKey", "-", "-"),
		pynaclLine("nacl.public.PrivateKey#1", "nacl.public.PrivateKey", "factory", "nacl.public.PrivateKey", "-", "-"),
		pynaclLine("nacl.public.PrivateKey.<init>#1", "nacl.public.PrivateKey.<init>", "factory", "nacl.public.PrivateKey", "-", "-"),
		pynaclLine("nacl.public.PrivateKey.generate#0", "nacl.public.PrivateKey.generate", "factory", "nacl.public.PrivateKey", "-", "-"),
		pynaclLine("nacl.public.PrivateKey.from_seed#1", "nacl.public.PrivateKey.from_seed", "factory", "nacl.public.PrivateKey", "-", "-"),
		// public.py:196 Box, :212 decode, :226 encrypt, :269 decrypt, :307 shared_key.
		pynaclLine("nacl.public.Box#2", "nacl.public.Box", "factory", "nacl.public.Box", "-", "-"),
		pynaclLine("nacl.public.Box.<init>#2", "nacl.public.Box.<init>", "factory", "nacl.public.Box", "-", "-"),
		pynaclLine("nacl.public.Box.decode#1", "nacl.public.Box.decode", "factory", "nacl.public.Box", "-", "-"),
		pynaclLine("nacl.public.Box.encrypt#1", "nacl.public.Box.encrypt", "operation", "nacl.utils.EncryptedMessage", "-", "-"),
		pynaclLine("nacl.public.Box.decrypt#1", "nacl.public.Box.decrypt", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.public.Box.shared_key#0", "nacl.public.Box.shared_key", "output", "builtins.bytes", "-", "-"),
		// public.py:346 SealedBox, :367 encrypt, :393 decrypt.
		pynaclLine("nacl.public.SealedBox#1", "nacl.public.SealedBox", "factory", "nacl.public.SealedBox", "-", "-"),
		pynaclLine("nacl.public.SealedBox.<init>#1", "nacl.public.SealedBox.<init>", "factory", "nacl.public.SealedBox", "-", "-"),
		pynaclLine("nacl.public.SealedBox.encrypt#1", "nacl.public.SealedBox.encrypt", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.public.SealedBox.decrypt#1", "nacl.public.SealedBox.decrypt", "operation", "builtins.bytes", "-", "-"),

		// signing.py:169 SigningKey, :209 generate, :220 sign,
		// :241 to_curve25519_private_key.
		pynaclLine("nacl.signing.SigningKey#1", "nacl.signing.SigningKey", "factory", "nacl.signing.SigningKey", "-", "-"),
		pynaclLine("nacl.signing.SigningKey.<init>#1", "nacl.signing.SigningKey.<init>", "factory", "nacl.signing.SigningKey", "-", "-"),
		pynaclLine("nacl.signing.SigningKey.generate#0", "nacl.signing.SigningKey.generate", "factory", "nacl.signing.SigningKey", "-", "-"),
		pynaclLine("nacl.signing.SigningKey.sign#1", "nacl.signing.SigningKey.sign", "operation", "nacl.signing.SignedMessage", "-", "-"),
		pynaclLine("nacl.signing.SigningKey.to_curve25519_private_key#0", "nacl.signing.SigningKey.to_curve25519_private_key", "factory", "nacl.public.PrivateKey", "-", "-"),
		// signing.py:68 VerifyKey, :98 verify, :139 to_curve25519_public_key.
		pynaclLine("nacl.signing.VerifyKey#1", "nacl.signing.VerifyKey", "factory", "nacl.signing.VerifyKey", "-", "-"),
		pynaclLine("nacl.signing.VerifyKey.<init>#1", "nacl.signing.VerifyKey.<init>", "factory", "nacl.signing.VerifyKey", "-", "-"),
		pynaclLine("nacl.signing.VerifyKey.verify#1", "nacl.signing.VerifyKey.verify", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.signing.VerifyKey.to_curve25519_public_key#0", "nacl.signing.VerifyKey.to_curve25519_public_key", "factory", "nacl.public.PublicKey", "-", "-"),

		// hash.py:62 sha256, :77 sha512, :92 blake2b, :136 siphash24(message,
		// key), :160 siphashx24(message, key).
		pynaclLine("nacl.hash.sha256#1", "nacl.hash.sha256", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.hash.sha512#1", "nacl.hash.sha512", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.hash.blake2b#1", "nacl.hash.blake2b", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.hash.siphash24#2", "nacl.hash.siphash24", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.hash.siphashx24#2", "nacl.hash.siphashx24", "operation", "builtins.bytes", "-", "-"),

		// pwhash/argon2i.py:49, argon2id.py:53, scrypt.py:59 kdf(size,
		// password, salt, opslimit, memlimit, encoder); size is in BYTES.
		pynaclLine("nacl.pwhash.argon2i.kdf#5", "nacl.pwhash.argon2i.kdf", "operation", "builtins.bytes", pynaclKdfTypes, pynaclKdfSizeParam),
		pynaclLine("nacl.pwhash.argon2i.str#1", "nacl.pwhash.argon2i.str", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.pwhash.argon2i.verify#2", "nacl.pwhash.argon2i.verify", "operation", "builtins.bool", "-", "-"),
		pynaclLine("nacl.pwhash.argon2id.kdf#5", "nacl.pwhash.argon2id.kdf", "operation", "builtins.bytes", pynaclKdfTypes, pynaclKdfSizeParam),
		pynaclLine("nacl.pwhash.argon2id.str#1", "nacl.pwhash.argon2id.str", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.pwhash.argon2id.verify#2", "nacl.pwhash.argon2id.verify", "operation", "builtins.bool", "-", "-"),
		pynaclLine("nacl.pwhash.scrypt.kdf#5", "nacl.pwhash.scrypt.kdf", "operation", "builtins.bytes", pynaclKdfTypes, pynaclKdfSizeParam),
		pynaclLine("nacl.pwhash.scrypt.str#1", "nacl.pwhash.scrypt.str", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.pwhash.scrypt.verify#2", "nacl.pwhash.scrypt.verify", "operation", "builtins.bool", "-", "-"),
		// pwhash/__init__.py:40 str = argon2id.str, :57 verify.
		pynaclLine("nacl.pwhash.str#1", "nacl.pwhash.str", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.pwhash.verify#2", "nacl.pwhash.verify", "operation", "builtins.bool", "-", "-"),

		// utils.py:70 random(size), :74 randombytes_deterministic(size, seed).
		pynaclLine("nacl.utils.random#1", "nacl.utils.random", "factory", "builtins.bytes", "-", pynaclOutputLengthParam),
		pynaclLine("nacl.utils.randombytes_deterministic#2", "nacl.utils.randombytes_deterministic", "factory", "builtins.bytes", "-", pynaclOutputLengthParam),

		// Low-level anchor: bindings/crypto_sign.py:72 crypto_sign(message,
		// sk), :90 crypto_sign_open(signed, pk).
		pynaclLine("nacl.bindings.crypto_sign#2", "nacl.bindings.crypto_sign", "operation", "builtins.bytes", "-", "-"),
		pynaclLine("nacl.bindings.crypto_sign_open#2", "nacl.bindings.crypto_sign_open", "operation", "builtins.bytes", "-", "-"),
	}
}

func TestPythonPynaclContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantPynaclContracts()
	got := loadedPynaclContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		wantSet[line] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, line := range got {
		gotSet[line] = struct{}{}
	}

	var missing, unexpected []string
	for _, line := range want {
		if _, ok := gotSet[line]; !ok {
			missing = append(missing, line)
		}
	}
	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			unexpected = append(unexpected, line)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	for _, line := range missing {
		t.Errorf("contract entry expected but NOT loaded from the YAML:\n\t%q,", line)
	}
	for _, line := range unexpected {
		t.Errorf("unexpected contract entry; if the YAML change is intended, add it to wantPynaclContracts():\n\t\t%q,", line)
	}
}

func TestPythonPynaclContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	allowed := map[string]struct{}{"factory": {}, "config": {}, "output": {}, "operation": {}}
	seen := 0
	for key, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != pynaclLibrary {
				continue
			}
			seen++
			if _, ok := allowed[c.Role]; !ok {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, c.Role)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no pynacl contracts loaded; every assertion above passed vacuously")
	}
}

func TestPythonPynaclContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "pynacl.yaml"))
	if err != nil {
		t.Fatalf("read pynacl.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pynacl.yaml): %v", err)
	}
	if kb.Ecosystem != "python" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema = %q/%q, want python/2", kb.Ecosystem, kb.SchemaVersion)
	}
	if kb.Library == nil || kb.Library.Name != pynaclLibrary {
		t.Fatalf("library block = %+v, want name pynacl", kb.Library)
	}
	if got := strings.Join(kb.Library.Coordinates, ","); got != "PyNaCl" {
		t.Errorf("library.coordinates = %q, want PyNaCl", got)
	}
	// 1.0 through 1.6: releases only add APIs and no return type changes;
	// 0.x used a different module layout.
	if got := kb.Library.VersionRange; got != ">=1.0,<2.0" {
		t.Errorf("library.version_range = %q, want >=1.0,<2.0", got)
	}
}

// TestPythonPynaclContract_UncontractedAPIsAreAbsent pins the surface this
// family deliberately does not contract, with the reason, so adding one later
// reads as a scope decision being reversed.
func TestPythonPynaclContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if got := kb.ContractsForTolerant("nacl.signing.SigningKey.sign", 1); len(got) == 0 {
		t.Fatal("positive control failed: nacl.signing.SigningKey.sign does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, absent := range []struct{ key, reason string }{
		{"nacl.pwhash.kdf", "matched by a detection rule pattern but not defined by PyNaCl 1.5.0 or 1.6.2"},
		{"nacl.hash.generichash", "alias of blake2b that no detection rule matches"},
		{"nacl.hash.shorthash", "alias of siphash24 that no detection rule matches"},
		{"nacl.hashlib.blake2b", "hashlib-compatible wrapper that no detection rule matches yet"},
		{"nacl.hashlib.scrypt", "hashlib-compatible wrapper that no detection rule matches yet"},
		{"nacl.pwhash.kdf_scryptsalsa208sha256", "legacy alias of scrypt.kdf with no rule"},
		{"nacl.encoding.HexEncoder.encode", "serialization helper, no cryptographic operation"},
		{"nacl.bindings.crypto_box", "only the crypto_sign pair anchors the binding layer"},
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(absent.key, arity) {
				if c.SourceLibrary == pynaclLibrary {
					t.Errorf("%s resolves to a pynacl contract, but it is deliberately not contracted: %s",
						absent.key, absent.reason)
				}
			}
		}
	}
}
