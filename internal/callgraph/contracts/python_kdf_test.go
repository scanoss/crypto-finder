package contracts_test

import "testing"

// TestLoadEmbeddedPython_KDFKeySizeRoles (T0.9 / row C, python-parser-parity-2)
// pins that every KDF contract this row adds/updates declares a keySize
// parameter role via argument_byte_length, with BOTH the declared Index AND
// Name populated — the keyword-name matching step (3a) needs Name; the
// positional/type-evidence-absent step (3b) needs Index — mirroring how
// jdk-crypto.yaml declares both index and name for its own keySize roles.
//
// Every arity/index value below was verified against the installed
// package's own primary source before authoring (see apply-progress.md):
// pyca-cryptography 50.0.1's own .pyi stub
// (cryptography/hazmat/bindings/_rust/openssl/kdf.pyi) for the
// cryptography.hazmat.primitives.kdf.* entries, and CPython 3.12's
// _hashlib built-in help() text for the hashlib.* entries.
func TestLoadEmbeddedPython_KDFKeySizeRoles(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method string
		arity  int
		index  int
		name   string
	}{
		{"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.<init>", 4, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.<init>", 5, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.hkdf.HKDF.<init>", 4, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.<init>", 3, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.<init>", 3, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.<init>", 3, 1, "length"},
		{"hashlib.pbkdf2_hmac", 5, 4, "dklen"},
		{"hashlib.scrypt", 7, 6, "dklen"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Index != nil && *parameter.Index == tt.index && parameter.Name == tt.name &&
					parameter.Role == "metadata-contributing" && parameter.Contributes != nil &&
					parameter.Contributes.Property == "keySize" && parameter.Contributes.Derivation == "argument_byte_length" {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want index %d name %q role metadata-contributing contributing keySize via argument_byte_length", got[0].Parameters, tt.index, tt.name)
		})
	}
}
