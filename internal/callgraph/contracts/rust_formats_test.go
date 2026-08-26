package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedRustIncludesFormatContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method  string
		arity   int
		library string
		role    string
	}
	tests := []row{
		{"der::SecretDocument.from_pem", 1, "der", "factory"},
		{"der::SecretDocument.encode_msg", 1, "der", "factory"},
		{"der::SecretDocument.to_pem", 2, "der", "output"},
		{"pkcs1::DecodeRsaPrivateKey.from_pkcs1_der", 1, "pkcs1", "factory"},
		{"pkcs1::EncodeRsaPrivateKey.to_pkcs1_der", 0, "pkcs1", "output"},
		{"pkcs1::DecodeRsaPublicKey.from_pkcs1_der", 1, "pkcs1", "factory"},
		{"pkcs1::EncodeRsaPublicKey.to_pkcs1_der", 0, "pkcs1", "output"},
		{"pkcs8::DecodePrivateKey.from_pkcs8_der", 1, "pkcs8", "factory"},
		{"pkcs8::PrivateKeyInfo.from_der", 1, "pkcs8", "factory"},
		{"pkcs8::EncodePrivateKey.to_pkcs8_der", 0, "pkcs8", "output"},
		{"pkcs8::DecodePrivateKey.from_pkcs8_encrypted_der", 2, "pkcs8", "factory"},
		{"pkcs8::EncryptedPrivateKeyInfo.decrypt", 1, "pkcs8", "operation"},
		{"pkcs8::PrivateKeyInfo.encrypt", 1, "pkcs8", "operation"},
		{"sec1::DecodeEcPrivateKey.from_sec1_der", 1, "sec1", "factory"},
		{"sec1::EncodeEcPrivateKey.to_sec1_der", 0, "sec1", "output"},
		{"sec1::point::EncodedPoint.from_bytes", 1, "sec1", "factory"},
		{"spki::DecodePublicKey.from_public_key_der", 1, "spki", "factory"},
		{"spki::SubjectPublicKeyInfo.from_der", 1, "spki", "factory"},
		{"spki::EncodePublicKey.to_public_key_der", 0, "spki", "output"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			t.Parallel()
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.library || got[0].Role != tt.role {
				t.Fatalf("ContractsFor(%q, %d) = %#v, want %s %s", tt.method, tt.arity, got[0], tt.library, tt.role)
			}
		})
	}
}
