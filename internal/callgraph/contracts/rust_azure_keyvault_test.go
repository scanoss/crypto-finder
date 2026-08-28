package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The Azure Key Vault Rust SDK ships in two generations at once inside the
// committed range: a legacy all-in-one crate with a hand-written builder API,
// and the generated per-service crates that replaced it. They share method
// names and differ in ARITY, so a contract keyed on one generation's shape
// silently fails to resolve the other's call sites.
func TestLoadEmbeddedRustIncludesAzureKeyVaultContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
	}{
		// legacy: sign takes the algorithm directly, encrypt takes two args
		{"azure_security_keyvault::KeyClient.sign", 3, "azure_security_keyvault", "operation"},
		{"azure_security_keyvault::KeyClient.encrypt", 2, "azure_security_keyvault", "operation"},
		{"azure_security_keyvault::KeyClient.decrypt", 2, "azure_security_keyvault", "operation"},
		{"azure_security_keyvault::KeyClient.wrap_key", 2, "azure_security_keyvault", "operation"},
		{"azure_security_keyvault::KeyClient.new", 2, "azure_security_keyvault", "factory"},
		// generated: every operation takes three
		{"azure_security_keyvault_keys::KeyClient.encrypt", 3, "azure_security_keyvault_keys", "operation"},
		{"azure_security_keyvault_keys::KeyClient.sign", 3, "azure_security_keyvault_keys", "operation"},
		{"azure_security_keyvault_keys::KeyClient.unwrap_key", 3, "azure_security_keyvault_keys", "operation"},
		{"azure_security_keyvault_keys::KeyClient.create_key", 3, "azure_security_keyvault_keys", "factory"},
		// the non-crypto siblings
		{"azure_security_keyvault_secrets::SecretClient.set_secret", 3, "azure_security_keyvault_secrets", "operation"},
		{"azure_security_keyvault_certificates::CertificateClient.create_certificate", 3, "azure_security_keyvault_certificates", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want role %q from %s", tt.method, tt.arity, got[0], tt.role, tt.lib)
			}
		})
	}
}

// `KeyClient.encrypt` exists in both generations with different arities. The
// arity is what separates them, so assert each resolves to its own crate and
// neither is answered by the other's contract.
func TestAzureKeyVaultGenerationsDoNotBlurTogether(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		lib    string
	}{
		{"azure_security_keyvault.KeyClient.encrypt", 2, "azure_security_keyvault"},
		{"azure_security_keyvault_keys.KeyClient.encrypt", 3, "azure_security_keyvault_keys"},
		{"azure_security_keyvault.KeyClient.sign", 3, "azure_security_keyvault"},
		{"azure_security_keyvault_keys.KeyClient.sign", 3, "azure_security_keyvault_keys"},
	} {
		t.Run(fmt.Sprintf("%s#%d", tc.method, tc.arity), func(t *testing.T) {
			// The dot-joined form is what a call site produces; the KB is
			// authored with "::". Both must reach the same contract.
			got := kb.ContractsFor(tc.method, tc.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tc.method, tc.arity, len(got))
			}
			if got[0].SourceLibrary != tc.lib {
				t.Fatalf("%s#%d resolved to %q, want %q — the two generations must stay apart",
					tc.method, tc.arity, got[0].SourceLibrary, tc.lib)
			}
		})
	}
}
