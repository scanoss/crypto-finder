package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Only the keySize property yields resolved key-length evidence; a keyLength
// contribution is exported but never read. These libraries publish a key size
// where the argument is one (the HMAC key of GnuTLS, in bytes) and publish none
// where the argument is not the key: a libjwt key buffer is a PEM document for
// the RSA and EC algorithms, and an s2n-tls ticket key is the input secret the
// library expands into an AES-256-GCM key.
func TestCContractsPublishKeySizeNotKeyLength(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	for _, lib := range []string{"gnutls", "libjwt", "s2n-tls"} {
		for key, list := range kb.Contracts {
			for _, c := range list {
				if c.SourceLibrary != lib {
					continue
				}
				for _, p := range c.Parameters {
					if p.Contributes != nil && p.Contributes.Property == "keyLength" {
						t.Errorf("%s %s: contributes inert property keyLength", lib, key)
					}
				}
			}
		}
	}

	byteKeySize := map[string]struct{ arity, index int }{
		"gnutls_hmac_init": {4, 3},
		"gnutls_hmac_fast": {6, 2},
	}
	for method, want := range byteKeySize {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != want.index || p.Contributes == nil {
				continue
			}
			found = true
			if p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_byte_length" {
				t.Errorf("%s: parameters[%d] contributes %#v, want keySize from argument_byte_length",
					method, want.index, p.Contributes)
			}
		}
		if !found {
			t.Errorf("%s: no contribution at index %d", method, want.index)
		}
	}
}
