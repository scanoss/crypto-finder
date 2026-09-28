package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The NSS contracts key on bare C function names. This pins, against what the C
// parser emits, that the PK11 context, one-shot, key-generation, derivation,
// cryptohi signing and verification, certificate and libssl configuration calls
// each resolve to exactly one NSS contract with the expected role, and that slot
// management and object destruction resolve to nothing.
func TestNSSContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "pk11pub.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "cert.h"
#include "ssl.h"

SECStatus flows(PK11SlotInfo *slot, PK11SymKey *key, SECItem *param, SECItem *sig, SECItem *hash,
                SECKEYPublicKey *pub, SECKEYPrivateKey *priv, CERTCertificate *cert, PRFileDesc *fd,
                unsigned char *out, unsigned int *outLen, const unsigned char *in, SSLVersionRange *range) {
    PK11Context *ctx = PK11_CreateContextBySymKey(CKM_AES_GCM, CKA_ENCRYPT, key, param);
    int len = 0;
    PK11_CipherOp(ctx, out, &len, 64, in, 64);
    PK11Context *md = PK11_CreateDigestContext(SEC_OID_SHA256);
    PK11_DigestBegin(md);
    PK11_DigestOp(md, in, 64);
    PK11_DigestFinal(md, out, outLen, 32);
    PK11_HashBuf(SEC_OID_SHA384, out, in, 64);
    PK11_Encrypt(key, CKM_AES_CBC_PAD, param, out, outLen, 64, in, 48);
    PK11_PubEncrypt(pub, CKM_RSA_PKCS_OAEP, param, out, outLen, 256, in, 32, NULL);
    PK11SymKey *aes = PK11_KeyGen(slot, CKM_AES_KEY_GEN, NULL, 32, NULL);
    SECKEYPrivateKey *ec = PK11_GenerateKeyPair(slot, CKM_EC_KEY_PAIR_GEN, param, &pub, PR_FALSE, PR_TRUE, NULL);
    PK11_PubDerive(priv, pub, PR_FALSE, NULL, NULL, CKM_ECDH1_DERIVE, CKM_AES_GCM, CKA_ENCRYPT, 32, NULL);
    SECKEYPrivateKey *rsa = SECKEY_CreateRSAPrivateKey(2048, &pub, NULL);
    PK11_SignWithMechanism(priv, CKM_RSA_PKCS_PSS, param, sig, hash);
    SGNContext *sgn = SGN_NewContext(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION, priv);
    SGN_Begin(sgn);
    SGN_Update(sgn, in, 64);
    SGN_End(sgn, sig);
    VFY_VerifyData(in, 64, pub, sig, SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE, NULL);
    CERTCertificate *leaf = CERT_DecodeCertFromPackage((char *)in, 64);
    CERT_VerifyCertNow(CERT_GetDefaultCertDB(), leaf, PR_TRUE, certUsageSSLServer, NULL);
    CERT_ExtractPublicKey(leaf);
    PRFileDesc *ssl = SSL_ImportFD(NULL, fd);
    SSL_OptionSet(ssl, SSL_ENABLE_TLS13_COMPAT_MODE, PR_TRUE);
    SSL_CipherPrefSet(ssl, TLS_AES_128_GCM_SHA256, PR_TRUE);
    SSL_VersionRangeSet(ssl, range);

    /* Slot management and destruction. None of these may resolve to a contract. */
    PK11_GetInternalSlot();
    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(aes);
    SECKEY_DestroyPrivateKey(ec);
    SECKEY_DestroyPrivateKey(rsa);
    CERT_DestroyCertificate(cert);
    return SECSuccess;
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"PK11_CreateContextBySymKey": {4, "factory"},
		"PK11_CipherOp":              {6, "operation"},
		"PK11_CreateDigestContext":   {1, "factory"},
		"PK11_DigestBegin":           {1, "config"},
		"PK11_DigestOp":              {3, "operation"},
		"PK11_DigestFinal":           {4, "operation"},
		"PK11_HashBuf":               {4, "operation"},
		"PK11_Encrypt":               {8, "operation"},
		"PK11_PubEncrypt":            {9, "operation"},
		"PK11_KeyGen":                {5, "factory"},
		"PK11_GenerateKeyPair":       {7, "factory"},
		"PK11_PubDerive":             {10, "operation"},
		"SECKEY_CreateRSAPrivateKey": {3, "factory"},
		"PK11_SignWithMechanism":     {5, "operation"},
		"SGN_NewContext":             {2, "factory"},
		"SGN_Begin":                  {1, "config"},
		"SGN_Update":                 {3, "operation"},
		"SGN_End":                    {2, "operation"},
		"VFY_VerifyData":             {6, "operation"},
		"CERT_DecodeCertFromPackage": {2, "factory"},
		"CERT_VerifyCertNow":         {5, "operation"},
		"CERT_ExtractPublicKey":      {1, "output"},
		"SSL_ImportFD":               {2, "factory"},
		"SSL_OptionSet":              {3, "config"},
		"SSL_CipherPrefSet":          {3, "config"},
		"SSL_VersionRangeSet":        {2, "config"},
	}
	negative := map[string]bool{
		"PK11_GetInternalSlot": true, "PK11_DestroyContext": true, "PK11_FreeSymKey": true,
		"SECKEY_DestroyPrivateKey": true, "CERT_DestroyCertificate": true,
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				bare := method
				if idx := strings.LastIndex(bare, "."); idx >= 0 {
					bare = bare[idx+1:]
				}
				if negative[bare] {
					if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
						t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
					}
					seen[bare] = true
					continue
				}
				expect, ok := want[bare]
				if !ok {
					continue
				}
				if len(call.Arguments) != expect.arity {
					t.Fatalf("%s: parsed arity %d, want %d", bare, len(call.Arguments), expect.arity)
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one", method, expect.arity, len(got))
				}
				if got[0].Role != expect.role || got[0].SourceLibrary != "nss" {
					t.Fatalf("%s: role %q library %q, want %q nss", bare, got[0].Role, got[0].SourceLibrary, expect.role)
				}
				seen[bare] = true
			}
		}
	}
	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q", method)
		}
	}
	for method := range negative {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover negative %q", method)
		}
	}
}

// The mechanism, hash OID or signature OID is what selects an NSS operation, so
// each entry must carry that argument as operation-determining at its real index.
func TestNSSContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	selector := map[string]struct{ arity, index int }{
		"PK11_CreateContextBySymKey": {4, 0},
		"PK11_CreateDigestContext":   {1, 0},
		"PK11_HashBuf":               {4, 0},
		"PK11_Encrypt":               {8, 1},
		"PK11_Decrypt":               {8, 1},
		"PK11_PubEncrypt":            {9, 1},
		"PK11_PrivDecrypt":           {8, 1},
		"PK11_KeyGen":                {5, 1},
		"PK11_GenerateKeyPair":       {7, 1},
		"PK11_PubDerive":             {10, 5},
		"SGN_NewContext":             {2, 0},
		"VFY_CreateContext":          {4, 2},
		"VFY_VerifyData":             {6, 4},
		"SSL_CipherPrefSet":          {3, 1},
	}
	for method, want := range selector {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == want.index {
				found = p.Role == "operation-determining"
			}
		}
		if !found {
			t.Errorf("%s: parameter %d is not operation-determining", method, want.index)
		}
	}
	rsa := kb.ContractsFor("SECKEY_CreateRSAPrivateKey", 3)
	if len(rsa) != 1 || len(rsa[0].Parameters) != 1 || rsa[0].Parameters[0].Contributes == nil ||
		rsa[0].Parameters[0].Contributes.Property != "keySize" {
		t.Fatalf("SECKEY_CreateRSAPrivateKey must contribute keySize from its first argument: %#v", rsa)
	}
}
