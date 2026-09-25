package callgraph

import (
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// golang-fips/openssl lives at the module path github.com/golang-fips/openssl/v2
// but declares `package openssl`, and consumers import it without an alias.
// The parser used to name an unaliased import after the last path element, so
// `openssl.SHA1(msg)` never resolved to the package and no contract matched.
// This pins the unaliased consumer shape against every contracted call.
func TestGolangFIPSOpenSSLContractsResolveUnaliasedMajorVersionImport(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	g := buildGoGraph(t, `package app

import (
	"crypto"

	"github.com/golang-fips/openssl/v2"
)

func use(msg, digest, seed, privBytes, pubBytes []byte) {
	_ = openssl.NewSHA1()
	_ = openssl.SHA1(msg)
	_ = openssl.MD5(msg)
	_, _, _, _, _, _, _, _, _ = openssl.GenerateKeyRSA(2048)
	_, _, _, _ = openssl.GenerateKeyECDSA("P-256")
	_, _ = openssl.NewPublicKeyECDSA("P-256", nil, nil)
	_, _ = openssl.DecryptRSAPKCS1(nil, msg)
	_ = openssl.HashVerifyRSAPKCS1v15(nil, crypto.SHA256, msg, digest)
	_, _ = openssl.NewPrivateKeyEd25119(privBytes)
	_, _ = openssl.NewPublicKeyEd25119(pubBytes)
	_, _ = openssl.NewPrivateKeyEd25519FromSeed(seed)
	_ = openssl.VerifyEd25519(nil, msg, digest)
}
`)

	const pkg = "github.com/golang-fips/openssl/v2."
	var resolved []string
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if !strings.HasPrefix(call.Raw, "openssl.") {
				continue
			}
			key := call.Callee.String()
			if !strings.HasPrefix(key, pkg) {
				t.Errorf("%s resolved to %q, want the %s package", call.Raw, key, pkg)
				continue
			}
			if got := kb.ContractsFor(key, len(call.Arguments)); len(got) != 1 || got[0].SourceLibrary != "golang-fips-openssl-v2" {
				t.Errorf("%s: ContractsFor(%q, %d) = %v, want one golang-fips-openssl-v2 contract", call.Raw, key, len(call.Arguments), got)
			}
			resolved = append(resolved, strings.TrimPrefix(key, pkg))
		}
	}
	sort.Strings(resolved)
	if len(resolved) != 12 {
		t.Fatalf("resolved %d openssl calls %v, want 12", len(resolved), resolved)
	}
}

func TestGoImplicitImportName(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]string{
		"crypto/aes":                           "aes",
		"fmt":                                  "fmt",
		"github.com/golang-fips/openssl/v2":    "openssl",
		"github.com/cloudflare/circl/v10":      "circl",
		"gopkg.in/yaml.v3":                     "yaml",
		"gopkg.in/square/go-jose.v2":           "go-jose",
		"github.com/example/v2ray":             "v2ray",
		"v2":                                   "v2",
		"k8s.io/api/core/v1":                   "v1",
		"k8s.io/apimachinery/pkg/apis/meta/v1": "v1",
		"example.com/pkg/v0":                   "v0",
		"example.com/pkg/v02":                  "v02",
		"gopkg.in/yaml.v1":                     "yaml",
		"gopkg.in/check.v0":                    "check",
	} {
		if got := goImplicitImportName(path); got != want {
			t.Errorf("goImplicitImportName(%q) = %q, want %q", path, got, want)
		}
	}
}
