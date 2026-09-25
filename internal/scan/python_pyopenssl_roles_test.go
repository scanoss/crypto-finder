// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// pyopensslConsumer exercises the two halves of the pyOpenSSL contract
// separately: TLS context and connection configuration through
// `from OpenSSL import SSL`, and key and certificate operations through
// `from OpenSSL.crypto import ...`. Both used to leave every call after the
// constructor keyed on the consumer's variable (`mypkg.ctx.set_cipher_list`),
// which no contract joins, so the supporting call shipped with no category.
const pyopensslConsumer = `from OpenSSL import SSL
from OpenSSL.crypto import PKey, X509, TYPE_RSA


def tls(sock):
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    ctx.set_cipher_list(b"ECDHE+AESGCM")
    ctx.use_privatekey_file("key.pem")
    ctx.check_privatekey()
    ctx.set_verify(SSL.VERIFY_PEER)
    conn = SSL.Connection(ctx, sock)
    conn.do_handshake()
    conn.send(b"payload")
    return conn.get_peer_certificate()


def cert():
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)
    x = X509()
    x.set_pubkey(key)
    x.sign(key, "sha256")
    return x.digest("sha256")
`

func pyopensslFinding(line int, match, api, assetType string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     match,
		Rules:     []entities.RuleInfo{{ID: "python.pyopenssl.synth"}},
		Metadata:  map[string]string{"api": api, "assetType": assetType, "library": "pyopenssl"},
	}
}

func TestPythonPyopenssl_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "app.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{
				pyopensslFinding(6, "SSL.Context(SSL.TLS_METHOD)", "OpenSSL.SSL.Context", "protocol"),
				pyopensslFinding(19, "PKey()", "OpenSSL.crypto.PKey", "related-crypto-material"),
				pyopensslFinding(21, "X509()", "OpenSSL.crypto.X509", "certificate"),
			},
		}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyopensslConsumer), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
	b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem("python", javaruntime.Config{}))
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	export := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "mypkg", Ecosystem: "python",
	})

	type site struct {
		line   int
		symbol string
	}
	got := map[site]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall == nil {
			continue
		}
		got[site{s.StartLine, s.SupportingCall.FunctionName}] = s.Category
	}

	for _, want := range []struct {
		site     site
		category string
	}{
		// TLS context configuration.
		{site{7, "OpenSSL.SSL.Context.set_min_proto_version"}, "config"},
		{site{8, "OpenSSL.SSL.Context.set_cipher_list"}, "config"},
		{site{9, "OpenSSL.SSL.Context.use_privatekey_file"}, "config"},
		{site{10, "OpenSSL.SSL.Context.check_privatekey"}, "operation"},
		{site{11, "OpenSSL.SSL.Context.set_verify"}, "config"},
		// Key and certificate operations.
		{site{20, "OpenSSL.crypto.PKey.generate_key"}, "operation"},
		{site{22, "OpenSSL.crypto.X509.set_pubkey"}, "config"},
		{site{23, "OpenSSL.crypto.X509.sign"}, "operation"},
		{site{24, "OpenSSL.crypto.X509.digest"}, "operation"},
	} {
		category, ok := got[want.site]
		if !ok {
			t.Errorf("no supporting call %s at line %d; got %v", want.site.symbol, want.site.line, got)
			continue
		}
		if category != want.category {
			t.Errorf("%s at line %d: category = %q, want %q", want.site.symbol, want.site.line, category, want.category)
		}
	}

	// Application data is not part of any crypto lifecycle.
	for s := range got {
		if s.symbol == "OpenSSL.SSL.Connection.send" || s.symbol == "mypkg.conn.send" {
			t.Errorf("conn.send at line %d became a supporting call; it carries no cryptography", s.line)
		}
	}
}
