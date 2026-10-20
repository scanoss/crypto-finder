// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

const mplClient = "aws_cryptographic_material_providers.smithygenerated.aws_cryptography_materialproviders.client.AwsCryptographicMaterialProviders"

// awsPykmipTruststoreTracer writes each library the way its own examples do.
// A factory on an anchor line types the receiver its later calls are keyed on.
const awsPykmipTruststoreTracer = `import aws_encryption_sdk
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateRawAesKeyringInput
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
import truststore


def run(key, data):
    client = aws_encryption_sdk.EncryptionSDKClient()
    mpl = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
    ring = mpl.create_raw_aes_keyring(input=CreateRawAesKeyringInput(key_namespace="n", key_name="k", wrapping_key=key))
    ct, header = client.encrypt(source=data, keyring=ring)
    kmip = ProxyKmipClient()
    uid = kmip.create(enums.CryptographicAlgorithm.AES, 256)
    sig = kmip.sign(data, uid)
    ctx = truststore.SSLContext()
    ctx.load_verify_locations()
    ctx.set_ciphers("ECDHE+AESGCM")
    return ct, sig, ctx
`

func TestAwsPykmipTruststore_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	lines := strings.Split(awsPykmipTruststoreTracer, "\n")
	var assets []entities.CryptographicAsset
	for _, line := range []int{11, 12, 15, 18} {
		assets = append(assets, entities.CryptographicAsset{
			StartLine: line, EndLine: line,
			Match:    strings.TrimSpace(lines[line-1]),
			Rules:    []entities.RuleInfo{{ID: "python.test"}},
			Metadata: map[string]string{"assetType": "algorithm"},
		})
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "app.py", Language: "python", CryptographicAssets: assets,
		}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(awsPykmipTruststoreTracer), 0o600); err != nil {
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

	got := map[int]map[string]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall == nil {
			continue
		}
		if got[s.StartLine] == nil {
			got[s.StartLine] = map[string]string{}
		}
		got[s.StartLine][s.SupportingCall.FunctionName] = s.Category
	}
	want := []pycaSupportingCall{
		{13, mplClient + ".create_raw_aes_keyring", "factory"},
		{14, "aws_encryption_sdk.EncryptionSDKClient.encrypt", "operation"},
		{16, "kmip.pie.client.ProxyKmipClient.create", "operation"},
		{17, "kmip.pie.client.ProxyKmipClient.sign", "operation"},
		{19, "truststore._api.SSLContext.load_verify_locations", "config"},
		{20, "truststore._api.SSLContext.set_ciphers", "config"},
	}
	for _, w := range want {
		category, ok := got[w.line][w.symbol]
		if !ok {
			t.Errorf("line %d: no supporting call %s; got %v", w.line, w.symbol, got[w.line])
			continue
		}
		if category != w.category {
			t.Errorf("line %d: %s category = %q, want %q", w.line, w.symbol, category, w.category)
		}
	}
}
