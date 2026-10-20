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

const esdkKMS = "aws_encryption_sdk.key_providers.kms"

const keystoreClient = "aws_cryptographic_material_providers.smithygenerated.aws_cryptography_keystore.client.KeyStore"

const mplClient = "aws_cryptographic_material_providers.smithygenerated.aws_cryptography_materialproviders.client.AwsCryptographicMaterialProviders"

// awsPykmipTruststoreTracer writes each library the way its own examples do.
// A factory on an anchor line types the receiver its later calls are keyed on.
const awsPykmipTruststoreTracer = `import aws_encryption_sdk
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateRawAesKeyringInput
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
from truststore import SSLContext
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.models import CreateKeyInput
from kmip.services.kmip_client import KMIPProxy


def run(key, data, sock, arn, request, store_config, template):
    client = aws_encryption_sdk.EncryptionSDKClient()
    mpl = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
    ring = mpl.create_raw_aes_keyring(input=CreateRawAesKeyringInput(key_namespace="n", key_name="k", wrapping_key=key))
    ct, header = client.encrypt(source=data, keyring=ring)
    provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[arn])
    provider.add_master_key(arn)
    cmm = aws_encryption_sdk.DefaultCryptoMaterialsManager(provider)
    materials = cmm.get_encryption_materials(request)
    stream = aws_encryption_sdk.StreamEncryptor(source=data, key_provider=provider)
    chunk = stream.read()
    with ProxyKmipClient() as kmip:
        uid = kmip.create(enums.CryptographicAlgorithm.AES, 256)
        sig = kmip.sign(data, uid)
    ctx = SSLContext()
    ctx.load_verify_locations()
    ctx.set_ciphers("ECDHE+AESGCM")
    tls = ctx.wrap_socket(sock)
    store = KeyStore(config=store_config)
    branch = store.create_key(input=CreateKeyInput())
    legacy = KMIPProxy()
    created = legacy.create(enums.ObjectType.SYMMETRIC_KEY, template)
    return ct, materials, chunk, sig, tls, branch, created
`

func TestAwsPykmipTruststore_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	lines := strings.Split(awsPykmipTruststoreTracer, "\n")
	var assets []entities.CryptographicAsset
	for _, line := range []int{14, 15, 18, 20, 22, 24, 27, 31, 33} {
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
		{16, mplClient + ".create_raw_aes_keyring", "factory"},
		{17, "aws_encryption_sdk.EncryptionSDKClient.encrypt", "operation"},
		{19, esdkKMS + ".StrictAwsKmsMasterKeyProvider.add_master_key", "config"},
		{21, "aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager.get_encryption_materials", "operation"},
		{23, "aws_encryption_sdk.streaming_client.StreamEncryptor.read", "operation"},
		{25, "kmip.pie.client.ProxyKmipClient.create", "operation"},
		{26, "kmip.pie.client.ProxyKmipClient.sign", "operation"},
		{28, "truststore._api.SSLContext.load_verify_locations", "config"},
		{29, "truststore._api.SSLContext.set_ciphers", "config"},
		{30, "truststore._api.SSLContext.wrap_socket", "factory"},
		{32, keystoreClient + ".create_key", "operation"},
		{34, "kmip.services.kmip_client.KMIPProxy.create", "operation"},
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
