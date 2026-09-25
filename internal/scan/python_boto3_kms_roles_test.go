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

// boto3Consumer binds a KMS client every way boto3 allows. The client type
// exists only behind `client('kms')`, a conditional contract, so each receiver
// used to stay keyed on the consumer's variable (`mypkg.kms.encrypt`).
const boto3Consumer = `import boto3
import boto3.session
from boto3 import Session as TopSession
from boto3.session import Session


def plain(data):
    kms = boto3.client('kms')
    kms.encrypt(KeyId="alias/k", Plaintext=data)
    return kms.generate_random(NumberOfBytes=32)


def regional(data):
    kms = boto3.client("kms", region_name="eu-west-1")
    kms.decrypt(CiphertextBlob=data)
    return kms.generate_random(NumberOfBytes=32)


def session_top(data):
    session = boto3.Session(profile_name="p")
    kms = session.client('kms')
    kms.sign(KeyId="alias/k", Message=data, SigningAlgorithm="ECDSA_SHA_256")
    return kms.generate_random(NumberOfBytes=32)


def session_attr(data):
    session = boto3.session.Session()
    kms = session.client('kms')
    kms.get_public_key(KeyId="alias/k")
    return kms.generate_random(NumberOfBytes=32)


def session_imported(data):
    session = Session()
    kms = session.client('kms')
    kms.generate_data_key_pair_without_plaintext(KeyId="alias/k", KeyPairSpec="RSA_2048")
    return kms.generate_random(NumberOfBytes=32)


def session_top_imported(data):
    session = TopSession()
    kms = session.client('kms')
    kms.verify_mac(KeyId="alias/k", Message=data, Mac=data, MacAlgorithm="HMAC_SHA_256")
    return kms.generate_random(NumberOfBytes=32)


def other_service(data):
    s3 = boto3.client('s3')
    s3.encrypt(KeyId="alias/k", Plaintext=data)
    return s3.generate_random(NumberOfBytes=32)


def named_service(name, data):
    client = boto3.client(name)
    client.encrypt(KeyId="alias/k", Plaintext=data)
    return client.generate_random(NumberOfBytes=32)
`

func boto3Finding(line int) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     strings.TrimSpace(strings.Split(boto3Consumer, "\n")[line-1]),
		Rules:     []entities.RuleInfo{{ID: "python.boto3.algorithm.ae.aes-gcm.kms-encrypt"}},
		Metadata: map[string]string{
			"api":       "kms.encrypt",
			"assetType": "algorithm",
			"operation": "encrypt",
		},
	}
}

func TestPythonBoto3_KMSClientBindsFromItsServiceLiteral(t *testing.T) {
	t.Parallel()

	anchors := []int{10, 16, 23, 30, 37, 44, 50, 56}
	assets := make([]entities.CryptographicAsset, 0, len(anchors))
	for _, line := range anchors {
		assets = append(assets, boto3Finding(line))
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "app.py", Language: "python", CryptographicAssets: assets,
		}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(boto3Consumer), 0o600); err != nil {
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

	for _, want := range []struct {
		line     int
		symbol   string
		category string
	}{
		{8, "boto3.client", "factory"},
		{9, "botocore.client.KMS.encrypt", "operation"},
		{14, "boto3.client", "factory"},
		{15, "botocore.client.KMS.decrypt", "operation"},
		{20, "boto3.Session", "factory"},
		{21, "boto3.session.Session.client", "factory"},
		{22, "botocore.client.KMS.sign", "operation"},
		{27, "boto3.session.Session", "factory"},
		{29, "botocore.client.KMS.get_public_key", "output"},
		{34, "boto3.session.Session.<init>", "factory"},
		{36, "botocore.client.KMS.generate_data_key_pair_without_plaintext", "operation"},
		{41, "boto3.Session.<init>", "factory"},
		{43, "botocore.client.KMS.verify_mac", "operation"},
	} {
		category, ok := got[want.line][want.symbol]
		if !ok {
			t.Errorf("line %d: no supporting call %s; got %v", want.line, want.symbol, got[want.line])
			continue
		}
		if category != want.category {
			t.Errorf("line %d: %s category = %q, want %q", want.line, want.symbol, category, want.category)
		}
	}

	// Only the literal 'kms' binds a KMS client: an S3 client and a service
	// name held in a variable must not borrow the KMS operations.
	for _, line := range []int{49, 55} {
		for symbol := range got[line] {
			if symbol == "botocore.client.KMS.encrypt" {
				t.Errorf("line %d: a non-KMS client resolved to %s", line, symbol)
			}
		}
	}
}
