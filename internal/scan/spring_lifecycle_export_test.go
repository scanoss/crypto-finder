package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestBuildGraphFragmentExport_Issue137ExportsRsaSecretEncryptorOperations(t *testing.T) {
	t.Parallel()

	ownerID := callgraph.FunctionID{Package: "com.acme", Type: "Secrets", Name: "roundTrip#1"}
	factoryID := callgraph.FunctionID{Package: "org.springframework.security.crypto.encrypt", Type: "RsaSecretEncryptor", Name: "<init>#0"}
	encryptID := callgraph.FunctionID{Package: "org.springframework.security.crypto.encrypt", Type: "RsaSecretEncryptor", Name: "encrypt#1"}
	decryptID := callgraph.FunctionID{Package: "org.springframework.security.crypto.encrypt", Type: "RsaSecretEncryptor", Name: "decrypt#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID:        ownerID,
			FilePath:  "Secrets.java",
			StartLine: 1,
			EndLine:   8,
			Calls: []callgraph.FunctionCall{
				{Callee: factoryID, FilePath: "Secrets.java", Line: 3, Raw: "new RsaSecretEncryptor()", AssignedVar: "encryptor"},
				{Callee: encryptID, FilePath: "Secrets.java", Line: 4, Raw: "encryptor.encrypt(plain)", ReceiverVar: "encryptor"},
				{Callee: decryptID, FilePath: "Secrets.java", Line: 5, Raw: "encryptor.decrypt(ciphertext)", ReceiverVar: "encryptor"},
			},
		},
		factoryID.String(): {ID: factoryID, FilePath: "RsaSecretEncryptor.java", StartLine: 1, ReturnType: "org.springframework.security.crypto.encrypt.RsaSecretEncryptor"},
		encryptID.String(): {ID: encryptID, FilePath: "RsaSecretEncryptor.java", StartLine: 2, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
		decryptID.String(): {ID: decryptID, FilePath: "RsaSecretEncryptor.java", StartLine: 3, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Secrets.java",
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "rsa-secret-encryptor",
			StartLine: 3,
			EndLine:   3,
			Match:     "new RsaSecretEncryptor()",
			Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
			Metadata: map[string]string{
				"api":       "org.springframework.security.crypto.encrypt.RsaSecretEncryptor.<init>",
				"assetType": "algorithm",
			},
		}},
	}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 1 {
		t.Fatalf("crypto_annotations = %#v, want one finding", payload.CryptoAnnotations)
	}

	operations := map[string]string{}
	for _, support := range payload.SupportingCalls {
		if support.SupportingCall != nil {
			operations[support.SupportingCall.FunctionName] = support.Category
		}
	}
	for _, name := range []string{
		"org.springframework.security.crypto.encrypt.RsaSecretEncryptor.encrypt",
		"org.springframework.security.crypto.encrypt.RsaSecretEncryptor.decrypt",
	} {
		if operations[name] != "operation" {
			t.Fatalf("%s category = %q, want operation; supporting_calls = %#v", name, operations[name], payload.SupportingCalls)
		}
	}
	if len(payload.CryptoAnnotations[0].SupportingCallIDs) < 2 {
		t.Fatalf("supporting_call_ids = %#v, want encrypt and decrypt", payload.CryptoAnnotations[0].SupportingCallIDs)
	}
}
