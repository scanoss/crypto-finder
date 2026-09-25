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
)

const springRsaOverloadsSrc = `package com.example;

import org.springframework.security.crypto.encrypt.RsaRawEncryptor;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;

public class Rsa {
    public void raw(String text, byte[] data) {
        RsaRawEncryptor raw = new RsaRawEncryptor();
        String cipherText = raw.encrypt(text);
        String plainText = raw.decrypt(cipherText);
        byte[] cipherBytes = raw.encrypt(data);
        byte[] plainBytes = raw.decrypt(cipherBytes);
    }

    public void secret(String text, byte[] data) {
        RsaSecretEncryptor secret = new RsaSecretEncryptor();
        String cipherText = secret.encrypt(text);
        String plainText = secret.decrypt(cipherText);
        byte[] cipherBytes = secret.encrypt(data);
        byte[] plainBytes = secret.decrypt(cipherBytes);
    }
}
`

// The RSA encryptors overload encrypt and decrypt at one argument as String to
// String and byte[] to byte[]. A contract is keyed by method and arity, so the
// knowledge base cannot declare one return per overload on these classes.
// Both overloads still ship as operations through the TextEncryptor and
// BytesEncryptor contracts the classes implement, and each keeps the argument
// type of its own call site.
func TestJavaSpringRsaEncryptorOverloadsAreOperations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Rsa.java"), []byte(springRsaOverloadsSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.example:consumer"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	const pkg = "org.springframework.security.crypto.encrypt."
	report := &entities.InterimReport{Findings: []entities.Finding{
		javaConstructorFinding("Rsa.java", 8, "new RsaRawEncryptor()", pkg+"RsaRawEncryptor.<init>"),
		javaConstructorFinding("Rsa.java", 16, "new RsaSecretEncryptor()", pkg+"RsaSecretEncryptor.<init>"),
	}}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.example:consumer", Ecosystem: "java",
	})

	type call struct{ category, signature string }
	got := map[int]call{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall != nil {
			got[s.StartLine] = call{s.Category, s.SupportingCall.CanonicalSignature}
		}
	}
	for line, signature := range map[int]string{
		9:  pkg + "RsaRawEncryptor.encrypt(String)",
		10: pkg + "RsaRawEncryptor.decrypt(String)",
		11: pkg + "RsaRawEncryptor.encrypt(byte[])",
		12: pkg + "RsaRawEncryptor.decrypt(byte[])",
		17: pkg + "RsaSecretEncryptor.encrypt(String)",
		18: pkg + "RsaSecretEncryptor.decrypt(String)",
		19: pkg + "RsaSecretEncryptor.encrypt(byte[])",
		20: pkg + "RsaSecretEncryptor.decrypt(byte[])",
	} {
		have, ok := got[line]
		if !ok {
			t.Errorf("line %d: no supporting call, want %s; got %v", line, signature, got)
			continue
		}
		if have != (call{"operation", signature}) {
			t.Errorf("line %d = %+v, want operation %s", line, have, signature)
		}
	}
}
