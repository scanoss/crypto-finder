// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The qtbase contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestQtBaseContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QPasswordDigestor>
#include <QSslSocket>

void flows(QCryptographicHash& h, QMessageAuthenticationCode& mac, QSslConfiguration& conf, QSslSocket& sock, QSslKey& key, QSslCertificate& cert, int x) {
    h.addData(x);
    h.addData(x, x);
    h.result();
    h.resultView();
    QCryptographicHash::hash(x, x);
    mac.setKey(x);
    mac.addData(x);
    mac.addData(x, x);
    mac.result();
    mac.resultView();
    QMessageAuthenticationCode::hash(x, x, x);
    QPasswordDigestor::deriveKeyPbkdf1(x, x, x, x, x);
    QPasswordDigestor::deriveKeyPbkdf2(x, x, x, x, x);
    QSslConfiguration::defaultConfiguration();
    QSslConfiguration::defaultDtlsConfiguration();
    conf.setProtocol(x);
    conf.setPeerVerifyMode(x);
    conf.setPeerVerifyDepth(x);
    conf.setCiphers(x);
    conf.setEllipticCurves(x);
    conf.setLocalCertificate(x);
    conf.setLocalCertificateChain(x);
    conf.setPrivateKey(x);
    conf.setCaCertificates(x);
    conf.addCaCertificate(x);
    conf.addCaCertificates(x);
    conf.addCaCertificates(x, x);
    conf.addCaCertificates(x, x, x);
    conf.setSslOption(x, x);
    conf.setDiffieHellmanParameters(x);
    conf.setPreSharedKeyIdentityHint(x);
    conf.setOcspStaplingEnabled(x);
    conf.setMissingCertificateIsFatal(x);
    QSslConfiguration::setDefaultConfiguration(x);
    conf.setBackendConfigurationOption(x, x);
    sock.setSslConfiguration(x);
    sock.setProtocol(x);
    sock.setPeerVerifyMode(x);
    sock.setPeerVerifyDepth(x);
    sock.setLocalCertificate(x);
    sock.setLocalCertificate(x, x);
    sock.setLocalCertificateChain(x);
    sock.setPrivateKey(x);
    sock.setPrivateKey(x, x);
    sock.setPrivateKey(x, x, x);
    sock.setPrivateKey(x, x, x, x);
    sock.setCiphers(x);
    sock.ignoreSslErrors();
    sock.ignoreSslErrors(x);
    sock.connectToHostEncrypted(x, x);
    sock.connectToHostEncrypted(x, x, x);
    sock.connectToHostEncrypted(x, x, x, x);
    sock.connectToHostEncrypted(x, x, x, x, x);
    sock.startClientEncryption();
    sock.startServerEncryption();
    sock.waitForEncrypted();
    sock.waitForEncrypted(x);
    key.toPem();
    key.toPem(x);
    key.toDer();
    key.toDer(x);
    cert.toPem();
    cert.toDer();
    h.reset();
    h.hashLength(x);
    sock.peerCertificate();
}
`
	if err := os.WriteFile(filepath.Join(dir, "net.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"QCryptographicHash.addData#1":                      "operation",
		"QCryptographicHash.addData#2":                      "operation",
		"QCryptographicHash.result#0":                       "output",
		"QCryptographicHash.resultView#0":                   "output",
		"QCryptographicHash.hash#2":                         "operation",
		"QMessageAuthenticationCode.setKey#1":               "config",
		"QMessageAuthenticationCode.addData#1":              "operation",
		"QMessageAuthenticationCode.addData#2":              "operation",
		"QMessageAuthenticationCode.result#0":               "output",
		"QMessageAuthenticationCode.resultView#0":           "output",
		"QMessageAuthenticationCode.hash#3":                 "operation",
		"QPasswordDigestor.deriveKeyPbkdf1#5":               "operation",
		"QPasswordDigestor.deriveKeyPbkdf2#5":               "operation",
		"QSslConfiguration.defaultConfiguration#0":          "factory",
		"QSslConfiguration.defaultDtlsConfiguration#0":      "factory",
		"QSslConfiguration.setProtocol#1":                   "config",
		"QSslConfiguration.setPeerVerifyMode#1":             "config",
		"QSslConfiguration.setPeerVerifyDepth#1":            "config",
		"QSslConfiguration.setCiphers#1":                    "config",
		"QSslConfiguration.setEllipticCurves#1":             "config",
		"QSslConfiguration.setLocalCertificate#1":           "config",
		"QSslConfiguration.setLocalCertificateChain#1":      "config",
		"QSslConfiguration.setPrivateKey#1":                 "config",
		"QSslConfiguration.setCaCertificates#1":             "config",
		"QSslConfiguration.addCaCertificate#1":              "config",
		"QSslConfiguration.addCaCertificates#1":             "config",
		"QSslConfiguration.addCaCertificates#2":             "config",
		"QSslConfiguration.addCaCertificates#3":             "config",
		"QSslConfiguration.setSslOption#2":                  "config",
		"QSslConfiguration.setDiffieHellmanParameters#1":    "config",
		"QSslConfiguration.setPreSharedKeyIdentityHint#1":   "config",
		"QSslConfiguration.setOcspStaplingEnabled#1":        "config",
		"QSslConfiguration.setMissingCertificateIsFatal#1":  "config",
		"QSslConfiguration.setDefaultConfiguration#1":       "config",
		"QSslConfiguration.setBackendConfigurationOption#2": "config",
		"QSslSocket.setSslConfiguration#1":                  "config",
		"QSslSocket.setProtocol#1":                          "config",
		"QSslSocket.setPeerVerifyMode#1":                    "config",
		"QSslSocket.setPeerVerifyDepth#1":                   "config",
		"QSslSocket.setLocalCertificate#1":                  "config",
		"QSslSocket.setLocalCertificate#2":                  "config",
		"QSslSocket.setLocalCertificateChain#1":             "config",
		"QSslSocket.setPrivateKey#1":                        "config",
		"QSslSocket.setPrivateKey#2":                        "config",
		"QSslSocket.setPrivateKey#3":                        "config",
		"QSslSocket.setPrivateKey#4":                        "config",
		"QSslSocket.setCiphers#1":                           "config",
		"QSslSocket.ignoreSslErrors#0":                      "config",
		"QSslSocket.ignoreSslErrors#1":                      "config",
		"QSslSocket.connectToHostEncrypted#2":               "operation",
		"QSslSocket.connectToHostEncrypted#3":               "operation",
		"QSslSocket.connectToHostEncrypted#4":               "operation",
		"QSslSocket.connectToHostEncrypted#5":               "operation",
		"QSslSocket.startClientEncryption#0":                "operation",
		"QSslSocket.startServerEncryption#0":                "operation",
		"QSslSocket.waitForEncrypted#0":                     "operation",
		"QSslSocket.waitForEncrypted#1":                     "operation",
		"QSslKey.toPem#0":                                   "output",
		"QSslKey.toPem#1":                                   "output",
		"QSslKey.toDer#0":                                   "output",
		"QSslKey.toDer#1":                                   "output",
		"QSslCertificate.toPem#0":                           "output",
		"QSslCertificate.toDer#0":                           "output",
	}
	negative := map[string]bool{}
	for _, key := range []string{"QCryptographicHash.reset#0", "QCryptographicHash.hashLength#1", "QSslSocket.peerCertificate#0"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one qtbase contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "qtbase" {
					t.Fatalf("contract for %q = role %q library %q, want qtbase %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}

// The one-shot calls carry their algorithm, and the PBKDF calls their
// iteration count and derived-key length, as arguments.
func TestQtBaseContractsAttributeArguments(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	type param struct {
		index          int
		role, property string
	}
	pbkdf := []param{
		{0, "operation-determining", "algorithm"},
		{3, "metadata-contributing", "iterations"},
		{4, "metadata-contributing", "outputLength"},
	}
	cases := []struct {
		method string
		arity  int
		want   []param
	}{
		{"QCryptographicHash.hash", 2, []param{{1, "operation-determining", "algorithm"}}},
		{"QMessageAuthenticationCode.hash", 3, []param{{2, "operation-determining", "algorithm"}}},
		{"QPasswordDigestor.deriveKeyPbkdf1", 5, pbkdf},
		{"QPasswordDigestor.deriveKeyPbkdf2", 5, pbkdf},
	}

	for _, tc := range cases {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		if len(got[0].Parameters) != len(tc.want) {
			t.Fatalf("%s: %d parameter entries, want %d", tc.method, len(got[0].Parameters), len(tc.want))
		}
		for i, want := range tc.want {
			p := got[0].Parameters[i]
			if p.Index == nil || *p.Index != want.index || p.Role != want.role ||
				p.Contributes == nil || p.Contributes.Property != want.property {
				t.Errorf("%s: parameters[%d] = %+v, want index %d role %s property %s", tc.method, i, p, want.index, want.role, want.property)
			}
		}
	}
}
