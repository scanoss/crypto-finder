// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// schannel's whole API is fluent builders, so this test's job is to hold the
// line on which links of a chain resolve. Every identity below is one the
// parser really emits -- transcribed from a run, not from what a reader of the
// crate's docs would expect -- and each must join to exactly one contract.
//
// The keys are the call-site spelling, which joins module segments with "." and
// which ContractsFor bridges to the authored "::" form.
//
// HOW THIS SET WAS ARRIVED AT, because the numbers are the argument for the
// entries the KB carries. Measured on the source below, at three points:
//
//	before the contract existed         5 of 12 call sites resolved
//	with the role: config links         9 of 12
//	with canonical_return_type added   12 of 12
//
// The hops that were lost came out as `<scanned crate>.connect`,
// `<scanned crate>.acquire`, `<scanned crate>.supported_algorithms` and
// `<scanned crate>.import` -- the consumer's own package named as the owner of a
// third-party call, which is a wrong identity and not merely a missing one.
func TestSchannelContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use schannel::cert_context::{CertContext, HashAlgorithm};
use schannel::crypt_prov::{AcquireOptions, ProviderType};
use schannel::schannel_cred::{Algorithm, Direction, Protocol, SchannelCred};
use schannel::tls_stream;
use std::net::TcpStream;

fn client(socket: TcpStream) {
    let cred = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .supported_algorithms(&[Algorithm::Aes256])
        .acquire(Direction::Outbound)
        .unwrap();
    let _stream = tls_stream::Builder::new()
        .domain("example.com")
        .connect(cred, socket)
        .unwrap();
}

fn bound_builder() {
    let mut b = SchannelCred::builder();
    b.enabled_protocols(&[Protocol::Tls12]);
    b.supported_algorithms(&[Algorithm::Aes256]);
    let _c = b.acquire(Direction::Outbound);
}

fn server(socket: TcpStream, cred: SchannelCred) {
    let _stream = tls_stream::Builder::new().accept(cred, socket).unwrap();
}

fn keys(der: &[u8], pkcs8: &[u8], pem: &[u8]) {
    let mut prov = AcquireOptions::new()
        .container("scanoss")
        .acquire(ProviderType::rsa_full())
        .unwrap();
    let _k = prov.import().import(der).unwrap();
    let _k8 = prov.import().import_pkcs8(pkcs8).unwrap();
    let _kp = prov.import().import_pkcs8_pem(pem).unwrap();
}

fn certs(der: &[u8], pem: &str) {
    let cert = CertContext::new(der).unwrap();
    let _other = CertContext::from_pem(pem).unwrap();
    let _fp = cert.fingerprint(HashAlgorithm::sha256()).unwrap();
    let _pk = cert.private_key();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// THE FULL BUILDER, not the parser alone. rust_fluent_chain_qualifier_test.go
	// records why: "the parser resolved the case above correctly and a
	// post-build pass undid it, so a parser-only helper asserts nothing about
	// this defect." Two passes run after parsing
	// (resolveFluentChainsByReturnType, resolveFluentChainCalleesByContract),
	// and a parser-only test cannot see either.
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string]string{
		// TLS credential. Note the receiver: see the SchannelCred note in the KB.
		"schannel::schannel_cred.SchannelCred.builder":              "factory",
		"schannel::schannel_cred.SchannelCred.enabled_protocols":    "config",
		"schannel::schannel_cred.SchannelCred.supported_algorithms": "config",
		"schannel::schannel_cred.SchannelCred.acquire":              "operation",
		// TLS handshake.
		"schannel::tls_stream.Builder.new":     "factory",
		"schannel::tls_stream.Builder.domain":  "config",
		"schannel::tls_stream.Builder.connect": "operation",
		"schannel::tls_stream.Builder.accept":  "operation",
		// Key containers and private keys.
		"schannel::crypt_prov.AcquireOptions.new":             "factory",
		"schannel::crypt_prov.AcquireOptions.container":       "config",
		"schannel::crypt_prov.AcquireOptions.acquire":         "operation",
		"schannel::crypt_prov.ProviderType.rsa_full":          "config",
		"schannel::crypt_prov.CryptProv.import":               "factory",
		"schannel::crypt_prov.ImportOptions.import":           "operation",
		"schannel::crypt_prov.ImportOptions.import_pkcs8":     "operation",
		"schannel::crypt_prov.ImportOptions.import_pkcs8_pem": "operation",
		// Certificates.
		"schannel::cert_context.CertContext.new":         "factory",
		"schannel::cert_context.CertContext.from_pem":    "factory",
		"schannel::cert_context.CertContext.fingerprint": "operation",
		"schannel::cert_context.CertContext.private_key": "factory",
		"schannel::cert_context.HashAlgorithm.sha256":    "config",
	}

	seen := map[string]bool{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			callee := call.Callee
			method, arity := splitMethodArity(&callee)
			role, ok := want[method]
			if !ok {
				continue
			}
			seen[method] = true
			got := kb.ContractsFor(method, arity)
			if len(got) != 1 {
				t.Errorf("%s#%d: ContractsFor returned %d contracts, want exactly 1",
					method, arity, len(got))
				continue
			}
			if got[0].SourceLibrary != "schannel" {
				t.Errorf("%s: SourceLibrary=%q, want schannel", method, got[0].SourceLibrary)
			}
			if got[0].Role != role {
				t.Errorf("%s: role=%q, want %q", method, got[0].Role, role)
			}
		}
	}
	for method := range want {
		if !seen[method] {
			t.Errorf("the builder never produced %q; either the source above stopped "+
				"exercising it or the resolver's identity for it changed", method)
		}
	}

	// THE OTHER DIRECTION, and the reason it is here: a review deleted an
	// entry, flipped a role, changed an arity 2 -> 7 and appended a contract
	// for a module that does not exist -- all four at once -- and the whole
	// suite stayed green, because the table above only guards the entries it
	// names. Every schannel key in the KB must now be accounted for.
	//
	// An entry that the source does not exercise is fine and is listed in
	// unexercised below; an entry that is in NEITHER list fails, so adding a
	// contract without deciding which it is cannot pass unnoticed.
	unexercised := map[string]bool{
		// Reachable API this source does not call. Each is declared because a
		// consumer's chain may travel through it.
		"schannel::schannel_cred.Builder.new":                            true,
		"schannel::schannel_cred.Builder.supported_algorithms":           true,
		"schannel::schannel_cred.Builder.enabled_protocols":              true,
		"schannel::schannel_cred.Builder.cert":                           true,
		"schannel::schannel_cred.Builder.acquire":                        true,
		"schannel::schannel_cred.SchannelCred.cert":                      true,
		"schannel::tls_stream.Builder.use_sni":                           true,
		"schannel::tls_stream.Builder.accept_invalid_hostnames":          true,
		"schannel::tls_stream.Builder.cert_store":                        true,
		"schannel::tls_stream.Builder.request_application_protocols":     true,
		"schannel::tls_stream.TlsStream.peer_certificate":                true,
		"schannel::tls_stream.TlsStream.negotiated_application_protocol": true,
		"schannel::cert_context.CertContext.to_der":                      true,
		"schannel::cert_context.CertContext.to_pem":                      true,
		"schannel::cert_context.HashAlgorithm.md5":                       true,
		"schannel::cert_context.HashAlgorithm.sha1":                      true,
		"schannel::cert_context.HashAlgorithm.sha384":                    true,
		"schannel::cert_context.HashAlgorithm.sha512":                    true,
		"schannel::cert_context.AcquirePrivateKeyOptions.compare_key":    true,
		"schannel::cert_context.AcquirePrivateKeyOptions.silent":         true,
		"schannel::cert_context.AcquirePrivateKeyOptions.acquire":        true,
		"schannel::crypt_prov.AcquireOptions.provider":                   true,
		"schannel::crypt_prov.AcquireOptions.new_keyset":                 true,
		"schannel::crypt_prov.AcquireOptions.machine_keyset":             true,
		"schannel::crypt_prov.AcquireOptions.verify_context":             true,
		"schannel::crypt_prov.AcquireOptions.silent":                     true,
		"schannel::crypt_prov.ProviderType.rsa_aes":                      true,
		"schannel::crypt_prov.ProviderType.rsa_sig":                      true,
		"schannel::crypt_prov.ProviderType.rsa_schannel":                 true,
		"schannel::crypt_prov.ProviderType.dss":                          true,
		"schannel::crypt_prov.ProviderType.dss_dh":                       true,
		"schannel::crypt_prov.ProviderType.dh_schannel":                  true,
		"schannel::crypt_prov.ProviderType.fortezza":                     true,
		"schannel::crypt_prov.ProviderType.ms_exchange":                  true,
		"schannel::crypt_prov.ProviderType.ssl":                          true,
	}
	for key, cs := range kb.Contracts {
		for _, c := range cs {
			if c.SourceLibrary != "schannel" {
				continue
			}
			// kb.Contracts is keyed on the AUTHORED spelling
			// (`schannel::tls_stream::Builder.connect#2`); the tables use the
			// call-site spelling the resolver emits. Rewriting the LAST "::"
			// to a "." is exactly the normalisation rustAuthoredKey inverts.
			emitted := key
			if i := strings.LastIndex(key, "::"); i >= 0 {
				emitted = key[:i] + "." + key[i+2:]
			}
			if h := strings.LastIndex(emitted, "#"); h >= 0 {
				emitted = emitted[:h]
			}
			if want[emitted] == "" && !unexercised[emitted] {
				t.Errorf("KB holds schannel contract %q (emitted %q) that this test "+
					"neither exercises nor lists as unexercised. Add it to `want` with "+
					"its role if the source should call it, to `unexercised` if it is "+
					"reachable API a chain may travel through, or delete it from the "+
					"contract.", key, emitted)
			}
		}
	}
}

// NOTHING IN A REALISTIC CONSUMER MAY FALL BACK TO THE SCANNED CRATE. This is
// the assertion that would have caught the state this KB started in, where 7 of
// 12 call sites came out owned by the consumer's own package.
//
// It is deliberately blunt: any callee whose identity begins with the scanned
// package name and whose method is one of schannel's is a wrong attribution,
// however it arose. `unwrap` is excluded because it is std, not schannel's.
func TestSchannelNoCallSiteFallsBackToTheScannedCrate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use schannel::cert_context::{CertContext, HashAlgorithm};
use schannel::crypt_prov::{AcquireOptions, ProviderType};
use schannel::schannel_cred::{Algorithm, Direction, Protocol, SchannelCred};
use schannel::tls_stream;
use std::net::TcpStream;

fn client(socket: TcpStream) {
    let cred = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .supported_algorithms(&[Algorithm::Aes256])
        .acquire(Direction::Outbound)
        .unwrap();
    let _stream = tls_stream::Builder::new()
        .domain("example.com")
        .connect(cred, socket)
        .unwrap();
}

fn keys(der: &[u8]) {
    let mut prov = AcquireOptions::new()
        .container("scanoss")
        .acquire(ProviderType::rsa_full())
        .unwrap();
    let _k = prov.import().import(der).unwrap();
}

fn certs(der: &[u8]) {
    let cert = CertContext::new(der).unwrap();
    let _fp = cert.fingerprint(HashAlgorithm::sha256()).unwrap();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	schannelMethods := map[string]bool{
		"connect": true, "accept": true, "acquire": true, "import": true,
		"import_pkcs8": true, "import_pkcs8_pem": true, "domain": true,
		"container": true, "enabled_protocols": true, "supported_algorithms": true,
		"fingerprint": true, "from_pem": true, "private_key": true,
		"builder": true, "rsa_full": true, "sha256": true,
	}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				if len(method) < 4 || method[:4] != "app." {
					continue
				}
				bare := method[4:]
				if schannelMethods[bare] {
					t.Errorf("call site %q fell back to the scanned crate: a schannel "+
						"method attributed to the consumer's own package is a WRONG "+
						"identity, not a missing one, and it matches no contract. "+
						"Check the return type declared for the link before it in the "+
						"chain.", method)
				}
			}
		}
	}
}

// ARITY IS DOCUMENTATION FOR RUST, AND IS PINNED ANYWAY. Rust callees carry no
// encoded arity, so every lookup arrives with -1 and ContractsFor resolves by
// name through lowestArityByName. A wrong arity therefore changes no match --
// a review mutated `Builder.connect` from 2 to 7 and every other test stayed
// green. It is still a false statement in a file whose comments exist to record
// what the crate declares, so the declared arity of every entry is asserted
// here against the real signatures.
func TestSchannelDeclaredAritiesMatchTheCrate(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// authored method -> arity, from the declarations in schannel 0.1.29's
	// src/{schannel_cred,tls_stream,cert_context,crypt_prov}.rs. Receiver
	// excluded, matching every other Rust KB here.
	wantArity := map[string]int{
		"schannel::schannel_cred::SchannelCred.builder":                   0,
		"schannel::schannel_cred::SchannelCred.enabled_protocols":         1,
		"schannel::schannel_cred::SchannelCred.supported_algorithms":      1,
		"schannel::schannel_cred::SchannelCred.cert":                      1,
		"schannel::schannel_cred::SchannelCred.acquire":                   1,
		"schannel::schannel_cred::Builder.new":                            0,
		"schannel::schannel_cred::Builder.supported_algorithms":           1,
		"schannel::schannel_cred::Builder.enabled_protocols":              1,
		"schannel::schannel_cred::Builder.cert":                           1,
		"schannel::schannel_cred::Builder.acquire":                        1,
		"schannel::tls_stream::Builder.new":                               0,
		"schannel::tls_stream::Builder.domain":                            1,
		"schannel::tls_stream::Builder.use_sni":                           1,
		"schannel::tls_stream::Builder.accept_invalid_hostnames":          1,
		"schannel::tls_stream::Builder.cert_store":                        1,
		"schannel::tls_stream::Builder.request_application_protocols":     1,
		"schannel::tls_stream::Builder.connect":                           2,
		"schannel::tls_stream::Builder.accept":                            2,
		"schannel::tls_stream::TlsStream.peer_certificate":                0,
		"schannel::tls_stream::TlsStream.negotiated_application_protocol": 0,
		"schannel::cert_context::CertContext.new":                         1,
		"schannel::cert_context::CertContext.from_pem":                    1,
		"schannel::cert_context::CertContext.fingerprint":                 1,
		"schannel::cert_context::CertContext.private_key":                 0,
		"schannel::cert_context::CertContext.to_der":                      0,
		"schannel::cert_context::CertContext.to_pem":                      0,
		"schannel::cert_context::HashAlgorithm.md5":                       0,
		"schannel::cert_context::HashAlgorithm.sha1":                      0,
		"schannel::cert_context::HashAlgorithm.sha256":                    0,
		"schannel::cert_context::HashAlgorithm.sha384":                    0,
		"schannel::cert_context::HashAlgorithm.sha512":                    0,
		"schannel::cert_context::AcquirePrivateKeyOptions.compare_key":    1,
		"schannel::cert_context::AcquirePrivateKeyOptions.silent":         1,
		"schannel::cert_context::AcquirePrivateKeyOptions.acquire":        0,
		"schannel::crypt_prov::AcquireOptions.new":                        0,
		"schannel::crypt_prov::AcquireOptions.container":                  1,
		"schannel::crypt_prov::AcquireOptions.provider":                   1,
		"schannel::crypt_prov::AcquireOptions.new_keyset":                 1,
		"schannel::crypt_prov::AcquireOptions.machine_keyset":             1,
		"schannel::crypt_prov::AcquireOptions.verify_context":             1,
		"schannel::crypt_prov::AcquireOptions.silent":                     1,
		"schannel::crypt_prov::AcquireOptions.acquire":                    1,
		"schannel::crypt_prov::CryptProv.import":                          0,
		"schannel::crypt_prov::ImportOptions.import":                      1,
		"schannel::crypt_prov::ImportOptions.import_pkcs8":                1,
		"schannel::crypt_prov::ImportOptions.import_pkcs8_pem":            1,
		"schannel::crypt_prov::ProviderType.rsa_full":                     0,
		"schannel::crypt_prov::ProviderType.rsa_aes":                      0,
		"schannel::crypt_prov::ProviderType.rsa_sig":                      0,
		"schannel::crypt_prov::ProviderType.rsa_schannel":                 0,
		"schannel::crypt_prov::ProviderType.dss":                          0,
		"schannel::crypt_prov::ProviderType.dss_dh":                       0,
		"schannel::crypt_prov::ProviderType.dh_schannel":                  0,
		"schannel::crypt_prov::ProviderType.fortezza":                     0,
		"schannel::crypt_prov::ProviderType.ms_exchange":                  0,
		"schannel::crypt_prov::ProviderType.ssl":                          0,
	}

	found := map[string]bool{}
	for key, cs := range kb.Contracts {
		for _, c := range cs {
			if c.SourceLibrary != "schannel" {
				continue
			}
			h := strings.LastIndex(key, "#")
			if h < 0 {
				t.Errorf("contract key %q carries no arity suffix", key)
				continue
			}
			method := key[:h]
			gotArity, err := strconv.Atoi(key[h+1:])
			if err != nil {
				t.Errorf("contract key %q has a non-numeric arity", key)
				continue
			}
			exp, ok := wantArity[method]
			if !ok {
				t.Errorf("KB declares %q, which this test does not name; add it with "+
					"the arity the crate's declaration shows", method)
				continue
			}
			found[method] = true
			if gotArity != exp {
				t.Errorf("%s: declared arity %d, but the crate declares %d",
					method, gotArity, exp)
			}
		}
	}
	for method := range wantArity {
		if !found[method] {
			t.Errorf("this test names %q but the KB does not declare it", method)
		}
	}
}
