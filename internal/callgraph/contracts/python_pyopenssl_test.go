package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const pyopensslLibrary = "pyopenssl"

// renderPyopensslContract renders every field the loader parses, so a
// mutation to any of them changes the line.
func renderPyopensslContract(key string, c contracts.Contract) string {
	paramRoles := "-"
	if len(c.Parameters) > 0 {
		rendered := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprintf("%d", *p.Index)
			}
			property, derivation := "-", "-"
			if p.Contributes != nil {
				property = p.Contributes.Property
				derivation = p.Contributes.Derivation
			}
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s", idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/types=%s/canonical=%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		strings.Join(c.ParameterTypes, "|"), c.CanonicalReturnType, paramRoles, c.Varargs, when, c.SourceLibrary)
}

// po renders one expected line. It only formats; every value passed to it
// below is written by hand from the pyOpenSSL sources.
func po(method string, arity int, role, ret, paramRoles string) string {
	return fmt.Sprintf("%s#%d %s/%s/%s/high/types=/canonical=/params=%s/varargs=false/when=-/lib=pyopenssl",
		method, arity, method, role, ret, paramRoles)
}

// poCtor is a constructor under both spellings: the attribute path
// (`SSL.Context(..)`, `OpenSSL.SSL.Context(..)`) and `.<init>`
// (`from OpenSSL.SSL import Context; Context(..)`).
func poCtor(class string, arity int, paramRoles string) []string {
	return []string{
		po(class, arity, "factory", class, paramRoles),
		po(class+".<init>", arity, "factory", class, paramRoles),
	}
}

const (
	poNone  = "builtins.NoneType"
	poBytes = "builtins.bytes"
	poPKey  = "OpenSSL.crypto.PKey"
	poX509  = "OpenSSL.crypto.X509"
	poReq   = "OpenSSL.crypto.X509Req"
	poStore = "OpenSSL.crypto.X509Store"
	poCtx   = "OpenSSL.SSL.Context"
	poConn  = "OpenSSL.SSL.Connection"
	poP12   = "OpenSSL.crypto.PKCS12"
)

// wantPyopensslContracts is written BY HAND from the pyOpenSSL 24.3.0 and
// 26.3.0 sources (23.2.0 for the removed crypto.py surface). It is never
// derived from the YAML: a derived expectation is green on a corrupted one.
func wantPyopensslContracts() []string {
	var want []string
	add := func(lines ...string) { want = append(want, lines...) }

	// Key and certificate operations (OpenSSL.crypto).
	// crypto.py:237 PKey(); :274 from_cryptography_key; :335
	// generate_key(type, bits); :395 check; :250 to_cryptography_key returns
	// one of ten key classes.
	add(poCtor(poPKey, 0, "-")...)
	add(po(poPKey+".from_cryptography_key", 1, "factory", poPKey, "-"))
	add(po(poPKey+".generate_key", 2, "operation", poNone,
		"0:type:operation-determining:-:-,1:bits:metadata-contributing:keySize:argument_value"))
	add(po(poPKey+".check", 0, "operation", "builtins.bool", "-"))
	add(po(poPKey+".to_cryptography_key", 0, "output", "builtins.object", "-"))

	// crypto.py:781 X509(); :816 from_cryptography; :863 get_pubkey; :882
	// set_pubkey; :901 sign(pkey, digest); :948 digest(digest_name); :929
	// get_signature_algorithm; :802 to_cryptography.
	add(poCtor(poX509, 0, "-")...)
	add(po(poX509+".from_cryptography", 1, "factory", poX509, "-"))
	add(po(poX509+".get_pubkey", 0, "factory", poPKey, "-"))
	add(po(poX509+".set_pubkey", 1, "config", poNone, "-"))
	add(po(poX509+".sign", 2, "operation", poNone, "1:digest:operation-determining:-:-"))
	add(po(poX509+".digest", 1, "operation", poBytes, "0:digest_name:operation-determining:-:-"))
	add(po(poX509+".get_signature_algorithm", 0, "output", poBytes, "-"))
	add(po(poX509+".to_cryptography", 0, "output", "cryptography.x509.Certificate", "-"))

	// X509Req and its load/dump pair (24.3.0; removed by 26.3.0).
	add(poCtor(poReq, 0, "-")...)
	add(po(poReq+".get_pubkey", 0, "factory", poPKey, "-"))
	add(po(poReq+".set_pubkey", 1, "config", poNone, "-"))
	add(po(poReq+".sign", 2, "operation", poNone, "1:digest:operation-determining:-:-"))
	add(po(poReq+".verify", 1, "operation", "builtins.bool", "-"))
	add(po("OpenSSL.crypto.load_certificate_request", 2, "factory", poReq, "-"))
	add(po("OpenSSL.crypto.dump_certificate_request", 2, "output", poBytes, "-"))

	// crypto.py:1286 X509Store; :1473 X509StoreContext(store, certificate).
	add(poCtor(poStore, 0, "-")...)
	for _, m := range []string{"add_cert", "add_crl", "set_flags", "set_time", "load_locations"} {
		add(po(poStore+"."+m, 1, "config", poNone, "-"))
	}
	add(poCtor("OpenSSL.crypto.X509StoreContext", 2, "-")...)
	add(po("OpenSSL.crypto.X509StoreContext.set_store", 1, "config", poNone, "-"))
	add(po("OpenSSL.crypto.X509StoreContext.verify_certificate", 0, "operation", poNone, "-"))
	add(po("OpenSSL.crypto.X509StoreContext.get_verified_chain", 0, "output", "builtins.list", "-"))

	// crypto.py:1631 onward: load_*(type, buffer) and dump_*(type, obj).
	add(po("OpenSSL.crypto.load_certificate", 2, "factory", poX509, "-"))
	add(po("OpenSSL.crypto.load_privatekey", 2, "factory", poPKey, "-"))
	add(po("OpenSSL.crypto.load_publickey", 2, "factory", poPKey, "-"))
	add(po("OpenSSL.crypto.dump_certificate", 2, "output", poBytes, "-"))
	add(po("OpenSSL.crypto.dump_privatekey", 2, "output", poBytes, "-"))
	add(po("OpenSSL.crypto.dump_publickey", 2, "output", poBytes, "-"))

	// 23.2.0 crypto.py:3102 sign(pkey, data, digest); :3137 verify(cert,
	// signature, data, digest).
	add(po("OpenSSL.crypto.sign", 3, "operation", poBytes, "2:digest:operation-determining:-:-"))
	add(po("OpenSSL.crypto.verify", 4, "operation", poNone, "3:digest:operation-determining:-:-"))

	// 23.2.0 crypto.py:2616 PKCS12, :3275 load_pkcs12(buffer, passphrase).
	add(poCtor(poP12, 0, "-")...)
	add(po("OpenSSL.crypto.load_pkcs12", 1, "factory", poP12, "-"))
	add(po(poP12+".get_certificate", 0, "factory", poX509, "-"))
	add(po(poP12+".get_privatekey", 0, "factory", poPKey, "-"))
	add(po(poP12+".set_certificate", 1, "config", poNone, "-"))
	add(po(poP12+".set_privatekey", 1, "config", poNone, "-"))
	add(po(poP12+".export", 0, "output", poBytes, "-"))

	// TLS context and connection configuration (OpenSSL.SSL).
	// SSL.py:904 Context(method).
	add(poCtor(poCtx, 1, "0:method:operation-determining:-:-")...)
	add(po(poCtx+".set_min_proto_version", 1, "config", poNone, "0:version:operation-determining:-:-"))
	add(po(poCtx+".set_max_proto_version", 1, "config", poNone, "0:version:operation-determining:-:-"))
	add(po(poCtx+".set_options", 1, "config", "builtins.int", "0:options:operation-determining:-:-"))
	add(po(poCtx+".set_cipher_list", 1, "config", poNone, "0:cipher_list:operation-determining:-:-"))
	add(po(poCtx+".set_tls13_ciphersuites", 1, "config", poNone, "0:ciphersuites:operation-determining:-:-"))
	add(po(poCtx+".set_tmp_ecdh", 1, "config", poNone, "0:curve:operation-determining:-:-"))
	add(po(poCtx+".load_tmp_dh", 1, "config", poNone, "-"))
	add(po(poCtx+".set_verify", 1, "config", poNone, "0:mode:operation-determining:-:-"))
	add(po(poCtx+".set_verify_depth", 1, "config", poNone, "-"))
	add(po(poCtx+".load_verify_locations", 1, "config", poNone, "-"))
	add(po(poCtx+".set_default_verify_paths", 0, "config", poNone, "-"))
	presented := []string{
		"use_certificate_chain_file", "use_certificate_file", "use_certificate",
		"add_extra_chain_cert", "use_privatekey_file", "use_privatekey",
	}
	for _, m := range presented {
		add(po(poCtx+"."+m, 1, "config", poNone, "-"))
	}
	add(po(poCtx+".check_privatekey", 0, "operation", poNone, "-"))
	add(po(poCtx+".get_cert_store", 0, "output", poStore, "-"))

	// SSL.py:1975 Connection(context, socket=None).
	add(poCtor(poConn, 1, "-")...)
	add(po(poConn+".do_handshake", 0, "operation", poNone, "-"))
	add(po(poConn+".renegotiate", 0, "operation", "builtins.bool", "-"))
	add(po(poConn+".export_keying_material", 2, "operation", poBytes,
		"1:olen:metadata-contributing:outputLength:argument_value"))
	add(po(poConn+".get_peer_certificate", 0, "output", poX509, "-"))
	add(po(poConn+".get_certificate", 0, "output", poX509, "-"))
	add(po(poConn+".get_peer_cert_chain", 0, "output", "builtins.list", "-"))
	add(po(poConn+".get_verified_chain", 0, "output", "builtins.list", "-"))
	add(po(poConn+".get_cipher_name", 0, "output", "builtins.str", "-"))
	add(po(poConn+".get_cipher_bits", 0, "output", "builtins.int", "-"))
	add(po(poConn+".get_cipher_version", 0, "output", "builtins.str", "-"))
	add(po(poConn+".get_protocol_version_name", 0, "output", "builtins.str", "-"))
	add(po(poConn+".get_group_name", 0, "output", "builtins.str", "-"))
	add(po(poConn+".master_key", 0, "output", poBytes, "-"))
	add(po(poConn+".get_finished", 0, "output", poBytes, "-"))
	add(po(poConn+".get_peer_finished", 0, "output", poBytes, "-"))

	return want
}

func TestPythonPyopensslContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	gotSet := map[string]struct{}{}
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == pyopensslLibrary {
				gotSet[renderPyopensslContract(key, list[i])] = struct{}{}
			}
		}
	}
	if len(gotSet) == 0 {
		t.Fatal("no pyopenssl contracts loaded from the embedded python KB")
	}

	want := wantPyopensslContracts()
	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		if _, dup := wantSet[line]; dup {
			t.Errorf("expectation lists a line twice: %q", line)
		}
		wantSet[line] = struct{}{}
		if _, ok := gotSet[line]; !ok {
			t.Errorf("contract entry declared in the expectation but NOT loaded from the YAML:\n\t%q", line)
		}
	}
	got := make([]string, 0, len(gotSet))
	for line := range gotSet {
		got = append(got, line)
	}
	sort.Strings(got)
	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			t.Errorf("unexpected contract entry; if the YAML change is intended, add it to wantPyopensslContracts():\n\t%q", line)
		}
	}
}

func TestPythonPyopensslContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "pyopenssl.yaml"))
	if err != nil {
		t.Fatalf("read pyopenssl.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pyopenssl.yaml): %v", err)
	}
	if kb.Library == nil || kb.Library.Name != pyopensslLibrary {
		t.Fatalf("library block = %+v, want name pyopenssl", kb.Library)
	}
	if got := strings.Join(kb.Library.Coordinates, ","); got != "pyOpenSSL" {
		t.Errorf("library.coordinates = %q, want pyOpenSSL", got)
	}
	// 0.15 through 26.x were read. The range must reach below 24.0: the file
	// carries crypto.sign, crypto.verify, PKCS12 and load_pkcs12, which no
	// release from 24.x on defines.
	if got, want := kb.Library.VersionRange, ">=0.15,<27.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
}

// TestPythonPyopensslContract_UncontractedAPIsAreAbsent pins the surface this
// family deliberately does not contract, each with its reason.
func TestPythonPyopensslContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if got := kb.ContractsForTolerant("OpenSSL.SSL.Context.set_cipher_list", 1); len(got) == 0 {
		t.Fatal("positive control failed: OpenSSL.SSL.Context.set_cipher_list does not resolve, " +
			"so the negative assertions below prove nothing")
	}
	for _, absent := range []struct{ key, reason string }{
		{"OpenSSL.SSL.Connection.send", "application data over an established session"},
		{"OpenSSL.SSL.Connection.recv", "application data over an established session"},
		{"OpenSSL.SSL.Connection.set_tlsext_host_name", "SNI name selection, not cryptography"},
		{"OpenSSL.SSL.Context.set_session_id", "session cache bookkeeping"},
		{"OpenSSL.SSL.Context.set_alpn_protos", "application protocol negotiation"},
		{"OpenSSL.SSL.Context.set_keylog_callback", "consumer-supplied callback the library invokes"},
		{"OpenSSL.crypto.X509.set_serial_number", "certificate metadata, no cryptography"},
		{"OpenSSL.crypto.X509.has_expired", "a time comparison"},
		{"OpenSSL.crypto.PKey.bits", "declared int return is already informative"},
		{"OpenSSL.crypto.get_elliptic_curve", "needs-follow-up: returns a private _EllipticCurve type"},
	} {
		for _, arity := range []int{0, 1, 2} {
			for _, c := range kb.ContractsForTolerant(absent.key, arity) {
				if c.SourceLibrary == pyopensslLibrary {
					t.Errorf("%s resolves to a pyopenssl contract, but it is deliberately not contracted: %s",
						absent.key, absent.reason)
				}
			}
		}
	}
}
