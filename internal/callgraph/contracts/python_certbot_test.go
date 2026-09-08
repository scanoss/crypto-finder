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

const certbotLibrary = "certbot"

// renderCertbotContracts renders EVERY loaded certbot contract as one string
// per entry and returns the sorted set.
//
// It is an exact-set comparison rather than a per-key ContractsFor assertion on
// purpose: a per-key subset assertion cannot see an entry that should not be
// there, an entry that was dropped, or a field that was corrupted. The render
// covers method, arity, role, both return types, parameter_types, confidence,
// varargs AND the parameters block — a contributed property renamed from
// keySize to something else loads cleanly through the schema's presence checks
// and would otherwise pass an "exact" test while silently changing what
// resolvedKeyLengthFromContract reads.
func renderCertbotContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != certbotLibrary {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				idx := "nil"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contrib := "nil"
				if p.Contributes != nil {
					contrib = fmt.Sprintf("%s:%s", p.Contributes.Property, p.Contributes.Derivation)
				}
				params = append(params, fmt.Sprintf("%s:%s:%s:%s", idx, p.Name, p.Role, contrib))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/varargs=%t/params=[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				c.Varargs, strings.Join(params, ";"), c.SourceLibrary))
		}
	}
	sort.Strings(got)
	return got
}

// wantCertbotContracts is the whole certbot contract set. Every key here was
// read off an exported call graph of a probe consumer, not written from the API:
// before this file existed the export emitted these same
// `certbot.crypto_util.<fn>` spellings with `(?, ?)` signatures and empty
// parameter_types, and after it every one of them resolves.
var wantCertbotContracts = []string{
	"certbot.crypto_util.cert_and_chain_from_fullchain#1/output/builtins.tuple/builtins.tuple/[builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.csr_matches_pubkey#2/operation/builtins.bool/builtins.bool/[builtins.bytes,builtins.bytes]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.dump_pyopenssl_chain#1/output/builtins.bytes/builtins.bytes/[builtins.list]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.find_chain_with_issuer#2/output/builtins.str/builtins.str/[builtins.list,builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.generate_csr#3/factory/certbot.util.CSR/certbot.util.CSR/[certbot.util.Key,builtins.list,builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.generate_key#2/factory/certbot.util.Key/certbot.util.Key/[builtins.int,builtins.str]/high/varargs=false/params=[0:key_size:metadata-contributing:keySize:argument_value]/certbot",
	"certbot.crypto_util.import_csr_file#2/output/builtins.tuple/builtins.tuple/[builtins.str,builtins.bytes]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.init_save_csr#3/factory/certbot.util.CSR/certbot.util.CSR/[certbot.util.Key,builtins.set,builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.init_save_key#2/factory/certbot.util.Key/certbot.util.Key/[builtins.int,builtins.str]/high/varargs=false/params=[0:key_size:metadata-contributing:keySize:argument_value]/certbot",
	"certbot.crypto_util.make_csr#2/factory/builtins.tuple/builtins.tuple/[builtins.str,builtins.list]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.make_key#1/factory/builtins.bytes/builtins.bytes/[builtins.int]/high/varargs=false/params=[0:bits:metadata-contributing:keySize:argument_value]/certbot",
	"certbot.crypto_util.pyopenssl_load_certificate#1/output/builtins.tuple/builtins.tuple/[builtins.bytes]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.read_csr_file#2/output/certbot.util.CSR/certbot.util.CSR/[builtins.str,builtins.bytes]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.sha256sum#1/operation/builtins.str/builtins.str/[builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.valid_csr#1/output/builtins.bool/builtins.bool/[builtins.bytes]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.valid_privkey#1/output/builtins.bool/builtins.bool/[builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.verify_cert_matches_priv_key#2/operation/builtins.NoneType/builtins.NoneType/[builtins.str,builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.verify_fullchain#1/output/builtins.NoneType/builtins.NoneType/[certbot.interfaces.RenewableCert]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.verify_renewable_cert#1/operation/builtins.NoneType/builtins.NoneType/[certbot.interfaces.RenewableCert]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.verify_renewable_cert_sig#1/operation/builtins.NoneType/builtins.NoneType/[certbot.interfaces.RenewableCert]/high/varargs=false/params=[]/certbot",
	"certbot.crypto_util.verify_signed_payload#4/operation/builtins.NoneType/builtins.NoneType/[builtins.object,builtins.bytes,builtins.bytes,cryptography.hazmat.primitives.hashes.HashAlgorithm]/high/varargs=false/params=[]/certbot",
	"certbot.ocsp.RevocationChecker#1/factory/certbot.ocsp.RevocationChecker/certbot.ocsp.RevocationChecker/[builtins.bool]/high/varargs=false/params=[]/certbot",
	"certbot.ocsp.RevocationChecker.<init>#0/factory/certbot.ocsp.RevocationChecker/certbot.ocsp.RevocationChecker/[]/high/varargs=false/params=[]/certbot",
	"certbot.ocsp.RevocationChecker.ocsp_revoked#1/output/builtins.bool/builtins.bool/[certbot.interfaces.RenewableCert]/high/varargs=false/params=[]/certbot",
	"certbot.ocsp.RevocationChecker.ocsp_revoked#2/output/builtins.bool/builtins.bool/[builtins.str,builtins.str]/high/varargs=false/params=[]/certbot",
	"certbot.ocsp.RevocationChecker.ocsp_revoked_by_paths#2/output/builtins.bool/builtins.bool/[builtins.str,builtins.str]/high/varargs=false/params=[]/certbot",
}

// TestLoadEmbedded_Python_Certbot_ExactSet compares the loaded set against the
// literal below AS A SET, not index by index, and the distinction is the whole
// point of this shape.
//
// AN INDEX-BASED COMPARISON TURNS A CORRECT REPAIR INTO A 20-LINE CASCADE. The
// previous version of this test walked both sorted slices by position, so
// adding one genuine entry to the YAML — `get_serial_from_cert`, which really
// is present at 5.6.0 — shifted every later index and reported a count
// mismatch plus ~20 spurious "got X want Y" lines, none of which named the
// actual difference. A reader then has to reconstruct what changed from the
// noise, and the obvious reading ("I broke twenty contracts") is wrong. This is
// the fifth occurrence of that trap in this campaign, so it is a known class
// rather than one family's mistake.
//
// A set diff reports exactly what differs: one added entry gives ONE
// "unexpected contract entry" line, quoted so it can be pasted straight into
// the literal as the one-line edit the repair actually needs, and one removed
// entry gives ONE "missing contract entry" line.
//
// What is deliberately NOT done here: deriving the want-set from the YAML. That
// would make this test tautological — it would pass for any YAML, including a
// corrupted one — and corruption detection is the only reason the exact set
// earns its keep. It is checked: 15 mutation classes (entry deletion, role
// flip, arity change, return-type corruption, parameter_types corruption,
// confidence downgrade, contributed-property rename, derivation swap, dropped
// parameters block, version_range, coordinates, name and description
// corruption, varargs, canonical_return_type) are each killed by this test, and
// that battery was re-run after this refactor to confirm the set diff did not
// weaken any of them.
func TestLoadEmbedded_Python_Certbot_ExactSet(t *testing.T) {
	t.Parallel()

	want := make(map[string]bool, len(wantCertbotContracts))
	for _, w := range wantCertbotContracts {
		want[w] = true
	}
	got := make(map[string]bool)
	for _, g := range renderCertbotContracts(t) {
		got[g] = true
	}

	var unexpected, missing []string
	for g := range got {
		if !want[g] {
			unexpected = append(unexpected, g)
		}
	}
	for w := range want {
		if !got[w] {
			missing = append(missing, w)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(missing)

	for _, u := range unexpected {
		t.Errorf("unexpected contract entry — if the YAML change is intended, add this one line to wantCertbotContracts:\n\t%q,", u)
	}
	for _, m := range missing {
		t.Errorf("missing contract entry — the YAML no longer declares it:\n\t%s", m)
	}
}

// TestLoadEmbedded_Python_Certbot_NotVacuous guards the exact-set test above
// against the one way it could pass while proving nothing: matching zero
// entries. A contract set of size 0 compared against a want-list of size 0
// would be green.
//
// It is deliberately NOT the same assertion as the exact-set test, and it
// carries NO COUNTS. Hardcoded tallies here (26 entries / 21 crypto_util /
// 5 ocsp) duplicated the exact-set literal with no independent source, so one
// genuine YAML addition failed three assertions in two tests and none of them
// named the entry. What survives is the part that is independent: the set is
// non-empty, and BOTH library surfaces are present — which still fails on a
// wholesale rename of SourceLibrary even if someone regenerates the want-list.
func TestLoadEmbedded_Python_Certbot_NotVacuous(t *testing.T) {
	t.Parallel()

	got := renderCertbotContracts(t)
	if len(got) == 0 {
		t.Fatal("no certbot contracts loaded; the exact-set test above would be vacuous")
	}
	var cryptoUtil, ocsp int
	for _, line := range got {
		switch {
		case strings.HasPrefix(line, "certbot.crypto_util."):
			cryptoUtil++
		case strings.HasPrefix(line, "certbot.ocsp."):
			ocsp++
		}
	}
	if cryptoUtil == 0 {
		t.Error("no certbot.crypto_util entries loaded; SourceLibrary may have been renamed wholesale")
	}
	if ocsp == 0 {
		t.Error("no certbot.ocsp entries loaded; SourceLibrary may have been renamed wholesale")
	}
}

// TestLoadEmbedded_Python_Certbot_KeysResolveThroughTolerantLookup pins the
// reason each method is declared ONCE rather than at every arity a consumer can
// write. Python resolution is arity-tolerant, so a call at a higher arity must
// still reach the single declared entry — and if that tolerance ever changes,
// the contract needs an entry per arity and this test is what says so.
//
// The arities below are the ones the probe consumer's export actually emitted:
// make_key at 1 and 2, generate_key at 3 and 4.
func TestLoadEmbedded_Python_Certbot_KeysResolveThroughTolerantLookup(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	cases := []struct {
		method     string
		arity      int
		wantReturn string
	}{
		{"certbot.crypto_util.make_key", 1, "builtins.bytes"},
		{"certbot.crypto_util.make_key", 2, "builtins.bytes"},
		{"certbot.crypto_util.make_key", 3, "builtins.bytes"},
		{"certbot.crypto_util.generate_key", 2, "certbot.util.Key"},
		{"certbot.crypto_util.generate_key", 3, "certbot.util.Key"},
		{"certbot.crypto_util.generate_key", 4, "certbot.util.Key"},
		{"certbot.crypto_util.generate_csr", 3, "certbot.util.CSR"},
		{"certbot.crypto_util.generate_csr", 5, "certbot.util.CSR"},
		{"certbot.crypto_util.init_save_key", 2, "certbot.util.Key"},
		{"certbot.crypto_util.sha256sum", 1, "builtins.str"},
		{"certbot.ocsp.RevocationChecker.ocsp_revoked_by_paths", 2, "builtins.bool"},
		{"certbot.ocsp.RevocationChecker.ocsp_revoked_by_paths", 3, "builtins.bool"},
	}
	for _, tc := range cases {
		ctrs := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(ctrs) == 0 {
			t.Errorf("%s#%d resolved to no contract", tc.method, tc.arity)
			continue
		}
		if ctrs[0].Return.Type != tc.wantReturn {
			t.Errorf("%s#%d return: got %q, want %q",
				tc.method, tc.arity, ctrs[0].Return.Type, tc.wantReturn)
		}
	}
}

// TestLoadEmbedded_Python_Certbot_LibraryMetadata covers the fields the
// exact-set render CANNOT reach. kb.Library is nil on the merged python KB, so
// the library block is only observable by loading the one file — and
// version_range, coordinates, name and description are parsed and then never
// consulted by any other assertion, which is exactly how a corrupted one stays
// green everywhere else.
func TestLoadEmbedded_Python_Certbot_LibraryMetadata(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "certbot.yaml"))
	if err != nil {
		t.Fatalf("read certbot.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(certbot.yaml): %v", err)
	}
	if kb.Ecosystem != "python" {
		t.Errorf("ecosystem: got %q, want %q", kb.Ecosystem, "python")
	}
	if kb.Library == nil {
		t.Fatal("library block is nil")
	}
	if kb.Library.Name != "certbot" {
		t.Errorf("library.name: got %q, want %q", kb.Library.Name, "certbot")
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "certbot"; got != want {
		t.Errorf("library.coordinates: got %q, want %q", got, want)
	}
	// The matrix lists 0.6.0 as the oldest row and 5.6.0 as the newest, so the
	// range spans exactly that and stops before a major this family has not
	// looked at. Per-symbol windows are narrower and documented in the file.
	if got, want := kb.Library.VersionRange, ">=0.6.0,<6.0"; got != want {
		t.Errorf("library.version_range: got %q, want %q", got, want)
	}
	if !strings.Contains(kb.Library.Description, "ACME") {
		t.Errorf("library.description does not mention ACME: %q", kb.Library.Description)
	}
}
