// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// buildRustGraphForFilter parses one Rust file as the crate named pkg.
func buildRustGraphForFilter(t *testing.T, pkg, src string) *callgraph.CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("rust", callgraph.NewRustParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: pkg}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// reportAt builds the interim report opengrep would produce for one match of
// ruleID spanning a single line.
func reportAt(ruleID string, line, startCol, endCol int) *entities.InterimReport {
	return &entities.InterimReport{
		Version: "1.0",
		Findings: []entities.Finding{{
			FilePath: "main.rs",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: line, EndLine: line, StartCol: startCol, EndCol: endCol,
				Rules: []entities.RuleInfo{{ID: ruleID, Message: "detected", Severity: "INFO"}},
			}},
		}},
	}
}

func assetCount(report *entities.InterimReport) int {
	n := 0
	for _, f := range report.Findings {
		n += len(f.CryptographicAssets)
	}
	return n
}

// lineOf returns the 1-based line of the first source line containing needle.
func lineOf(t *testing.T, src, needle string) (int, int, int) {
	t.Helper()
	for i, l := range strings.Split(src, "\n") {
		if col := strings.Index(l, needle); col >= 0 {
			return i + 1, col + 1, col + 1 + len(needle)
		}
	}
	t.Fatalf("needle %q not in source", needle)
	return 0, 0, 0
}

const consumerSrc = `use ed25519_dalek::SigningKey;

struct ConsumerOwnType;
impl ConsumerOwnType {
    fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
}

struct Holder { inner: SigningKey }
impl Holder {
    fn go(&self, m: &[u8]) -> Vec<u8> { self.inner.sign(m).to_vec() }
}

fn mk() -> SigningKey { SigningKey::from_bytes(&[0u8; 32]) }

fn consumer_code() {
    let own = ConsumerOwnType;
    let _ = own.sign(b"x");
    let sk = mk();
    let _ = sk.sign(b"y");
}
`

const eddsaSignRule = "rust.ed25519-dalek.algorithm.signature.eddsa-sign"

// The defect this filter exists for: a consumer's OWN type with a same-named
// method, in a file that imports the crate, is claimed by the crate's rule.
func TestForeignReceiverFilter_DropsTheConsumersOwnType(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	report := reportAt(eddsaSignRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if got := assetCount(report); got != 0 {
		t.Fatalf("assets left = %d, want 0", got)
	}
}

// The cost side. Every one of these receivers reaches the crate's type, and a
// taint-mode rewrite of the rule loses the first two. None may be dropped.
func TestForeignReceiverFilter_KeepsEveryReceiverThatReachesTheCrate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		needle string
	}{
		{"struct field receiver", "self.inner.sign(m)"},
		{"function return receiver", "sk.sign(b\"y\")"},
		{"static path call", "SigningKey::from_bytes(&[0u8; 32])"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildRustGraphForFilter(t, "app", consumerSrc)
			line, sc, ec := lineOf(t, consumerSrc, tc.needle)
			report := reportAt(eddsaSignRule, line, sc, ec)

			if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
				t.Fatalf("dropped = %d, want 0", got)
			}
			if got := assetCount(report); got != 1 {
				t.Fatalf("assets left = %d, want 1", got)
			}
		})
	}
}

// Scanning the library itself must be untouched: its own methods are declared
// in the scanned source, under its own crate.
func TestForeignReceiverFilter_KeepsTheLibraryScanningItself(t *testing.T) {
	t.Parallel()
	const librarySrc = `pub struct SigningKey { bytes: [u8; 32] }

impl SigningKey {
    pub fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
    pub fn resign(&self, m: &[u8]) -> Vec<u8> { self.sign(m) }
}
`
	graph := buildRustGraphForFilter(t, "ed25519_dalek", librarySrc)
	line, sc, ec := lineOf(t, librarySrc, "self.sign(m)")
	report := reportAt(eddsaSignRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0", got)
	}
}

// Other ecosystems are out of scope and must not be touched at all.
func TestForeignReceiverFilter_IsRustOnly(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	for _, eco := range []string{"java", "python", "go", "node", "c", ""} {
		report := reportAt(eddsaSignRule, line, sc, ec)
		if got := FilterForeignReceiverAssets(report, graph, eco); got != 0 {
			t.Fatalf("ecosystem %q: dropped = %d, want 0", eco, got)
		}
	}
}

// A rule ID that names no crate cannot be second-guessed, so its asset stays
// even on the consumer's own type.
func TestForeignReceiverFilter_KeepsRulesThatNameNoCrate(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	for _, id := range []string{"generic.weak-signature", "java.bouncycastle.sign", ""} {
		report := reportAt(id, line, sc, ec)
		if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
			t.Fatalf("rule %q: dropped = %d, want 0", id, got)
		}
	}
}

// An asset claimed by both a foreign crate rule and a crate-less one keeps the
// crate-less rule instead of being dropped whole.
func TestForeignReceiverFilter_DropsOnlyTheOffendingRule(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	report := reportAt(eddsaSignRule, line, sc, ec)
	report.Findings[0].CryptographicAssets[0].Rules = append(
		report.Findings[0].CryptographicAssets[0].Rules,
		entities.RuleInfo{ID: "generic.signature-usage", Message: "generic", Severity: "INFO"},
	)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 (a crate-less rule survives)", got)
	}
	rules := report.Findings[0].CryptographicAssets[0].Rules
	if len(rules) != 1 || rules[0].ID != "generic.signature-usage" {
		t.Fatalf("rules = %#v, want only generic.signature-usage", rules)
	}
}

// The hyphen/underscore normalization between a rule ID and a module path.
func TestForeignReceiverFilter_CrateOfRuleID(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]string{
		"rust.ed25519-dalek.algorithm.signature.eddsa-sign": "ed25519_dalek",
		// The shape --rules-dir on the repository root actually produces, which
		// is how the mining service loads the ruleset.
		"semgrep-rules.rust.ed25519-dalek.algorithm.signature.rust.ed25519-dalek.algorithm.signature.eddsa-sign": "ed25519_dalek",
		"ed25519-dalek.algorithm.signature.rust.ed25519-dalek.algorithm.signature.eddsa-sign":                    "ed25519_dalek",
		// Two different crates in one ID is a shape this does not understand.
		"rust.p256.x.rust.k256.y":                "",
		"rust.p256.algorithm.signature.ecdsa":    "p256",
		"rust.tokio-rustls.protocol.tls.connect": "tokio_rustls",
		"java.bouncycastle.x":                    "",
		"rust.":                                  "",
		"":                                       "",
	} {
		if got := crateOfRuleID(id); got != want {
			t.Errorf("crateOfRuleID(%q) = %q, want %q", id, got, want)
		}
	}
}

// The unit tests above all passed while the filter dropped NOTHING in
// production, because they used the rule ID as authored in the YAML. opengrep
// prefixes it with the rule file's path relative to the config root, and the
// mining service loads the ruleset with --rules-dir on the repository root. This
// asserts the shape that actually arrives.
func TestForeignReceiverFilter_DropsWithTheRuleIDShapeProductionProduces(t *testing.T) {
	t.Parallel()
	const productionID = "semgrep-rules.rust.ed25519-dalek.algorithm.signature." +
		"rust.ed25519-dalek.algorithm.signature.eddsa-sign"

	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	report := reportAt(productionID, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if got := assetCount(report); got != 0 {
		t.Fatalf("assets left = %d, want 0", got)
	}
}

// A finding whose every asset is dropped is removed, rather than left claiming
// an empty cryptographic_assets list.
func TestForeignReceiverFilter_RemovesAFindingLeftWithNoAsset(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", consumerSrc)
	line, sc, ec := lineOf(t, consumerSrc, "own.sign(b\"x\")")
	report := reportAt(eddsaSignRule, line, sc, ec)

	FilterForeignReceiverAssets(report, graph, "rust")
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

// A chain whose ROOT is the consumer's own type but whose crypto link reaches
// the crate must survive. findCryptoCallNode returns the chain root by contract,
// so judging that one node alone dropped a true positive in tlfs-crdt 0.1.0.
func TestForeignReceiverFilter_KeepsAChainRootedOnTheConsumersOwnType(t *testing.T) {
	t.Parallel()
	const wrapperSrc = `use ed25519_dalek::{PublicKey, SecretKey, Signature};

pub struct Wrapper([u8; 32]);

impl Wrapper {
    fn to_keypair(self) -> ed25519_dalek::Keypair {
        let secret = SecretKey::from_bytes(&self.0).unwrap();
        let public = PublicKey::from(&secret);
        ed25519_dalek::Keypair { secret, public }
    }
    pub fn sign(self, msg: &[u8]) -> Signature {
        self.to_keypair().sign(msg)
    }
}
`
	graph := buildRustGraphForFilter(t, "app", wrapperSrc)
	line, sc, ec := lineOf(t, wrapperSrc, "self.to_keypair().sign(msg)")
	report := reportAt(eddsaSignRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 (the chain reaches ed25519_dalek)", got)
	}
}

// A method declared in `impl <CrateTrait> for <LocalType>` is the CRATE's API
// even though the receiver type is the consumer's. Judging the receiver type
// alone dropped five true positives in apple-codesign 0.16.0 and one in
// elliptic-curve 0.9.9 — both published on crates.io, both caught by the
// consumer sweep rather than by these tests.
func TestForeignReceiverFilter_KeepsAMethodOfTheCratesTraitOnALocalType(t *testing.T) {
	t.Parallel()
	const traitImplSrc = `use pkcs8::{EncodePrivateKey, PrivateKeyDocument};

pub struct InMemoryPrivateKey;

impl EncodePrivateKey for InMemoryPrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<PrivateKeyDocument> { unimplemented!() }
}

pub fn encode(k: &InMemoryPrivateKey) { let _ = k.to_pkcs8_der(); }
`
	graph := buildRustGraphForFilter(t, "app", traitImplSrc)
	line, sc, ec := lineOf(t, traitImplSrc, "k.to_pkcs8_der()")
	report := reportAt("rust.pkcs8.format.key.pkcs8-encode", line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 (to_pkcs8_der is pkcs8's trait method)", got)
	}
}

// The safety net for the same case when the trait is not resolvable: the method
// name carries the crate's name. Nothing generic is affected.
func TestForeignReceiverFilter_MethodNameCarriesClaimedCrate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		method string
		crate  string
		want   bool
	}{
		{"to_pkcs8_der", "pkcs8", true},
		{"from_pkcs1_pem", "pkcs1", true},
		{"to_sec1_der", "sec1", true},
		{"from_spki_der", "spki", true},
		// The generic names this filter exists for must NOT be kept by name.
		{"sign", "ed25519_dalek", false},
		{"verify", "webpki", false},
		{"authenticate_password", "russh", false},
		{"connect", "tokio_rustls", false},
		{"diffie_hellman", "p256", false},
		// A crate name of three characters or fewer would match by accident.
		{"derive_key", "der", false},
	} {
		claimed := map[string]struct{}{tc.crate: {}}
		if got := methodNameCarriesClaimedCrate(tc.method, claimed); got != tc.want {
			t.Errorf("methodNameCarriesClaimedCrate(%q, %q) = %v, want %v",
				tc.method, tc.crate, got, tc.want)
		}
	}
}

// A trait the consumer declares itself names no crate, so it is not evidence
// that the method belongs to the claimed one.
func TestForeignReceiverFilter_ALocalTraitIsNotTheCratesAPI(t *testing.T) {
	t.Parallel()
	const localTraitSrc = `use ed25519_dalek::SigningKey;

pub trait MySigner { fn sign(&self, m: &[u8]) -> Vec<u8>; }

pub struct ConsumerOwnType;
impl MySigner for ConsumerOwnType {
    fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
}

pub fn go(k: &SigningKey, c: &ConsumerOwnType) { let _ = c.sign(b"x"); }
`
	graph := buildRustGraphForFilter(t, "app", localTraitSrc)
	line, sc, ec := lineOf(t, localTraitSrc, "c.sign(b\"x\")")
	report := reportAt(eddsaSignRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1 (MySigner is the consumer's own trait)", got)
	}
}

// crateOfTraitPath: a resolved path names a crate, a bare trait name does not.
func TestForeignReceiverFilter_CrateOfTraitPath(t *testing.T) {
	t.Parallel()
	for trait, want := range map[string]string{
		"pkcs8::EncodePrivateKey": "pkcs8",
		"ed25519-dalek::Signer":   "ed25519_dalek",
		"signature::Signer":       "signature",
		"EncodePrivateKey":        "",
		"":                        "",
		"::Weird":                 "",
	} {
		if got := crateOfTraitPath(trait); got != want {
			t.Errorf("crateOfTraitPath(%q) = %q, want %q", trait, got, want)
		}
	}
}

// Condition 3 asks whether the scanned source declares the METHOD, not whether
// it declares the owning TYPE. An extension trait puts a local method on a
// FOREIGN type, which makes the type look source-declared while every other
// method of it still belongs to whoever defines it.
//
// apple-codesign 0.16.0 is the measured case: `impl AppleCertificate for
// CapturedX509Certificate` (x509-certificate's type) made
// `cert.to_public_key_der()` — spki's EncodePublicKey trait method, imported at
// main.rs:89 — look like apple-codesign's own, and it was dropped.
func TestForeignReceiverFilter_KeepsAForeignTypeCarryingALocalExtensionTrait(t *testing.T) {
	t.Parallel()
	// The import is written as a braced group nested inside a braced group,
	// exactly as apple-codesign writes it. That shape does not reach the parser's
	// Imports map, so CapturedX509Certificate resolves to the SCANNED crate — the
	// condition under which the type test wrongly reads it as source-declared. A
	// plain `use x509_certificate::CapturedX509Certificate;` resolves to the
	// dependency and would not reproduce the defect at all.
	const extensionSrc = `use {
    spki::EncodePublicKey,
    x509_certificate::{CapturedX509Certificate, KeyAlgorithm},
};

pub trait AppleCertificate {
    fn apple_team_id(&self) -> Option<String>;
}

impl AppleCertificate for CapturedX509Certificate {
    fn apple_team_id(&self) -> Option<String> { None }
}

pub fn spki_der(cert: &CapturedX509Certificate) -> Vec<u8> {
    cert.to_public_key_der().unwrap().as_ref().to_vec()
}
`
	graph := buildRustGraphForFilter(t, "app", extensionSrc)
	line, sc, ec := lineOf(t, extensionSrc, "cert.to_public_key_der()")
	report := reportAt("rust.spki.related-crypto-material.public-key.encode", line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 (to_public_key_der is not declared here)", got)
	}
}

// opengrep's Rust engine does not distinguish a method call from a path call:
// `$X.write_message(...)` matches `t.write_message(..)`,
// `framing::write_message(..)` AND `Codec::write_message(c, ..)` — measured on
// 1.12.1 and 1.28.0. So an import-guarded rule also claims the consumer's OWN
// module-level functions, and no receiver constraint at the rule layer can
// separate them: the difference is in the call syntax, not in what the
// metavariable binds, and `pattern-not: $A::$B(...)` removes the genuine
// matches too.
const moduleFreeFunctionSrc = `use snow::Builder;

mod framing {
    pub fn write_message(_p: &[u8]) {}
}

fn consumer_code(payload: &[u8], out: &mut [u8]) {
    framing::write_message(payload);
    let params = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
    let mut hs = Builder::new(params).build_initiator().unwrap();
    let _ = hs.write_message(payload, out);
}
`

const snowTransportRule = "rust.snow.protocol.noise-patterns.transport-message-write"

func TestForeignReceiverFilter_DropsTheConsumersOwnModuleFunction(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", moduleFreeFunctionSrc)
	line, sc, ec := lineOf(t, moduleFreeFunctionSrc, "framing::write_message(payload)")
	report := reportAt(snowTransportRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1 — the consumer's own module function is claimed by snow's rule", got)
	}
	if got := assetCount(report); got != 0 {
		t.Fatalf("assets left = %d, want 0", got)
	}
}

// The cost side of the same extension. A genuine crate call whose receiver the
// parser could not type resolves to a free function of the SCANNED package that
// the graph does not declare — `app.write_message` here — and must be kept.
func TestForeignReceiverFilter_KeepsAnUndeclaredFreeFunctionCall(t *testing.T) {
	t.Parallel()
	graph := buildRustGraphForFilter(t, "app", moduleFreeFunctionSrc)
	line, sc, ec := lineOf(t, moduleFreeFunctionSrc, "hs.write_message(payload, out)")
	report := reportAt(snowTransportRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 — an unresolved receiver is not the consumer's own declaration", got)
	}
	if got := assetCount(report); got != 1 {
		t.Fatalf("assets left = %d, want 1", got)
	}
}

// Scanning the library itself: snow's own module-level function is declared
// under the crate the rule names, so condition 4 fails and the asset stays.
func TestForeignReceiverFilter_KeepsTheLibrarysOwnModuleFunction(t *testing.T) {
	t.Parallel()
	const src = `use crate::params::NoiseParams;

pub mod framing {
    pub fn write_message(_p: &[u8]) {}
}

pub fn run(payload: &[u8]) {
    framing::write_message(payload);
}
`
	graph := buildRustGraphForFilter(t, "snow", src)
	line, sc, ec := lineOf(t, src, "framing::write_message(payload)")
	report := reportAt(snowTransportRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 — the declaring crate IS the crate the rule names", got)
	}
}

func TestForeignReceiverFilter_FreeFunctionOwnerFQN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id   callgraph.FunctionID
		want string
	}{
		{callgraph.FunctionID{Package: "app::handshake", Name: "psk"}, "app.handshake"},
		{callgraph.FunctionID{Package: "app", Name: "psk"}, "app."},
		{callgraph.FunctionID{Package: "app::a::b", Name: "psk"}, "app.a.b"},
		// A method has an owning type; declaringTypeFQN answers for it.
		{callgraph.FunctionID{Package: "app", Type: "Own", Name: "psk"}, ""},
		// Nothing to say without a package.
		{callgraph.FunctionID{Name: "psk"}, ""},
	} {
		if got := freeFunctionOwnerFQN(tc.id); got != tc.want {
			t.Errorf("freeFunctionOwnerFQN(%+v) = %q, want %q", tc.id, got, tc.want)
		}
		if tc.want != "" && crateOfTypeFQN(tc.want) != strings.Split(tc.id.Package, "::")[0] {
			t.Errorf("crateOfTypeFQN(%q) did not recover the crate of %q", tc.want, tc.id.Package)
		}
	}
}

// A rule can identify its crate through an algorithm CONSTANT passed as an
// argument rather than through a receiver. aws-lc-rs names its algorithms
// `hmac::HMAC_SHA256` and `signature::RSA_PSS_SHA384`, and published consumers
// pass them into their own helpers: jwts 0.5.1 writes
// `sign_hmac(data, key, hmac::HMAC_SHA512)`. The call resolves to a free
// function the source declares, but the algorithm evidence is the crate's and
// the finding is real — judging these dropped 13 true positives across two
// published consumers.
func TestForeignReceiverFilter_KeepsCrateEvidencePassedAsAnArgument(t *testing.T) {
	t.Parallel()
	const src = `use aws_lc_rs::hmac;

fn sign_hmac(_a: hmac::Algorithm, _k: &[u8], _m: &[u8]) -> Vec<u8> { vec![] }

fn consumer_code(key: &[u8], message: &[u8]) {
    let _ = sign_hmac(hmac::HMAC_SHA256, key, message);
}
`
	graph := buildRustGraphForFilter(t, "app", src)
	line, sc, ec := lineOf(t, src, "sign_hmac(hmac::HMAC_SHA256, key, message)")
	report := reportAt("rust.aws-lc-rs.algorithm.mac.hmac", line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
		t.Fatalf("dropped = %d, want 0 — the algorithm constant is the crate's own evidence", got)
	}
}

// The escape hatch has to recognize a path that could name another crate and
// nothing else. Each shape below carries a `::` that names no crate, and each
// one re-opened the false positive when the test was a bare
// strings.Contains(argument, "::").
func TestForeignReceiverFilter_ArgumentPathsThatNameNoCrate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		call string
		want bool // may the argument name another crate?
	}{
		{"a dependency's constant", `framing::write_message(hmac::HMAC_SHA256)`, true},
		{"the consumer's own type", `framing::write_message(payload, Codec::default())`, false},
		{"a crate-rooted path", `framing::write_message(crate::PAYLOAD)`, false},
		{"a self-rooted path", `framing::write_message(self::PAYLOAD)`, false},
		{"a super-rooted path", `framing::write_message(super::PAYLOAD)`, false},
		{"a Self-rooted path", `framing::write_message(Self::PAYLOAD)`, false},
		{"a turbofish", `framing::write_message(s.parse::<usize>().unwrap())`, false},
		{"a path inside a string", `framing::write_message("a::b")`, false},
		{"a module path in a nested call", `framing::write_message(signature::RSA_PSS_SHA384.into())`, true},
		{"no path at all", `framing::write_message(payload)`, false},
	} {
		// The argument list as the parser hands it over: everything between the
		// outermost parentheses, split on the top-level commas.
		args := splitTopLevelArgs(tc.call[strings.Index(tc.call, "(")+1 : len(tc.call)-1])
		if got := callArgumentCarriesAPath(args); got != tc.want {
			t.Errorf("%s: callArgumentCarriesAPath(%q) = %v, want %v", tc.name, args, got, tc.want)
		}
	}
}

// splitTopLevelArgs splits an argument list on commas outside brackets and
// strings, so the table above can be written as source rather than as slices.
func splitTopLevelArgs(list string) []string {
	var args []string
	depth, start, inString := 0, 0, false
	for i := 0; i < len(list); i++ {
		switch c := list[i]; {
		case inString && c == '\\' && i+1 < len(list):
			i++
		case c == '"':
			inString = !inString
		case inString:
		case c == '(' || c == '[' || c == '<':
			depth++
		case c == ')' || c == ']' || c == '>':
			depth--
		case c == ',' && depth == 0:
			args = append(args, strings.TrimSpace(list[start:i]))
			start = i + 1
		}
	}
	if rest := strings.TrimSpace(list[start:]); rest != "" {
		args = append(args, rest)
	}
	return args
}
