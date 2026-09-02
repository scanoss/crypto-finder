// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package scan

import (
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A Rust rule identifies its crate with a file-level import guard:
//
//	- pattern-inside: |
//	    use $IMPORT;
//	    ...
//	- metavariable-regex: {metavariable: $IMPORT, regex: '(?i)^(ed25519.dalek).*'}
//	- pattern: $KEY.sign($MSG)
//
// The guard anchors the FILE. It does not anchor the CALL: `$KEY` is a free
// metavariable, so in a file that imports the crate the rule also claims
// `own.sign(..)` on the consumer's own type. Measured 2026-09-01 over published
// reverse-dependencies: 20 of 25 Rust crates in the ruleset leak this way, 134
// false matches. The rule files say so themselves — ed25519-dalek's records
// "the receiver's type is not knowable from the syntax tree ... Constraining it
// further is not possible at this layer".
//
// It is knowable at THIS layer. The Rust parser resolves a receiver's type
// through every value routing it supports (rust_receiver_routing_test.go), and
// stamps the callee as <crate>.<Type>.<method>. On the probe above it renders
// `own.sign` as app.ConsumerOwnType.sign and `self.inner.sign` as
// ed25519_dalek.SigningKey.sign — it separates exactly what the rule cannot,
// and it keeps the struct-field receiver that a taint-mode rewrite of the rule
// drops.
//
// Why not fix it in the rules instead: converting the guarded forms to
// `mode: taint` sourced at the crate's constructors was measured on the pinned
// opengrep over the same corpora. It removes the false matches but only reaches
// receivers a same-file constructor flows into, so it loses real detections
// wherever the key arrives from a struct field, a parameter or a function
// return — ed25519-dalek -8, tokio-rustls -9, p256 -6, russh -6, all of them
// true positives in wrapper crates. Filtering here costs no recall at all.
//
// SCOPE: Rust only, deliberately. The import-guard construct this compensates
// for is 100% Rust (466 rules, 132 files, no other language uses it), and every
// other ecosystem is already mined and served. Widening this is a separate
// change with its own measurement.

// FilterForeignReceiverAssets drops crypto assets whose matched call is a
// method invoked on a receiver the SCANNED SOURCE ITSELF declares, under a type
// that does not belong to the crate the matching rule names.
//
// It is deliberately one-sided. An asset is dropped only when every one of the
// four conditions below holds; anything unresolved, ambiguous or unrecognized
// keeps the asset, exactly as deadcode.FilterReport keeps findings in a file it
// cannot read:
//
//  1. the rule ID names a crate (rust.<crate>....);
//  2. the match resolves to a call node;
//  3. that node's callee resolved to a function the SCANNED SOURCE ITSELF
//     DECLARES — an unresolved receiver, or a method that lives in a
//     dependency, is kept. A free function counts: `framing::write_message(..)`
//     declared in the consumer's own module is the same defect as
//     `own.sign(..)`, because the rule layer cannot tell the two call shapes
//     apart (see freeFunctionOwnerFQN);
//  4. the declaring crate differs from the crate the rule names.
//
// Condition 3 asks about the METHOD, not its owning type. A crate may write
// `impl <ExtensionTrait> for <ForeignType>`: apple-codesign 0.16.0 has
// `impl AppleCertificate for CapturedX509Certificate`, a type belonging to
// x509-certificate. That makes the TYPE look source-declared while the method
// actually called — spki's `to_public_key_der` — is not declared here at all.
// Testing the type dropped that true positive; testing the method does not.
//
// Condition 3 is also what makes scanning the library itself safe: inside
// ed25519-dalek, `impl SigningKey { fn sign }` is source-declared under
// ed25519_dalek, so condition 4 fails and the asset stays.
//
// The method/static distinction is deliberately NOT drawn. Once the parser
// resolves a receiver it moves the identity into the callee and clears
// ReceiverVar, so the two are indistinguishable at this point — and they need
// not be distinguished: `ConsumerOwnType::from_bytes(..)` claimed by a crate
// rule is the same defect as `own.sign(..)`, and a genuine
// `ed25519_dalek::SigningKey::generate(..)` is not source-declared by a
// consumer, so condition 3 keeps it.
//
// Only the offending rules are removed from an asset. An asset is dropped only
// when it has no rule left, so a match claimed by both a crate rule and a
// generic one survives on the generic one.
//
// Returns the number of assets dropped.
func FilterForeignReceiverAssets(
	report *entities.InterimReport,
	graph *callgraph.CallGraph,
	ecosystem string,
) int {
	if report == nil || graph == nil || ecosystem != ecosystemRust {
		return 0
	}
	ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: ecosystem})
	dropped := 0
	// A finding whose every asset is dropped is removed, as deadcode.FilterReport
	// does: an empty cryptographic_assets list is a finding that claims nothing.
	kept := make([]entities.Finding, 0, len(report.Findings))
	for findingIndex := range report.Findings {
		finding := &report.Findings[findingIndex]
		had := len(finding.CryptographicAssets)
		dropped += filterFindingForeignReceivers(ctx, finding)
		if had > 0 && len(finding.CryptographicAssets) == 0 {
			continue
		}
		kept = append(kept, *finding)
	}
	report.Findings = kept
	if dropped > 0 {
		log.Info().
			Int("count", dropped).
			Str("ecosystem", ecosystem).
			Msg("Dropped crypto assets whose receiver type is declared by the scanned source, not by the rule's crate")
	}
	return dropped
}

// graphDeclaresMethod reports whether the scanned source declares the exact
// method the callee names. It deliberately does not ask whether the owning TYPE
// is declared here: an extension trait puts a local method on a foreign type,
// and every OTHER method of that type still belongs to whoever defines it.
func graphDeclaresMethod(graph *callgraph.CallGraph, callee callgraph.FunctionID) bool {
	decl, ok := graph.Functions[callee.String()]
	return ok && decl != nil
}

// candidateOwnerFQN renders the <crate>.<owner> a call is judged by, and reports
// whether it may be judged at all. A method's owner is its type; a free
// function's is the module it is declared in.
//
// It refuses to judge one shape: a free function whose call carries a
// path-qualified ARGUMENT. A rule can take the crate's identity from an
// argument rather than from a receiver — aws-lc-rs names its algorithms
// `hmac::HMAC_SHA256` and `signature::RSA_PSS_SHA384`, and its rules match
// wherever one is passed. jwts 0.5.1 and jsonwebtoken-aws-lc 9.3.0 pass those
// constants into their own `sign_hmac`/`sign_rsa`/`verify_asymmetric` helpers,
// so the call resolves to a free function the source declares while the
// algorithm evidence is genuine and belongs to the crate. Measured: judging
// those calls dropped 13 TRUE positives across the two consumers.
func candidateOwnerFQN(candidate *callgraph.FunctionCall) (owner string, judgeable bool) {
	if owner = declaringTypeFQN(candidate.Callee); owner != "" {
		return owner, true
	}
	if callArgumentCarriesAPath(candidate.Arguments) {
		return "", false
	}
	return freeFunctionOwnerFQN(candidate.Callee), true
}

// callArgumentCarriesAPath reports whether any argument of this call is a
// path-qualified expression that could name another crate. It is how a rule
// that identifies its crate through an algorithm CONSTANT rather than a
// receiver is recognized, so such a match is never judged as the consumer's own
// call.
//
// Deliberately syntactic: the graph carries the raw argument expressions but
// not the file's imports, so the root segment cannot be resolved back to a
// crate here, and this filter's standing rule is to keep the asset whenever a
// step is unresolved. Being syntactic, it has to exclude the `::` occurrences
// that carry no crate identity at all — measured, each of these re-opened the
// false positive the free-function judgement exists to close:
//
//	framing::write_message(payload, Codec::default())   // the consumer's own type
//	framing::write_message(crate::PAYLOAD)              // crate:: / self:: / super::
//	framing::write_message(s.parse::<usize>().unwrap()) // a turbofish is not a path
//	framing::write_message("a::b")                      // a string is not code
//
// A `crate`, `self`, `super` or `Self` root cannot name a dependency by
// definition. An uppercase-initial root is a TYPE, and a type the scanned
// source declares is exactly what the caller is being judged for; a type from
// the claimed crate would have to be imported, and then the receiver-side
// checks above already keep the asset.
func callArgumentCarriesAPath(arguments []string) bool {
	for _, argument := range arguments {
		if argumentNamesAnotherCrate(argument) {
			return true
		}
	}
	return false
}

// argumentNamesAnotherCrate reports whether one argument expression contains a
// module path whose root could belong to another crate.
func argumentNamesAnotherCrate(argument string) bool {
	for _, root := range pathRoots(stripStringLiterals(argument)) {
		switch root {
		case "crate", "self", "super", "Self":
			continue
		}
		// A lowercase root is a module or crate name; an uppercase one is a type.
		if r := rune(root[0]); r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

// pathRoots returns the identifier immediately left of each `::` separator,
// skipping the turbofish form `::<` which is a generic argument list rather than
// a path segment.
func pathRoots(expression string) []string {
	var roots []string
	for i := 0; i+1 < len(expression); i++ {
		if expression[i] != ':' || expression[i+1] != ':' {
			continue
		}
		if i+2 < len(expression) && expression[i+2] == '<' {
			continue // turbofish: `parse::<usize>()`
		}
		start := i
		for start > 0 && isIdentifierByte(expression[start-1]) {
			start--
		}
		if start < i {
			roots = append(roots, expression[start:i])
		}
	}
	return roots
}

func isIdentifierByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// stripStringLiterals blanks out the contents of double-quoted literals so a
// path spelled inside a string is not read as code. Escapes are honored; a
// character literal cannot hold a `::`, so it is left alone.
func stripStringLiterals(expression string) string {
	var b strings.Builder
	inString := false
	for i := 0; i < len(expression); i++ {
		c := expression[i]
		switch {
		case inString && c == '\\' && i+1 < len(expression):
			i++
		case c == '"':
			inString = !inString
			b.WriteByte(c)
		case inString:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// freeFunctionOwnerFQN renders the MODULE a free function is declared in, as
// <crate>.<module tail>, so a call with no owning type is judged by the same
// crate comparison a method gets: "app::handshake" -> "app.handshake".
//
// This exists because opengrep's Rust engine cannot tell a method call from a
// module-path call: `$X.write_message(...)` and `$A::write_message(...)` both
// match `t.write_message(..)`, `framing::write_message(..)` AND
// `Codec::write_message(c, ..)` — measured on 1.12.1 and 1.28.0. So a rule
// guarded on the file's imports also claims the consumer's OWN module-level
// functions, and no receiver constraint written at the rule layer can separate
// them; `pattern-not: $A::$B(...)` removes the genuine matches too.
//
// The parser does separate them: it resolves `framing::write_message(..)` to
// app::framing.write_message and declares that function in the graph, while a
// genuine `hs.write_message(..)` whose receiver it cannot type resolves to
// app.write_message, which the graph does NOT declare. Condition 3 below is
// what makes the difference load-bearing: only a function the scanned source
// actually declares is dropped.
//
// A bare crate path with no module segment ("app") gets the trailing separator
// so crateOfTypeFQN reads the same crate out of both shapes.
func freeFunctionOwnerFQN(id callgraph.FunctionID) string {
	if id.Type != "" || id.Package == "" {
		return ""
	}
	owner := strings.ReplaceAll(id.Package, "::", ".")
	if !strings.Contains(owner, ".") {
		owner += "."
	}
	return owner
}

// declaringTypeFQN renders the owning type of a FunctionID as <package>.<Type>,
// or "" for a free function. It mirrors engine.classFQN, which is unexported.
func declaringTypeFQN(id callgraph.FunctionID) string {
	switch {
	case id.Package != "" && id.Type != "":
		return id.Package + "." + id.Type
	case id.Type != "":
		return id.Type
	default:
		return ""
	}
}

func filterFindingForeignReceivers(
	ctx *exportBuildContext,
	finding *entities.Finding,
) int {
	kept := make([]entities.CryptographicAsset, 0, len(finding.CryptographicAssets))
	dropped := 0
	for i := range finding.CryptographicAssets {
		asset := finding.CryptographicAssets[i]
		owner, foreign := foreignSourceReceiver(ctx, finding, asset)
		if !foreign {
			kept = append(kept, asset)
			continue
		}
		asset.Rules = rulesNotClaimingForeignCrate(asset.Rules, owner)
		if len(asset.Rules) == 0 {
			log.Debug().
				Str("file", finding.FilePath).
				Int("line", asset.StartLine).
				Str("receiver_type", owner).
				Msg("Dropped asset: receiver type is declared by the scanned source, not by the rule's crate")
			dropped++
			continue
		}
		kept = append(kept, asset)
	}
	finding.CryptographicAssets = kept
	return dropped
}

// foreignSourceReceiver reports the resolved receiver type of the asset's match
// when EVERY call node at that position belongs to the scanned source under a
// crate none of the asset's rules names. The bool is false whenever any step is
// unresolved — the asset is kept in every such case.
//
// It judges every candidate node, not one. findCryptoCallNode returns the CHAIN
// ROOT by contract, and in a chain the root is frequently the consumer's own
// type while the crypto call is a later link: tlfs-crdt 0.1.0 src/crypto.rs:39
// is `self.to_keypair().sign(msg)` inside the crate's own `impl Keypair`, whose
// root resolves to tlfs_crdt.Keypair.to_keypair and whose second link resolves
// to ed25519_dalek.Keypair.sign. Judging the root alone dropped that TRUE
// positive — measured, not hypothetical. One link reaching the claimed crate is
// enough to keep the asset.
func foreignSourceReceiver(
	ctx *exportBuildContext,
	finding *entities.Finding,
	asset entities.CryptographicAsset,
) (string, bool) {
	claimed := claimedCrates(asset.Rules)
	if len(claimed) == 0 {
		return "", false
	}
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn == nil {
		return "", false
	}
	candidates := matchPositionCalls(containingFn, asset)
	if len(candidates) == 0 {
		return "", false
	}
	foreign := ""
	for _, candidate := range candidates {
		// The owning type of the RESOLVED callee, e.g. leakprobe.ConsumerOwnType
		// for `own.sign(..)` and ed25519_dalek.SigningKey for
		// `self.inner.sign(..)`. A free function has no owning type, and its
		// crate comes from the module it is declared in instead.
		owner, judgeable := candidateOwnerFQN(candidate)
		if !judgeable {
			return "", false
		}
		if owner == "" || !strings.Contains(owner, ".") {
			continue
		}
		if _, ok := claimed[crateOfTypeFQN(owner)]; ok {
			return "", false
		}
		// A method declared in `impl <CrateTrait> for <LocalType>` is the
		// CRATE's API even though the receiver type is the consumer's.
		// apple-codesign 0.16.0 writes `impl EncodePrivateKey for
		// InMemoryPrivateKey` under `use pkcs8::EncodePrivateKey`: its own type,
		// pkcs8's `to_pkcs8_der`. Judging the receiver type alone dropped five
		// true positives there and one in elliptic-curve 0.9.9 — caught by the
		// published-consumer sweep, not by the unit tests.
		if implementsClaimedCrateTrait(ctx.graph, candidate.Callee, claimed) {
			return "", false
		}
		// Safety net for the same case when the trait is NOT known. The trait is
		// resolved through the file's imports, and one import shape does not
		// reach the Imports map: a braced group nested inside a braced group,
		// `use { .., pkcs8::{.., EncodePrivateKey}, .. };`, which is how
		// apple-codesign 0.16.0 imports it. Rather than change Rust import
		// resolution — which every scan depends on — this keeps any method whose
		// NAME carries the crate's name.
		//
		// The naming is not a coincidence: `to_pkcs8_der`, `from_pkcs1_der`,
		// `to_sec1_der` are the crate's own trait methods, and a consumer type
		// carrying one is implementing that trait. Nothing generic is affected —
		// `sign` does not contain "ed25519_dalek", `authenticate_password` does
		// not contain "russh" — so the crates this filter exists for are
		// untouched.
		if methodNameCarriesClaimedCrate(candidate.Callee.Name, claimed) {
			return "", false
		}
		if foreign == "" && graphDeclaresMethod(ctx.graph, candidate.Callee) {
			foreign = owner
		}
	}
	if foreign == "" {
		return "", false
	}
	return foreign, true
}

// implementsClaimedCrateTrait reports whether the resolved callee is declared in
// an `impl <Trait> for <Type>` block whose trait belongs to one of the crates the
// asset's rules name.
//
// A trait the scanned crate declares itself resolves to a bare name with no
// module path, which names no crate and so matches nothing here — exactly right,
// since a consumer's own trait is not the claimed crate's API.
func implementsClaimedCrateTrait(
	graph *callgraph.CallGraph,
	callee callgraph.FunctionID,
	claimed map[string]struct{},
) bool {
	decl, ok := graph.Functions[callee.String()]
	if !ok || decl == nil {
		return false
	}
	for _, trait := range decl.OwnerTraits {
		if crate := crateOfTraitPath(trait); crate != "" {
			if _, ok := claimed[crate]; ok {
				return true
			}
		}
	}
	return false
}

// methodNameCarriesClaimedCrate reports whether the method's own name contains
// the name of a crate the asset's rules claim, compared with separators removed
// so `to_pkcs8_der` matches crate `pkcs8` and `from_pkcs1_pem` matches `pkcs1`.
//
// Crate names shorter than four characters are ignored: a two- or three-letter
// name would match by accident far more often than by convention.
func methodNameCarriesClaimedCrate(method string, claimed map[string]struct{}) bool {
	flat := flattenIdentifier(method)
	if flat == "" {
		return false
	}
	for crate := range claimed {
		flatCrate := flattenIdentifier(crate)
		if len(flatCrate) >= 4 && strings.Contains(flat, flatCrate) {
			return true
		}
	}
	return false
}

// flattenIdentifier lowercases an identifier and drops the separators that
// distinguish a method name from a crate name: to_pkcs8_der -> topkcs8der,
// ed25519-dalek -> ed25519dalek.
func flattenIdentifier(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r != '_' && r != '-' && r != '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// crateOfTraitPath takes the crate from a resolved trait path, normalized to the
// module spelling: "pkcs8::EncodePrivateKey" -> "pkcs8". A bare trait name has no
// path and yields "", meaning the scanned crate's own trait.
func crateOfTraitPath(trait string) string {
	i := strings.Index(trait, "::")
	if i <= 0 {
		return ""
	}
	return strings.ReplaceAll(trait[:i], "-", "_")
}

// matchPositionCalls returns the call nodes that sit at the asset's position:
// the calls inside the containing function on the match's lines, narrowed to
// those whose columns intersect the match when both sides carry columns. It
// mirrors steps 1 and 2 of findCryptoCallNode and stops before step 3, whose
// tie-break to the chain root is the wrong answer here.
func matchPositionCalls(
	containingFn *callgraph.FunctionDecl,
	asset entities.CryptographicAsset,
) []*callgraph.FunctionCall {
	lineCandidates := cryptoCallLineCandidates(containingFn, asset.StartLine, asset.EndLine)
	if len(lineCandidates) == 0 {
		return nil
	}
	if asset.TerminalStartCol > 0 && asset.TerminalEndCol > 0 {
		asset.StartCol = asset.TerminalStartCol
		asset.EndCol = asset.TerminalEndCol
	}
	if asset.StartCol <= 0 || asset.EndCol <= 0 {
		return lineCandidates
	}
	return cryptoCallColumnCandidates(lineCandidates, asset)
}

// rulesNotClaimingForeignCrate keeps the rules that do NOT name a crate other
// than the receiver's declaring one — a rule with no crate in its ID, or one
// that names the receiver's own crate.
func rulesNotClaimingForeignCrate(rules []entities.RuleInfo, owner string) []entities.RuleInfo {
	ownerCrate := crateOfTypeFQN(owner)
	kept := make([]entities.RuleInfo, 0, len(rules))
	for _, rule := range rules {
		crate := crateOfRuleID(rule.ID)
		if crate == "" || crate == ownerCrate {
			kept = append(kept, rule)
		}
	}
	return kept
}

func claimedCrates(rules []entities.RuleInfo) map[string]struct{} {
	crates := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if crate := crateOfRuleID(rule.ID); crate != "" {
			crates[crate] = struct{}{}
		}
	}
	return crates
}

// crateOfRuleID extracts the crate a Rust rule names, normalized to the module
// spelling the parser uses: hyphens become underscores, so
// "rust.ed25519-dalek.algorithm.signature.eddsa-sign" yields "ed25519_dalek".
//
// The ID is NOT the one authored in the YAML. opengrep prefixes it with the
// rule file's path relative to the config root, so the same rule arrives as
// "rust.ed25519-dalek.algorithm.signature.eddsa-sign" from a single --rules
// file and as
// "semgrep-rules.rust.ed25519-dalek.algorithm.signature.rust.ed25519-dalek.algorithm.signature.eddsa-sign"
// from --rules-dir on the repository root — which is how the mining service
// loads them. Anchoring on a "rust." PREFIX therefore matched nothing in
// production while every unit test passed.
//
// So every "rust" path segment is read, and the segment after it taken as a
// candidate crate. The candidates must agree: a disagreement means the shape is
// not understood, and returning "" there keeps the asset.
func crateOfRuleID(id string) string {
	segments := strings.Split(id, ".")
	crate := ""
	for i, segment := range segments {
		// The language segment of a rule ID happens to be spelled exactly like
		// the ecosystem name, so the same constant serves both.
		if segment != ecosystemRust || i+1 >= len(segments) {
			continue
		}
		candidate := strings.ReplaceAll(segments[i+1], "-", "_")
		if candidate == "" {
			return ""
		}
		if crate != "" && crate != candidate {
			return ""
		}
		crate = candidate
	}
	return crate
}

// crateOfTypeFQN takes the crate from a resolved <crate>.<Type> receiver, e.g.
// "ed25519_dalek.SigningKey" → "ed25519_dalek". A bare type with no package
// yields "", which matches no rule-declared crate and so reads as foreign.
func crateOfTypeFQN(owner string) string {
	if i := strings.IndexByte(owner, '.'); i >= 0 {
		return owner[:i]
	}
	return ""
}
