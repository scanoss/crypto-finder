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

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// SyntheticEntryPointRuleID labels findings produced by surfacing a library's
// public crypto API boundary (rather than by a call-site rule match), so the
// origin is auditable downstream. The call-graph export keys off this id to
// attach contract-derived supporting calls (the fluent lifecycle methods) to
// these synthetic terminals.
const (
	SyntheticEntryPointRuleID = "crypto-finder.api-entry-point"

	extYAML         = ".yaml"
	extYML          = ".yml"
	languageJava    = "java"
	ecosystemPython = "python"
)

// SynthesizeRuleCryptoEntryPoints surfaces a library's public crypto API methods
// as crypto entry points when the LIBRARY ITSELF is being mined. It exists for
// "Type 2" fluent/builder/DSL libraries (e.g. Password4J HashBuilder.withBcrypt)
// whose crypto meaning lives on the API boundary rather than in a detectable
// primitive call inside their own source — so mining them yields no public-API
// entry points and a purl-keyed reachability query returns nothing actionable.
//
// The crypto semantic is NOT re-declared here. It is read from the ruleset's
// metadata.crypto (the single source of truth) via the rule's `api` field, which
// for these boundary rules is the fully-qualified method symbol. A synthetic
// finding is emitted ONLY when:
//
//	(1) a rule's metadata.crypto.api matches a method DEFINITION in the scanned
//	    call graph (true only when the library that owns the API is mined; a
//	    consumer scan has call sites, not definitions, and Type 1 short api names
//	    like "Cipher.getInstance" never match a scanned definition), and
//	(2) that method body has no already-detected crypto finding (Type 1 methods
//	    whose primitive call is detectable inside them are already covered and
//	    must not be double-counted).
//
// The ecosystem parameter controls the qualified-symbol gate: "python" accepts
// api symbols with >= 1 dot (e.g. bcrypt.hashpw, jwt.encode) while all other
// ecosystems require >= 2 dots (Java convention, e.g. com.foo.Bar.method). Pass
// "" to apply the default >= 2-dot gate.
//
// report is mutated in place; returns the number of findings added. FindingIDs
// are assigned by the caller's existing AssignFindingIDs pass.
func SynthesizeRuleCryptoEntryPoints(report *entities.InterimReport, graph *callgraph.CallGraph, rulePaths []string, ecosystem string) int {
	if report == nil || graph == nil || len(rulePaths) == 0 {
		return 0
	}

	apiCrypto := buildRuleCryptoByAPI(rulePaths, ecosystem)
	if len(apiCrypto) == 0 {
		return 0
	}

	declsByFQN, declsByClass := indexGraphDeclarations(graph)
	fileIdx := indexReportFiles(report)
	added := synthesizeRuleCryptoAssets(report, fileIdx, apiCrypto, declsByFQN, declsByClass)

	if added > 0 {
		log.Info().
			Int("count", added).
			Str("ecosystem", ecosystem).
			Msg("Surfaced library public crypto API methods as entry points (from rule metadata.crypto)")
	}
	return added
}

// indexGraphDeclarations indexes method definitions present in the scanned
// source by their base FQN and by owning class FQN. The class index lets a
// constructor api resolve even when the class declares no explicit constructor
// (the compiler-generated default has no <init> in the source AST).
func indexGraphDeclarations(
	graph *callgraph.CallGraph,
) (map[string][]*callgraph.FunctionDecl, map[string][]*callgraph.FunctionDecl) {
	declsByFQN := make(map[string][]*callgraph.FunctionDecl)
	declsByClass := make(map[string][]*callgraph.FunctionDecl)
	for _, fn := range graph.Functions {
		if fqn := baseFQN(functionFQN(fn.ID)); fqn != "" {
			declsByFQN[fqn] = append(declsByFQN[fqn], fn)
		}
		if class := classFQN(fn.ID); class != "" {
			declsByClass[class] = append(declsByClass[class], fn)
		}
	}
	return declsByFQN, declsByClass
}

func indexReportFiles(report *entities.InterimReport) map[string]int {
	fileIdx := make(map[string]int, len(report.Findings))
	for i := range report.Findings {
		fileIdx[report.Findings[i].FilePath] = i
	}
	return fileIdx
}

func synthesizeRuleCryptoAssets(
	report *entities.InterimReport,
	fileIdx map[string]int,
	apiCrypto map[string]map[string]string,
	declsByFQN map[string][]*callgraph.FunctionDecl,
	declsByClass map[string][]*callgraph.FunctionDecl,
) int {
	added := 0
	for api, meta := range apiCrypto {
		added += synthesizeAPIAssets(report, fileIdx, api, meta, declsByFQN[api], declsByClass)
	}
	return added
}

func synthesizeAPIAssets(
	report *entities.InterimReport,
	fileIdx map[string]int,
	api string,
	meta map[string]string,
	decls []*callgraph.FunctionDecl,
	declsByClass map[string][]*callgraph.FunctionDecl,
) int {
	if len(decls) == 0 {
		return synthesizeImplicitCtorAsset(report, fileIdx, api, meta, declsByClass)
	}
	return synthesizeDeclaredAPIAssets(report, fileIdx, api, meta, decls)
}

func synthesizeImplicitCtorAsset(
	report *entities.InterimReport,
	fileIdx map[string]int,
	api string,
	meta map[string]string,
	declsByClass map[string][]*callgraph.FunctionDecl,
) int {
	// No source-declared method matches the api. A constructor api may still
	// belong to a scanned class with only an implicit default constructor.
	rep := implicitCtorRep(api, declsByClass)
	if rep == nil {
		return 0
	}
	if appendSyntheticRuleAsset(report, fileIdx, api, meta, rep) {
		return 1
	}
	return 0
}

func synthesizeDeclaredAPIAssets(
	report *entities.InterimReport,
	fileIdx map[string]int,
	api string,
	meta map[string]string,
	decls []*callgraph.FunctionDecl,
) int {
	added := 0
	for _, fn := range decls {
		if functionBodyHasFinding(report, fn) {
			continue // Type 1: primitive already detected inside the method.
		}
		if appendSyntheticRuleAsset(report, fileIdx, api, meta, fn) {
			added++
		}
	}
	return added
}

func appendSyntheticRuleAsset(
	report *entities.InterimReport,
	fileIdx map[string]int,
	api string,
	meta map[string]string,
	fn *callgraph.FunctionDecl,
) bool {
	asset := buildSyntheticAssetFromRule(api, meta, fn)
	return appendSyntheticAsset(report, fileIdx, fn.FilePath, languageForPath(fn.FilePath), asset)
}

// functionFQN renders a FunctionID as the dotted fully-qualified name used in a
// rule's metadata.crypto.api, e.g. "com.password4j.HashBuilder.withBcrypt".
func functionFQN(id callgraph.FunctionID) string {
	switch {
	case id.Type != "" && id.Package != "":
		return id.Package + "." + id.Type + "." + id.Name
	case id.Type != "":
		return id.Type + "." + id.Name
	case id.Package != "":
		return id.Package + "." + id.Name
	default:
		return id.Name
	}
}

// classFQN renders the owning class of a FunctionID as a dotted package.Type
// symbol (no method), e.g. "org.bouncycastle.crypto.engines.RSAEngine". Empty
// when the function has no owning type (e.g. a package-level function).
func classFQN(id callgraph.FunctionID) string {
	switch {
	case id.Package != "" && id.Type != "":
		return id.Package + "." + id.Type
	case id.Type != "":
		return id.Type
	default:
		return ""
	}
}

// implicitCtorRep resolves a constructor api ("package.Type.<init>") to a
// representative declaration of its owning class when the class is scanned but
// declares no explicit constructor (only a compiler-generated default exists,
// absent from the source AST). It returns nil for non-constructor apis or
// classes not present in the scan. The representative is the class member with
// the lowest start line, giving a stable, auditable location near the class top.
func implicitCtorRep(api string, declsByClass map[string][]*callgraph.FunctionDecl) *callgraph.FunctionDecl {
	const ctorSuffix = ".<init>"
	if !strings.HasSuffix(api, ctorSuffix) {
		return nil
	}
	decls := declsByClass[strings.TrimSuffix(api, ctorSuffix)]
	if len(decls) == 0 {
		return nil
	}
	rep := decls[0]
	for _, d := range decls[1:] {
		if d.StartLine > 0 && (rep.StartLine <= 0 || d.StartLine < rep.StartLine) {
			rep = d
		}
	}
	return rep
}

// baseFQN strips the arity/overload decoration ("#0", "#1$String", …) from a
// function FQN, leaving the bare package.Type.method symbol.
func baseFQN(fqn string) string {
	if i := strings.IndexByte(fqn, '#'); i >= 0 {
		return fqn[:i]
	}
	return fqn
}

// functionBodyHasFinding reports whether report already contains a crypto asset
// located within fn's line range in fn's file — i.e. the method itself performs
// a detectable crypto operation (Type 1) and is already a natural entry point.
func functionBodyHasFinding(report *entities.InterimReport, fn *callgraph.FunctionDecl) bool {
	fnPath := filepath.ToSlash(fn.FilePath)
	for i := range report.Findings {
		if !strings.HasSuffix(fnPath, filepath.ToSlash(report.Findings[i].FilePath)) &&
			!strings.HasSuffix(filepath.ToSlash(report.Findings[i].FilePath), fnPath) {
			continue
		}
		for j := range report.Findings[i].CryptographicAssets {
			a := &report.Findings[i].CryptographicAssets[j]
			if a.StartLine >= fn.StartLine && a.StartLine <= fn.EndLine {
				return true
			}
		}
	}
	return false
}

// buildSyntheticAssetFromRule constructs a CryptographicAsset at the API method's
// own declaration site, copying the rule's crypto metadata verbatim so the output
// is byte-for-byte what a call-site match of the same rule would have produced.
// Match is the bare dotted FQN (no parentheses) so the export's matched-operation
// classifier treats it as a type_usage and preserves this symbol.
func buildSyntheticAssetFromRule(api string, meta map[string]string, fn *callgraph.FunctionDecl) entities.CryptographicAsset {
	md := make(map[string]string, len(meta)+2)
	for k, v := range meta {
		md[k] = v
	}
	md["api"] = api
	if md["assetType"] == "" {
		md["assetType"] = "algorithm"
	}

	line := fn.StartLine
	if line <= 0 {
		line = 1
	}
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     api,
		Rules: []entities.RuleInfo{{
			ID:       SyntheticEntryPointRuleID,
			Message:  "Crypto entry point (library public API boundary): " + api,
			Severity: "INFO",
		}},
		Status:   "pending",
		Metadata: md,
		Source:   "direct",
	}
}

// appendSyntheticAsset adds asset to the Finding for filePath (creating one if
// needed), skipping exact duplicates. Returns true when an asset was added.
func appendSyntheticAsset(
	report *entities.InterimReport,
	fileIdx map[string]int,
	filePath, language string,
	asset entities.CryptographicAsset,
) bool {
	if idx, ok := fileIdx[filePath]; ok {
		for i := range report.Findings[idx].CryptographicAssets {
			existing := &report.Findings[idx].CryptographicAssets[i]
			if existing.StartLine == asset.StartLine && existing.Metadata["api"] == asset.Metadata["api"] {
				return false
			}
		}
		report.Findings[idx].CryptographicAssets = append(report.Findings[idx].CryptographicAssets, asset)
		return true
	}
	report.Findings = append(report.Findings, entities.Finding{
		FilePath:            filePath,
		Language:            language,
		CryptographicAssets: []entities.CryptographicAsset{asset},
	})
	fileIdx[filePath] = len(report.Findings) - 1
	return true
}

// ── rule metadata.crypto extraction ────────────────────────────────────────

// ruleFileCryptoYAML captures just the metadata.crypto block of each rule.
type ruleFileCryptoYAML struct {
	Rules []struct {
		Metadata struct {
			Crypto map[string]any `yaml:"crypto"`
		} `yaml:"metadata"`
	} `yaml:"rules"`
}

// buildRuleCryptoByAPI walks the ruleset (files and/or directories) and indexes
// every rule's metadata.crypto block by its `api` value, but only when `api`
// looks like a fully-qualified method (the boundary-rule convention: a dotted
// symbol). The ecosystem parameter is forwarded to the qualified-symbol gate so
// Python's 1-dot module-level functions are accepted. The returned map carries
// the crypto block stringified verbatim so the synthetic finding metadata is
// identical to a call-site match. The rule remains the single source of truth
// for the crypto semantics.
func buildRuleCryptoByAPI(rulePaths []string, ecosystem string) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for _, p := range rulePaths {
		for _, file := range expandRuleFiles(p) {
			addRuleCryptoFile(out, file, ecosystem)
		}
	}
	return out
}

func addRuleCryptoFile(out map[string]map[string]string, file, ecosystem string) {
	// Rule paths come from the trusted ruleset manager.
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	var rf ruleFileCryptoYAML
	if yaml.Unmarshal(data, &rf) != nil {
		return
	}

	for _, r := range rf.Rules {
		addRuleCrypto(out, r.Metadata.Crypto, ecosystem)
	}
}

func addRuleCrypto(out map[string]map[string]string, crypto map[string]any, ecosystem string) {
	api, ok := cryptoAPI(crypto, ecosystem)
	if !ok {
		return
	}
	if _, seen := out[api]; seen {
		return // first declaration wins; deterministic enough for synthesis
	}
	out[api] = stringifyCryptoBlock(crypto)
}

func cryptoAPI(crypto map[string]any, ecosystem string) (string, bool) {
	if len(crypto) == 0 {
		return "", false
	}
	api, ok := crypto["api"].(string)
	api = strings.TrimSpace(api)
	if !ok || api == "" {
		return "", false
	}
	if !isQualifiedMethodSymbol(api, ecosystem) {
		return "", false
	}
	return api, true
}

// isQualifiedMethodSymbol reports whether s is a dotted symbol that qualifies as
// a boundary-rule api entry point for the given ecosystem.
//
// For Python (ecosystem == "python"): requires exactly >= 1 dot — module-level
// functions like bcrypt.hashpw and jwt.encode are valid public-API entry points.
// Zero-dot bare names (e.g. "hashpw") and symbols containing spaces, parentheses,
// slashes, or quotes are always rejected.
//
// For all other ecosystems (Java and the default): requires >= 2 dots so that
// short JCA-style names like "Cipher.getInstance" (Type 1) are excluded while
// deep Java FQNs like "com.password4j.HashBuilder.withBcrypt" qualify.
func isQualifiedMethodSymbol(s, ecosystem string) bool {
	if s == "" || strings.ContainsAny(s, " ()/\"") {
		return false
	}
	minDots := 2
	if ecosystem == ecosystemPython {
		minDots = 1
	}
	return strings.Count(s, ".") >= minDots
}

// stringifyCryptoBlock renders a metadata.crypto block as map[string]string,
// matching how detection-rule metadata lands in finding metadata.
func stringifyCryptoBlock(crypto map[string]any) map[string]string {
	md := make(map[string]string, len(crypto))
	for k, v := range crypto {
		if v == nil {
			continue
		}
		md[k] = fmt.Sprintf("%v", v)
	}
	return md
}

// expandRuleFiles returns the YAML rule files for a path that may be a file or a
// directory.
func expandRuleFiles(path string) []string {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		return []string{path}
	}
	var files []string
	if err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip unreadable entries, keep walking
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext == extYAML || ext == extYML {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("failed to walk rule directory")
	}
	return files
}

// languageForPath maps a source file extension to the report Language tag.
func languageForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case "." + languageJava:
		return languageJava
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".rs":
		return "rust"
	case ".c", ".h":
		return "c"
	case ".cs":
		return "csharp"
	default:
		return ""
	}
}
