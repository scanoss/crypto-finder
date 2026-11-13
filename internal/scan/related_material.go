// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	// maxMaterialHops bounds how many application calls a drawn value is
	// followed through before the trail is dropped.
	maxMaterialHops = 3

	drbgPrimitive               = "drbg"
	assetTypeRelatedMaterial    = "related-crypto-material"
	metadataMaterialType        = "materialType"
	metadataAssetType           = "assetType"
	metadataAlgorithmPrimitive  = "algorithmPrimitive"
	pythonSelfParameter         = "self"
	pythonClassMethodParameter  = "cls"
	rustMutableBorrowPrefix     = "&mut "
	rustSharedBorrowPrefix      = "&"
	rustSomeWrapperPrefix       = "Some("
	rustIntoConversion          = ".into()"
	materialArgumentKeywordSign = "="
)

// MaterializeRelatedMaterial reports the related crypto material a random
// draw produces when the drawn value reaches a contract parameter with a
// material role in another function. `salt = os.urandom(16)` handed to a
// helper that calls `PBKDF2HMAC(salt=salt)` adds a salt asset at the draw.
//
// A draw is an asset whose rule names the drbg primitive. Its value is the
// variable the call's result is bound to, or a plain-identifier argument the
// call fills (`rand.Read(buf)`, `random.nextBytes(iv)`). The value is followed
// through the calls that take it as an argument, into application callees
// (mapped onto the receiving parameter) up to maxMaterialHops calls deep,
// until a call whose contract declares a material role at that argument. The
// trail is dropped, and nothing is reported, when the callee does not resolve
// to one function, the variable may be rebound or overwritten before the use,
// the argument is an expression rather than the variable, or the contracts
// that match the call disagree. A material the finding already reports at the
// draw is not added again.
//
// It then reports the material a constant becomes (materializeLiterals): a
// salt, iv or nonce argument of a reported crypto call written as a literal,
// or reaching it as a parameter's default or a caller's literal argument.
//
// result supplies the call graph and its ecosystem; report is the report the
// assets are added to. It returns the number of assets added.
func MaterializeRelatedMaterial(report *entities.InterimReport, result *engine.DepScanResult) int {
	if report == nil || result == nil || result.CallGraph == nil {
		return 0
	}
	kb, err := contracts.LoadEmbedded(result.Ecosystem)
	if err != nil || kb == nil {
		return 0
	}
	scoped := *result
	scoped.Report = report
	ctx := newExportPathContext(&scoped)
	ctx.kb = kb
	tracer := &materialTracer{ctx: ctx, ecosystem: result.Ecosystem, rebinders: map[string][]*regexp.Regexp{}}
	added := 0
	for i := range report.Findings {
		added += tracer.materializeFinding(&report.Findings[i])
	}
	added += tracer.materializeLiterals(report)
	if added > 0 {
		log.Info().Int("count", added).Str("ecosystem", result.Ecosystem).Msg("Reported related crypto material followed from random draws")
	}
	return added
}

type materialTracer struct {
	ctx       *exportBuildContext
	ecosystem string
	// rebinders caches the patterns that recognize a rebinding of one name.
	rebinders map[string][]*regexp.Regexp
}

func (t *materialTracer) materializeFinding(finding *entities.Finding) int {
	added := 0
	draws := slices.Clone(finding.CryptographicAssets)
	for i := range draws {
		draw := draws[i]
		if draw.Metadata[metadataAlgorithmPrimitive] != drbgPrimitive {
			continue
		}
		for _, material := range t.drawnMaterials(finding, draw) {
			if materialReportedAt(finding, draw, material) {
				continue
			}
			finding.CryptographicAssets = append(finding.CryptographicAssets, relatedMaterialAsset(draw, material))
			added++
		}
	}
	return added
}

// drawnMaterials returns, sorted, the material roles the value a draw produces
// reaches.
func (t *materialTracer) drawnMaterials(finding *entities.Finding, draw entities.CryptographicAsset) []string {
	fn := t.ctx.findContainingFunctionByFinding(finding.FilePath, draw.DependencyInfo, draw.StartLine, draw.StartCol)
	if fn == nil {
		return nil
	}
	call := findCryptoCallNode(t.ctx.graph, fn, draw, draw.StartLine, draw.EndLine)
	if call == nil {
		return nil
	}
	found := map[string]bool{}
	visited := map[string]bool{}
	after := codePosition{line: call.Line, col: call.EndCol}
	for _, name := range drawnNames(call, t.ecosystem, filledLink(fn, call, draw)) {
		t.trace(fn, name, after, 0, found, visited)
	}
	t.traceNestedDraw(fn, call, found, visited)
	materials := make([]string, 0, len(found))
	for material := range found {
		materials = append(materials, material)
	}
	sort.Strings(materials)
	return materials
}

// randomFillBuffer maps the name of a call that fills a caller's buffer with
// random bytes to the position of that buffer: Go `rand.Read(b)` and
// `io.ReadFull(rand.Reader, b)`, Java `nextBytes(b)`, Rust `fill_bytes(&mut b)`,
// `try_fill_bytes`, `fill`, `try_fill`, `getrandom` and OpenSSL `rand_bytes`,
// Node `randomFillSync(b)`, `randomFill(b, cb)` and `getRandomValues(b)`. Any
// other draw's arguments are inputs (a size, or a seed as in `setSeed(seed)`),
// never the drawn value.
var randomFillBuffer = map[string]int{
	"Read":            0,
	"ReadFull":        1,
	"nextBytes":       0,
	"fill_bytes":      0,
	"try_fill_bytes":  0,
	"fill":            0,
	"try_fill":        0,
	"getrandom":       0,
	"rand_bytes":      0,
	"randomFillSync":  0,
	"randomFill":      0,
	"getRandomValues": 0,
}

// drawnNames are the variables that may hold a draw's value: the one its
// result is bound to, and the buffer a filling draw (randomFillBuffer) writes.
// A bound name that is not the drawn value (the `err` of Go's rand.Read, a
// generator `new SecureRandom(seed)` returns) reaches no material role.
//
// filler is the call that fills the buffer; it differs from call when the
// draw is the first link of a chain the statement continues, as in Rust
// `getrandom::fill(&mut nonce).unwrap()`, whose terminal is `unwrap`.
func drawnNames(call *callgraph.FunctionCall, ecosystem string, filler *callgraph.FunctionCall) []string {
	var names []string
	if isSimpleIdentifier(call.AssignedVar) {
		names = append(names, call.AssignedVar)
	}
	index, fills := randomFillBuffer[callgraph.BaseFunctionName(filler.Callee.Name)]
	if !fills || index >= len(filler.Arguments) {
		return names
	}
	if name := bareArgument(filler.Arguments[index], ecosystem); isSimpleIdentifier(name) && !slices.Contains(names, name) {
		names = append(names, name)
	}
	return names
}

// filledLink is the call the rule of draw (any reported asset) matched: the
// tightest call on its line whose span holds its span, or call itself when
// the spans cannot tell. A link of call's own chain only, so a draw nested in another
// call's argument stays with traceNestedDraw.
func filledLink(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall, draw entities.CryptographicAsset) *callgraph.FunctionCall {
	if call.ChainID == "" {
		return call
	}
	candidates := cryptoCallLineCandidates(fn, draw.StartLine, draw.EndLine)
	i := tightestContainingIndexAmong(callCandidateViews(candidates), draw.StartCol, draw.EndCol)
	if i < 0 || candidates[i].ChainID != call.ChainID {
		return call
	}
	return candidates[i]
}

// codePosition is a point in a file: a call at it or after it is a use.
type codePosition struct {
	line int
	col  int
}

func (p codePosition) before(call *callgraph.FunctionCall) bool {
	if call.Line != p.line {
		return call.Line > p.line
	}
	return p.col > 0 && call.StartCol >= p.col
}

// trace follows name from the position after in fn and records in found the
// material role of every contract argument it reaches.
func (t *materialTracer) trace(fn *callgraph.FunctionDecl, name string, after codePosition, hops int, found, visited map[string]bool) {
	key := fn.ID.String() + "\x00" + name
	if visited[key] {
		return
	}
	visited[key] = true
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if !after.before(call) {
			continue
		}
		for index, arg := range call.Arguments {
			keyword, value := splitKeywordArgument(arg, t.ecosystem)
			if bareArgument(value, t.ecosystem) != name {
				continue
			}
			if t.rebound(fn, name, after.line, call.Line) {
				continue
			}
			t.followArgument(call, index, keyword, hops, found, visited)
		}
	}
}

// traceNestedDraw handles a draw written as the argument itself:
// `aead.Seal(nil, os.urandom(12), ...)`, or a helper called with it.
func (t *materialTracer) traceNestedDraw(fn *callgraph.FunctionDecl, draw *callgraph.FunctionCall, found, visited map[string]bool) {
	if draw.Raw == "" {
		return
	}
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call == draw || call.Line != draw.Line || !callSpanEncloses(call, draw) {
			continue
		}
		index, keyword := -1, ""
		for j, arg := range call.Arguments {
			kw, value := splitKeywordArgument(arg, t.ecosystem)
			if !strings.HasPrefix(strings.TrimSpace(value), draw.Raw+"(") {
				continue
			}
			if index >= 0 {
				return // two arguments draw: which one is this draw is unknown
			}
			index, keyword = j, kw
		}
		if index >= 0 {
			t.followArgument(call, index, keyword, 0, found, visited)
		}
	}
}

func callSpanEncloses(outer, inner *callgraph.FunctionCall) bool {
	if outer.StartCol <= 0 || outer.EndCol <= 0 || inner.StartCol <= 0 || inner.EndCol <= 0 {
		return false
	}
	return outer.StartCol <= inner.StartCol && inner.EndCol <= outer.EndCol && (outer.StartCol != inner.StartCol || outer.EndCol != inner.EndCol)
}

// followArgument records the material role a call's contract declares at an
// argument, or follows the argument into the application function the call
// resolves to.
func (t *materialTracer) followArgument(call *callgraph.FunctionCall, index int, keyword string, hops int, found, visited map[string]bool) {
	matches := contractMatchesForCall(t.ctx, call, len(call.Arguments))
	if len(matches) > 0 {
		if material := agreedMaterial(matches, index, keyword); material != "" {
			found[material] = true
		}
		return
	}
	if hops >= maxMaterialHops {
		return
	}
	callee := t.ctx.graph.Functions[call.Callee.String()]
	if callee == nil {
		return
	}
	parameter := t.receivingParameter(callee, call, index, keyword)
	if parameter == "" {
		return
	}
	t.trace(callee, parameter, codePosition{line: callee.StartLine}, hops+1, found, visited)
}

// agreedMaterial is the material role every matching contract declares at the
// argument; empty when one of them declares none or they disagree.
func agreedMaterial(matches []contracts.Contract, index int, keyword string) string {
	material := ""
	for i := range matches {
		m := matches[i].MaterialAt(index, keyword)
		if m == "" || (material != "" && m != material) {
			return ""
		}
		material = m
	}
	return material
}

// receivingParameter is the name of the callee parameter that receives the
// argument at index (or the keyword argument keyword). Empty when it cannot be
// told: a variadic tail, an unnamed parameter, or an explicit `Class.method(obj,
// ...)` call that passes Python's self positionally.
func (t *materialTracer) receivingParameter(callee *callgraph.FunctionDecl, call *callgraph.FunctionCall, index int, keyword string) string {
	params := callee.Parameters
	if keyword != "" {
		for i := range params {
			if params[i].Name == keyword {
				return keyword
			}
		}
		return ""
	}
	offset, ok := t.receiverOffset(callee, call)
	at := index + offset
	if !ok || at >= len(params) {
		return ""
	}
	name := params[at].Name
	if !isSimpleIdentifier(name) || name == pythonSelfParameter {
		return ""
	}
	return name
}

// receiverOffset is how many leading callee parameters the call passes
// implicitly: a Python or Rust method's self (or a classmethod's cls) is
// declared but bound by the receiver. ok is false for an explicit
// `Class.method(obj, ...)` Python call, which passes self positionally.
func (t *materialTracer) receiverOffset(callee *callgraph.FunctionDecl, call *callgraph.FunctionCall) (offset int, ok bool) {
	params := callee.Parameters
	if len(params) == 0 || (params[0].Name != pythonSelfParameter && params[0].Name != pythonClassMethodParameter) {
		return 0, true
	}
	receiver, _, dotted := strings.Cut(call.Raw, ".")
	if t.ecosystem == ecosystemPython && dotted && receiver == callee.ID.Type && params[0].Name == pythonSelfParameter {
		return 0, false
	}
	if dotted || t.ecosystem == ecosystemPython {
		return 1, true
	}
	return 0, true
}

// splitKeywordArgument splits a Python keyword argument `salt=value` into its
// keyword and value. Other ecosystems and positional arguments return an
// empty keyword and the argument unchanged.
func splitKeywordArgument(arg, ecosystem string) (keyword, value string) {
	if ecosystem != ecosystemPython {
		return "", arg
	}
	if m := pythonKeywordArgumentPattern.FindStringSubmatch(strings.TrimSpace(arg)); len(m) == 3 && !strings.HasPrefix(m[2], materialArgumentKeywordSign) {
		return m[1], strings.TrimSpace(m[2])
	}
	return "", arg
}

// bareArgument strips the borrow, Option wrapping and `.into()` conversion a
// Rust argument passes a variable with (`&mut nonce`, `&iv`, `Some(&salt)`,
// `(&nonce).into()`), so the variable itself is compared. `.into()` changes
// the type the bytes are held in, as a nonce array into a GenericArray, not
// the bytes.
func bareArgument(arg, ecosystem string) string {
	arg = strings.TrimSpace(arg)
	if ecosystem != ecosystemRust {
		return arg
	}
	if strings.HasPrefix(arg, rustSomeWrapperPrefix) && strings.HasSuffix(arg, ")") {
		arg = strings.TrimSpace(arg[len(rustSomeWrapperPrefix) : len(arg)-1])
	}
	arg = strings.TrimSuffix(arg, rustIntoConversion)
	if strings.HasPrefix(arg, "(") && strings.HasSuffix(arg, ")") {
		arg = strings.TrimSpace(arg[1 : len(arg)-1])
	}
	arg = strings.TrimPrefix(arg, rustMutableBorrowPrefix)
	return strings.TrimSpace(strings.TrimPrefix(arg, rustSharedBorrowPrefix))
}

// rebound reports whether any source line of fn strictly between from and to
// may rebind or overwrite name, or whether those lines cannot be read. The
// check is lexical and errs towards "rebound": a missed material is
// acceptable, a wrong one is not.
func (t *materialTracer) rebound(fn *callgraph.FunctionDecl, name string, from, to int) bool {
	if to <= from+1 {
		return false
	}
	file := t.ctx.excerpts().file(t.ctx.absPath(fn.FilePath))
	if file.unavailable != "" || to-1 > len(file.lineStarts) {
		return true
	}
	patterns := t.rebindPatterns(name)
	for line := from + 1; line < to; line++ {
		text := string(file.line(line))
		if isCommentLine(text) {
			continue
		}
		for _, re := range patterns {
			if re.MatchString(text) {
				return true
			}
		}
	}
	return false
}

func isCommentLine(text string) bool {
	trimmed := strings.TrimSpace(text)
	for _, prefix := range []string{"//", "#", "/*", "*"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// rebindPatterns are the shapes of a line that may give name another value or
// overwrite the buffer it holds: an assignment (also compound, indexed, a
// tuple or destructuring target, or Go's :=), a declaration or loop whose
// target is the name (let, var, const, for, as, del; not one that only reads
// it), a mutable borrow, and the standard in-place fills.
func (t *materialTracer) rebindPatterns(name string) []*regexp.Regexp {
	if patterns, ok := t.rebinders[name]; ok {
		return patterns
	}
	n := regexp.QuoteMeta(name)
	word := `(?:^|[^\w.$])` + n
	patterns := []*regexp.Regexp{
		regexp.MustCompile(word + `\s*(?:\[[^\]]*\]\s*)?(?:[-+*/%&|^]|<<|>>|\?\?|:)?=(?:[^=>]|$)`),
		regexp.MustCompile(word + `\s*,[^=]*:?=(?:[^=>]|$)`),
		// The name closing a destructuring target: `(salt, n) = ...`, `[a, iv] = ...`.
		regexp.MustCompile(word + `\s*[)\]][^=()]*:?=(?:[^=>]|$)`),
		// A declaration or binder whose target is the name, not one that only
		// reads it (`let n = Nonce::from_slice(&nonce)` keeps nonce).
		regexp.MustCompile(`\b(?:let(?:\s+mut)?|var|const|as|del)\s+` + n + `\b`),
		regexp.MustCompile(`\bfor\b[^:{]*?` + word + `\b[^:{]*?\b(?:in|of)\b`),
		regexp.MustCompile(`&mut\s+` + n + `\b`),
		regexp.MustCompile(`\bcopy\s*\(\s*` + n + `\b`),
		regexp.MustCompile(word + `\s*\.\s*(?:copy_from_slice|clone_from_slice|fill|fill_bytes|try_fill_bytes|set|write)\s*\(`),
		regexp.MustCompile(`arraycopy\s*\([^)]*,\s*` + n + `\s*,`),
		regexp.MustCompile(`Arrays\s*\.\s*fill\s*\(\s*` + n + `\b`),
	}
	t.rebinders[name] = patterns
	return patterns
}

// materialReportedAt reports whether the finding already holds material of
// this type at the draw's span, as a same-function rule reports it.
func materialReportedAt(finding *entities.Finding, draw entities.CryptographicAsset, material string) bool {
	for i := range finding.CryptographicAssets {
		a := &finding.CryptographicAssets[i]
		if a.Metadata[metadataAssetType] != assetTypeRelatedMaterial || a.Metadata[metadataMaterialType] != material {
			continue
		}
		if a.StartLine > draw.EndLine || draw.StartLine > a.EndLine {
			continue
		}
		if a.StartLine == draw.StartLine && a.StartCol > 0 && draw.StartCol > 0 && a.EndLine == draw.EndLine &&
			(a.StartCol >= draw.EndCol || draw.StartCol >= a.EndCol) {
			continue
		}
		return true
	}
	return false
}

// relatedMaterialAsset is the material asset reported at a draw: the draw's
// span, match and rule, with standard CycloneDX related-material metadata.
func relatedMaterialAsset(draw entities.CryptographicAsset, material string) entities.CryptographicAsset {
	asset := draw
	asset.FindingID = ""
	asset.OccurrenceKey = ""
	asset.OID = ""
	asset.ConditionedValue = ""
	asset.ConditionedValuesIncomplete = false
	asset.ParameterConditions = nil
	asset.Rules = slices.Clone(draw.Rules)
	asset.Metadata = map[string]string{
		metadataAssetType:    assetTypeRelatedMaterial,
		metadataMaterialType: material,
	}
	return asset
}
