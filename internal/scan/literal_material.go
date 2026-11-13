// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// maxDefaultSignatureLines bounds how many lines of a function's signature
// are read for a parameter's default value.
const maxDefaultSignatureLines = 10

// constantMaterialPatterns recognize, per ecosystem, an argument that is a
// value written in the source rather than computed: a bytes or string
// literal, a zero-filled buffer of a literal size, and the like. Such a value
// at a salt, iv or nonce argument is that material, fixed in the program.
var constantMaterialPatterns = map[string][]*regexp.Regexp{
	ecosystemPython: {
		// b'...', rb"...", optionally repeated: b' ' * 16, b'\x00' * 16.
		regexp.MustCompile(`^(?:[bB][rR]?|[rR][bB])(?:'[^']*'|"[^"]*")(?:\s*\*\s*\d+)?$`),
		// 'text'.encode() and "text".encode('utf-8').
		regexp.MustCompile(`^(?:'[^']*'|"[^"]*")\.encode\(\s*(?:'[^']*'|"[^"]*")?\s*\)$`),
		// bytes(16), bytearray(16), bytes.fromhex('00ff').
		regexp.MustCompile(`^(?:bytes|bytearray)\(\s*\d+\s*\)$`),
		regexp.MustCompile(`^bytes\.fromhex\(\s*(?:'[0-9a-fA-F\s]*'|"[0-9a-fA-F\s]*")\s*\)$`),
	},
	ecosystemNode: {
		// 'text', "text", `text` without interpolation.
		regexp.MustCompile("^(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)$"),
		// Buffer.alloc(16), Buffer.alloc(16, 0), Buffer.from('text'), Buffer.from('00ff', 'hex').
		regexp.MustCompile(`^Buffer\.alloc\(\s*\d+\s*(?:,\s*(?:\d+|'[^']*'|"[^"]*")\s*)?\)$`),
		regexp.MustCompile(`^Buffer\.from\(\s*(?:'[^']*'|"[^"]*")\s*(?:,\s*(?:'[^']*'|"[^"]*")\s*)?\)$`),
		regexp.MustCompile(`^new\s+Uint8Array\(\s*\d+\s*\)$`),
	},
}

// materializeLiterals reports the related crypto material a constant value
// becomes when it reaches an argument the contract of a reported crypto call
// marks as material: written at the call itself (`createCipheriv(alg, key,
// Buffer.alloc(16))`), passed by a caller to the parameter the call reads
// (`pbkdf2_sha1(password, salt=b'saltysalt')` into a helper calling
// `hashlib.pbkdf2_hmac`), through up to maxMaterialHops application calls, or
// given as that parameter's default value. The asset sits at the constant,
// with the crypto call's rule. A parameter the function may rebind before the
// call is not followed, and a line that already holds that material is left
// alone.
func (t *materialTracer) materializeLiterals(report *entities.InterimReport) int {
	patterns := constantMaterialPatterns[t.ecosystem]
	if len(patterns) == 0 {
		return 0
	}
	l := &literalTracer{materialTracer: t, report: report, patterns: patterns, seen: map[*callgraph.FunctionCall]bool{}}
	for i := 0; i < len(report.Findings); i++ {
		path, language := report.Findings[i].FilePath, report.Findings[i].Language
		consumers := len(report.Findings[i].CryptographicAssets)
		for j := 0; j < consumers; j++ {
			asset := report.Findings[i].CryptographicAssets[j]
			if asset.DependencyInfo != nil || asset.Metadata[metadataAssetType] == assetTypeRelatedMaterial {
				continue
			}
			l.fromAsset(path, language, asset)
		}
	}
	return l.added
}

type literalTracer struct {
	*materialTracer
	report   *entities.InterimReport
	patterns []*regexp.Regexp
	// seen holds the crypto calls already read, so two assets on one call
	// report its material once.
	seen  map[*callgraph.FunctionCall]bool
	added int
}

// literalConsumer is the reported crypto call a constant is material of.
type literalConsumer struct {
	asset    entities.CryptographicAsset
	language string
}

// fromAsset follows the material arguments of the crypto call asset reports.
func (l *literalTracer) fromAsset(findingPath, language string, asset entities.CryptographicAsset) {
	fn := l.ctx.findContainingFunctionByFinding(findingPath, nil, asset.StartLine, asset.StartCol)
	if fn == nil {
		return
	}
	call := findCryptoCallNode(l.ctx.graph, fn, asset, asset.StartLine, asset.EndLine)
	if call == nil {
		return
	}
	consumer := &literalConsumer{asset: asset, language: language}
	for _, c := range []*callgraph.FunctionCall{call, matchedLink(fn, call, asset)} {
		if l.seen[c] {
			continue
		}
		l.seen[c] = true
		matches := contractMatchesForCall(l.ctx, c, len(c.Arguments))
		if len(matches) == 0 {
			continue
		}
		for index, arg := range c.Arguments {
			keyword, value := splitKeywordArgument(arg, l.ecosystem)
			if material := agreedMaterial(matches, index, keyword); material != "" {
				l.source(fn, c, value, material, consumer, 0)
			}
		}
	}
}

// source reports value as material when it is a constant, or follows it to
// the default and the callers' arguments of the parameter it names.
func (l *literalTracer) source(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall, value, material string, consumer *literalConsumer, hops int) {
	value = strings.TrimSpace(value)
	if l.constant(value) {
		l.addMaterial(fn, call.Line, call.StartCol, value, material, consumer)
		return
	}
	name := bareArgument(value, l.ecosystem)
	if !isSimpleIdentifier(name) || name == pythonSelfParameter {
		return
	}
	position := -1
	for i := range fn.Parameters {
		if fn.Parameters[i].Name == name {
			position = i
			break
		}
	}
	if position < 0 || l.rebound(fn, name, fn.StartLine, call.Line) {
		return
	}
	if line, col, def := l.parameterDefault(fn, name); def != "" && l.constant(def) {
		l.addMaterial(fn, line, col, def, material, consumer)
	}
	if hops < maxMaterialHops {
		l.followCallers(fn, position, name, material, consumer, hops)
	}
}

// followCallers follows the argument every caller of fn passes to its
// parameter name at position.
func (l *literalTracer) followCallers(fn *callgraph.FunctionDecl, position int, name, material string, consumer *literalConsumer, hops int) {
	id := fn.ID.String()
	for _, callerID := range l.ctx.graph.Callers[id] {
		caller := l.ctx.graph.Functions[callerID]
		if caller == nil {
			continue
		}
		for i := range caller.Calls {
			c := &caller.Calls[i]
			if c.Callee.String() != id {
				continue
			}
			if arg := l.passedArgument(fn, c, position, name); arg != "" {
				l.source(caller, c, arg, material, consumer, hops+1)
			}
		}
	}
}

// passedArgument is the argument call passes to callee's parameter name at
// position: by keyword, or by position after the receiver the call binds
// implicitly. Empty when it cannot be told, as with a spread argument.
func (l *literalTracer) passedArgument(callee *callgraph.FunctionDecl, call *callgraph.FunctionCall, position int, name string) string {
	offset, ok := l.receiverOffset(callee, call)
	if !ok {
		return ""
	}
	for i, arg := range call.Arguments {
		if strings.HasPrefix(strings.TrimSpace(arg), "*") || strings.HasPrefix(strings.TrimSpace(arg), "...") {
			return ""
		}
		keyword, value := splitKeywordArgument(arg, l.ecosystem)
		if keyword != "" {
			if keyword == name {
				return value
			}
			continue
		}
		if i+offset == position {
			return value
		}
	}
	return ""
}

func (l *literalTracer) constant(value string) bool {
	for _, re := range l.patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// parameterDefault reads the default value the signature of fn gives
// parameter name (`salt=b'saltysalt'`, `iv = Buffer.alloc(16)`), with its
// line and 1-based column. Empty when it has none or the signature cannot be
// read.
func (l *literalTracer) parameterDefault(fn *callgraph.FunctionDecl, name string) (line, col int, value string) {
	file := l.ctx.excerpts().file(l.ctx.absPath(fn.FilePath))
	if file.unavailable != "" {
		return 0, 0, ""
	}
	re := regexp.MustCompile(`(?:^|[(,\s])` + regexp.QuoteMeta(name) + `\s*(?::[^=,()]*)?=\s*`)
	last := min(fn.StartLine+maxDefaultSignatureLines, fn.EndLine, len(file.lineStarts))
	for n := fn.StartLine; n > 0 && n <= last; n++ {
		text := string(file.line(n))
		if m := re.FindStringIndex(text); m != nil {
			v := argumentText(text[m[1]:])
			return n, m[1] + 1, v
		}
		if strings.Contains(text, ")") {
			return 0, 0, ""
		}
	}
	return 0, 0, ""
}

// argumentText is the leading argument of text: up to the first comma or
// closing bracket outside quotes and brackets.
func argumentText(text string) string {
	depth := 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case '\'', '"', '`':
			i = closingQuote(text, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}', ',':
			if depth == 0 {
				return strings.TrimSpace(text[:i])
			}
			if c != ',' {
				depth--
			}
		}
	}
	return strings.TrimSpace(text)
}

// closingQuote is the index of the quote closing the one at open, or the
// end of text.
func closingQuote(text string, open int) int {
	for i := open + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case text[open]:
			return i
		}
	}
	return len(text)
}

// addMaterial adds the material asset for value, which a call (or a
// signature) writes at line from column col on, to the finding of fn's file.
func (l *literalTracer) addMaterial(fn *callgraph.FunctionDecl, line, col int, value, material string, consumer *literalConsumer) {
	line, col = l.locate(fn, line, col, value)
	finding := l.findingFor(fn, consumer.language)
	if finding == nil {
		return
	}
	for i := range finding.CryptographicAssets {
		a := &finding.CryptographicAssets[i]
		if a.Metadata[metadataAssetType] == assetTypeRelatedMaterial && a.Metadata[metadataMaterialType] == material &&
			a.StartLine <= line && line <= a.EndLine {
			return
		}
	}
	asset := relatedMaterialAsset(consumer.asset, material)
	asset.StartLine, asset.EndLine = line, line
	asset.StartCol, asset.EndCol = 0, 0
	if col > 0 {
		asset.StartCol, asset.EndCol = col, col+len(value)
	}
	asset.TerminalStartCol, asset.TerminalEndCol = 0, 0
	asset.Match = value
	finding.CryptographicAssets = append(finding.CryptographicAssets, asset)
	l.added++
}

// locate finds value in the source from line and column col on: a call's
// arguments may continue on the lines after its start. It keeps line, with
// no column, when the text is not found within the function.
func (l *literalTracer) locate(fn *callgraph.FunctionDecl, line, col int, value string) (int, int) {
	file := l.ctx.excerpts().file(l.ctx.absPath(fn.FilePath))
	if file.unavailable != "" {
		return line, 0
	}
	last := min(fn.EndLine, len(file.lineStarts))
	for n := line; n > 0 && n <= last; n++ {
		text := string(file.line(n))
		from := 0
		if n == line && col > 1 && col-1 <= len(text) {
			from = col - 1
		}
		if i := strings.Index(text[from:], value); i >= 0 {
			return n, from + i + 1
		}
	}
	return line, 0
}

// findingFor is the finding of fn's file, added in language when the file
// has none. Nil for a file outside the project.
func (l *literalTracer) findingFor(fn *callgraph.FunctionDecl, language string) *entities.Finding {
	abs := l.ctx.absPath(fn.FilePath)
	for i := range l.report.Findings {
		f := &l.report.Findings[i]
		if file, ok := l.ctx.findingFile(f.FilePath, nil); ok && file == abs {
			return f
		}
	}
	rel, ok := relativeToRoot(l.ctx.absPath(l.ctx.projectRoot), abs)
	if !ok {
		return nil
	}
	l.report.Findings = append(l.report.Findings, entities.Finding{FilePath: filepath.ToSlash(rel), Language: language})
	return &l.report.Findings[len(l.report.Findings)-1]
}

// matchedLink is the call the asset's rule matched: the tightest call on its
// line whose span holds the asset's, when it is a link of call's own chain,
// as `createHash('sha256')` in `createHash('sha256').update(x).digest()`.
// Otherwise call itself.
func matchedLink(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall, asset entities.CryptographicAsset) *callgraph.FunctionCall {
	if call.ChainID == "" {
		return call
	}
	candidates := cryptoCallLineCandidates(fn, asset.StartLine, asset.EndLine)
	i := tightestContainingIndexAmong(callCandidateViews(candidates), asset.StartCol, asset.EndCol)
	if i < 0 || candidates[i].ChainID != call.ChainID {
		return call
	}
	return candidates[i]
}
