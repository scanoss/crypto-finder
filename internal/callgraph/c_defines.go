package callgraph

import (
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	cNodePreprocDef         = "preproc_def"
	cNodePreprocFunctionDef = "preproc_function_def"
)

// cDefine is an object-like #define whose replacement list is one integer or
// string literal.
type cDefine struct {
	value string
	line  int
	// until, when set, is the line of the including file's own define or
	// #undef of the same name: from there the header's value no longer holds.
	until int
}

// cDefines is everything a file's call arguments can resolve against: its own
// literal defines and the defines of the local headers it includes.
type cDefines struct {
	own      map[string]cDefine
	ownTouch map[string]int
	includes *cIncludeScope
	// unresolved are the lines of the file's quoted includes that name no file.
	unresolved cUnresolved
}

// resolve returns the define name denotes at line. A name any local header also
// defines is decided by the header alone, and only when exactly one included
// file touches it.
func (d *cDefines) resolve(name string, line int) (cDefine, bool) {
	if d == nil {
		return cDefine{}, false
	}
	define, ok := d.own[name]
	if d.includes != nil {
		if touches := d.includes.touches(name); touches > 0 {
			define, ok = d.includes.literal(name, d.ownTouch[name])
		}
	}
	if !ok || define.line >= line || (define.until != 0 && line >= define.until) || d.unresolved.kills(define.line, line) {
		return cDefine{}, false
	}
	return define, true
}

var (
	cIntegerReplacement = regexp.MustCompile(`^\(?\s*(\d+)[uUlL]*\s*\)?$`)
	cStringReplacement  = regexp.MustCompile(`^"(?:[^"\\\n]|\\.)*"$`)
	cTrailingComment    = regexp.MustCompile(`\s*(//.*|/\*.*\*/)\s*$`)
)

// cDefineScan is what one file says about macro names.
type cDefineScan struct {
	// literals are the file's unconditional, uniquely defined literal macros.
	literals map[string]cDefine
	// touched maps every name the file defines, redefines or #undefs, in any
	// way and under any condition, to the first line that does.
	touched map[string]int
}

// collectCDefines indexes the file's object-like literal #defines by name. A
// name that is defined more than once, redefined as a function-like macro, or
// #undef'd anywhere in the file is left out, and so is a define inside any
// conditional block (#if, #ifdef, #ifndef, #elif, #else): whether it holds, or
// whether -DNAME overrides it, is decided at build time, and no value beats a
// wrong one. A whole-file include guard does not count as a conditional.
func collectCDefines(root *sitter.Node, src []byte) cDefineScan {
	counts := make(map[string]int)
	literals := make(map[string]cDefine)
	touched := make(map[string]int)
	touch := func(name string, n *sitter.Node) {
		line := int(n.StartPoint().Row) + 1
		if first, ok := touched[name]; !ok || line < first {
			touched[name] = line
		}
	}
	guard := cIncludeGuard(root, src)
	guardName := ""
	if guard != nil {
		guardName = guard.ChildByFieldName("name").Content(src)
	}
	walkCNodes(root, func(n *sitter.Node) {
		name := cMacroName(n, src)
		if name == "" {
			return
		}
		counts[name] += cMacroWeight(n.Type())
		touch(name, n)
		if n.Type() != cNodePreprocDef {
			return
		}
		// A file that is only `#ifndef X / #define X v / #endif` is an
		// overridable default, not a guard around other content.
		if value, ok := cLiteralReplacement(n.ChildByFieldName("value"), src); ok && !cConditional(n, guard) && name != guardName {
			literals[name] = cDefine{value: value, line: int(n.StartPoint().Row) + 1}
		}
	})

	for name := range literals {
		if counts[name] != 1 {
			delete(literals, name)
		}
	}
	return cDefineScan{literals: literals, touched: touched}
}

// cMacroName is the macro a #define, function-like #define or #undef node
// names, or "" for any other node.
func cMacroName(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case cNodePreprocDef, cNodePreprocFunctionDef:
		if name := n.ChildByFieldName("name"); name != nil {
			return name.Content(src)
		}
	case "preproc_call":
		return cUndefName(n, src)
	}
	return ""
}

// cMacroWeight is how much a directive counts against a name staying a single
// literal definition: an #undef alone disqualifies it.
func cMacroWeight(nodeType string) int {
	if nodeType == "preproc_call" {
		return 2
	}
	return 1
}

func cLiteralReplacement(value *sitter.Node, src []byte) (string, bool) {
	if value == nil {
		return "", false
	}
	text := strings.TrimSpace(cTrailingComment.ReplaceAllString(value.Content(src), ""))
	if m := cIntegerReplacement.FindStringSubmatch(text); m != nil {
		if len(m[1]) > 1 && m[1][0] == '0' {
			return "", false
		}
		return m[1], true
	}
	if cStringReplacement.MatchString(text) {
		return text, true
	}
	return "", false
}

// cArgumentSources traces each argument of a call that is a bare identifier
// naming a literal #define earlier in the file or in a local header
// included earlier. The result is parallel to the
// call's arguments and nil when none resolves.
func cArgumentSources(call *sitter.Node, src []byte, defines *cDefines) [][]SourceNode {
	args := call.ChildByFieldName("arguments")
	if args == nil || defines == nil || (len(defines.own) == 0 && defines.includes == nil) {
		return nil
	}
	callLine := int(call.StartPoint().Row) + 1
	sources := make([][]SourceNode, 0, int(args.NamedChildCount()))
	resolved := false
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		if arg.Type() == "comment" {
			continue
		}
		var nodes []SourceNode
		if arg.Type() == cNodeIdentifier {
			name := arg.Content(src)
			if define, ok := defines.resolve(name, callLine); ok {
				nodes = []SourceNode{{
					Type:        "VARIABLE",
					Name:        name,
					SourceNodes: []SourceNode{{Type: "VALUE", Value: define.value}},
				}}
				resolved = true
			}
		}
		sources = append(sources, nodes)
	}
	if !resolved {
		return nil
	}
	return sources
}

func walkCNodes(n *sitter.Node, visit func(*sitter.Node)) {
	visit(n)
	for i := 0; i < int(n.ChildCount()); i++ {
		walkCNodes(n.Child(i), visit)
	}
}

func cUndefName(n *sitter.Node, src []byte) string {
	directive := n.ChildByFieldName("directive")
	argument := n.ChildByFieldName("argument")
	if directive == nil || argument == nil || strings.TrimSpace(directive.Content(src)) != "#undef" {
		return ""
	}
	return strings.TrimSpace(argument.Content(src))
}

// cConditional reports whether a define sits under a conditional-compilation
// directive other than the file's include guard.
func cConditional(n, guard *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef", "preproc_else":
			if guard == nil || !p.Equal(guard) {
				return true
			}
		}
	}
	return false
}

// cIncludeGuard returns the #ifndef that wraps the whole file in the classic
// `#ifndef X / #define X ... #endif` guard, or nil. Only comments may sit
// beside it at the top level, and it must have no #else or #elif branch.
func cIncludeGuard(root *sitter.Node, src []byte) *sitter.Node {
	var guard *sitter.Node
	for i := 0; i < int(root.NamedChildCount()); i++ {
		n := root.NamedChild(i)
		if n.Type() == "comment" {
			continue
		}
		if guard != nil || n.Type() != "preproc_ifdef" {
			return nil
		}
		guard = n
	}
	if guard == nil || guard.ChildByFieldName("alternative") != nil || !cIsIfndef(guard) {
		return nil
	}
	name := guard.ChildByFieldName("name")
	for i := 0; i < int(guard.NamedChildCount()); i++ {
		c := guard.NamedChild(i)
		if c.Type() == cNodePreprocDef {
			if defined := c.ChildByFieldName("name"); name != nil && defined != nil && defined.Content(src) == name.Content(src) {
				return guard
			}
			return nil
		}
	}
	return nil
}

func cIsIfndef(n *sitter.Node) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); !c.IsNamed() && c.Type() == "#ifndef" {
			return true
		}
	}
	return false
}
