package callgraph

import (
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// cDefine is an object-like #define whose replacement list is one integer or
// string literal.
type cDefine struct {
	value string
	line  int
}

var (
	cIntegerReplacement = regexp.MustCompile(`^\(?\s*(\d+)[uUlL]*\s*\)?$`)
	cStringReplacement  = regexp.MustCompile(`^"(?:[^"\\\n]|\\.)*"$`)
	cTrailingComment    = regexp.MustCompile(`\s*(//.*|/\*.*\*/)\s*$`)
)

// collectCDefines indexes the file's object-like literal #defines by name. A
// name that is defined more than once, redefined as a function-like macro, or
// #undef'd anywhere in the file is left out: which definition a call sees
// depends on conditional compilation, and no value beats a wrong one.
func collectCDefines(root *sitter.Node, src []byte) map[string]cDefine {
	counts := make(map[string]int)
	literals := make(map[string]cDefine)
	walkCNodes(root, func(n *sitter.Node) {
		switch n.Type() {
		case "preproc_def":
			if name := n.ChildByFieldName("name"); name != nil {
				key := name.Content(src)
				counts[key]++
				if value, ok := cLiteralReplacement(n.ChildByFieldName("value"), src); ok {
					literals[key] = cDefine{value: value, line: int(n.StartPoint().Row) + 1}
				}
			}
		case "preproc_function_def":
			if name := n.ChildByFieldName("name"); name != nil {
				counts[name.Content(src)]++
			}
		case "preproc_call":
			if name := cUndefName(n, src); name != "" {
				counts[name] += 2
			}
		}
	})

	for name := range literals {
		if counts[name] != 1 {
			delete(literals, name)
		}
	}
	return literals
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
// naming a literal #define earlier in the file. The result is parallel to the
// call's arguments and nil when none resolves.
func cArgumentSources(call *sitter.Node, src []byte, defines map[string]cDefine) [][]SourceNode {
	args := call.ChildByFieldName("arguments")
	if args == nil || len(defines) == 0 {
		return nil
	}
	callLine := int(call.StartPoint().Row) + 1
	var sources [][]SourceNode
	resolved := false
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		if arg.Type() == "comment" {
			continue
		}
		var nodes []SourceNode
		if arg.Type() == cNodeIdentifier {
			name := arg.Content(src)
			if define, ok := defines[name]; ok && define.line < callLine {
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
