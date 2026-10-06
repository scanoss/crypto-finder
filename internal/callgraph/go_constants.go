package callgraph

import (
	"math"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	goNodeConstDeclaration = "const_declaration"
	goNodeConstSpec        = "const_spec"
	goNodeSourceFile       = "source_file"
	goNodeArgumentList     = "argument_list"
	goNodeComment          = "comment"
	goNodeRangeClause      = "range_clause"
	goNodeReceiveStatement = "receive_statement"
	goNodeForClause        = "for_clause"
	goNodeLabeledStatement = "labeled_statement"
	goNodeTypeSwitch       = "type_switch_statement"
	goNodeVariadicParam    = "variadic_parameter_declaration"
	goNodeIntLiteral       = "int_literal"
	goNodeInterpretedStr   = "interpreted_string_literal"
	goNodeRawStr           = "raw_string_literal"
)

// goConstTypes are the declared types a typed const may have and still be read
// as a plain integer or string literal. A float or a named type is not.
var goConstTypes = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "byte": true, "rune": true, "string": true,
}

type goDeclKind int

const (
	// goDeclOpaque is a declaration of the name that yields no literal: a
	// variable, a parameter, or a const without a literal initializer.
	goDeclOpaque goDeclKind = iota
	goDeclLiteral
)

// goDecl is one declaration of a name inside a scope. end is the byte offset
// from which the declaration is in scope; parameters use 0.
type goDecl struct {
	end   uint32
	kind  goDeclKind
	value string
}

// goConstScopes indexes, once per scope node, the names each lexical scope
// declares, so resolving an argument costs the scope depth rather than a scan
// of every enclosing scope's statements. Reset it when the tree is closed.
type goConstScopes struct {
	byScope map[uintptr]map[string][]goDecl
	// crossFile resolves a name no scope of the current file declares against
	// the other files of its package. Nil when the file is parsed alone.
	crossFile func(name string) (string, bool)
}

func (c *goConstScopes) reset() { c.byScope, c.crossFile = nil, nil }

func (c *goConstScopes) index(scope *sitter.Node, src []byte) map[string][]goDecl {
	if c.byScope == nil {
		c.byScope = make(map[uintptr]map[string][]goDecl)
	}
	id := scope.ID()
	if idx, ok := c.byScope[id]; ok {
		return idx
	}
	idx := make(map[string][]goDecl)
	goCollectBoundNames(scope, src, idx)
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		goCollectDecls(scope.NamedChild(i), src, idx)
	}
	c.byScope[id] = idx
	return idx
}

// argumentSources traces each argument of a call expression that is a bare
// identifier naming a Go const initialized with an integer or string literal.
// The result is parallel to the call's arguments and nil when none resolves.
// Every other argument shape stays unresolved.
func (c *goConstScopes) argumentSources(call *sitter.Node, src []byte) [][]SourceNode {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.Type() != goNodeArgumentList {
		return nil
	}
	sources := make([][]SourceNode, 0, int(args.NamedChildCount()))
	resolved := false
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		if arg.Type() == goNodeComment {
			continue
		}
		var nodes []SourceNode
		if arg.Type() == goNodeIdentifier {
			if value, ok := c.lookup(arg, arg.Content(src), src); ok {
				nodes = []SourceNode{{
					Type:        "VARIABLE",
					Name:        arg.Content(src),
					SourceNodes: []SourceNode{{Type: "VALUE", Value: value}},
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

// lookup resolves name at use to the literal of the const it denotes. It walks
// outward through the enclosing scopes; the innermost scope that declares name
// decides, so a shadowed name never inherits an outer const.
func (c *goConstScopes) lookup(use *sitter.Node, name string, src []byte) (string, bool) {
	for child, scope := use, use.Parent(); scope != nil; child, scope = scope, scope.Parent() {
		position := child.StartByte()
		if scope.Type() == goNodeSourceFile {
			position = math.MaxUint32
		}
		var best *goDecl
		decls := c.index(scope, src)[name]
		for i := range decls {
			if decls[i].end <= position && (best == nil || decls[i].end >= best.end) {
				best = &decls[i]
			}
		}
		if best != nil {
			return best.value, best.kind == goDeclLiteral
		}
	}
	if c.crossFile != nil {
		return c.crossFile(name)
	}
	return "", false
}

// goCollectDecls records the names a scope child declares. It looks through the
// clause nodes that hold a binding without opening a scope of their own: the
// init of a for clause, a labeled statement, and a select receive case.
func goCollectDecls(n *sitter.Node, src []byte, idx map[string][]goDecl) {
	switch n.Type() {
	case goNodeConstDeclaration:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			goCollectConstSpec(n.NamedChild(i), src, idx)
		}
	case goNodeVarDeclaration:
		goWalk(n, func(c *sitter.Node) {
			if c.Type() == goNodeVarSpec {
				goAddNames(c, n.EndByte(), src, idx)
			}
		})
	case goNodeShortVarDeclaration, goNodeRangeClause:
		goAddIdentifiers(n.ChildByFieldName(goFieldLeft), n.EndByte(), src, idx)
	case goNodeReceiveStatement:
		if goHasToken(n, ":=") {
			goAddIdentifiers(n.ChildByFieldName(goFieldLeft), n.EndByte(), src, idx)
		}
	case goNodeForClause, goNodeLabeledStatement:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			goCollectDecls(n.NamedChild(i), src, idx)
		}
	}
}

func goCollectConstSpec(spec *sitter.Node, src []byte, idx map[string][]goDecl) {
	if spec.Type() != goNodeConstSpec {
		return
	}
	var names []*sitter.Node
	for i := 0; i < int(spec.ChildCount()); i++ {
		if c := spec.Child(i); c.IsNamed() && spec.FieldNameForChild(i) == javaFieldName {
			names = append(names, c)
		}
	}
	values := spec.ChildByFieldName("value")
	typed := spec.ChildByFieldName(goFieldType)
	literal := values != nil && int(values.NamedChildCount()) == len(names) &&
		(typed == nil || goConstTypes[typed.Content(src)])
	for i, name := range names {
		decl := goDecl{end: spec.EndByte(), kind: goDeclOpaque}
		if literal {
			if text, ok := goLiteralText(values.NamedChild(i), src); ok {
				decl.kind, decl.value = goDeclLiteral, text
			}
		}
		idx[name.Content(src)] = append(idx[name.Content(src)], decl)
	}
}

// goLiteralText returns the text of a plain decimal integer or string literal.
// A leading zero, a base prefix or an underscore changes what the digits mean
// downstream, so those give nothing.
func goLiteralText(n *sitter.Node, src []byte) (string, bool) {
	text := n.Content(src)
	switch n.Type() {
	case goNodeIntLiteral:
		if text == "" || (len(text) > 1 && text[0] == '0') {
			return "", false
		}
		for _, r := range text {
			if r < '0' || r > '9' {
				return "", false
			}
		}
		return text, true
	case goNodeInterpretedStr, goNodeRawStr:
		return text, true
	}
	return "", false
}

func goAddNames(n *sitter.Node, end uint32, src []byte, idx map[string][]goDecl) {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.IsNamed() && n.FieldNameForChild(i) == javaFieldName {
			idx[c.Content(src)] = append(idx[c.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		}
	}
}

func goAddIdentifiers(list *sitter.Node, end uint32, src []byte, idx map[string][]goDecl) {
	if list == nil {
		return
	}
	if list.Type() == goNodeIdentifier {
		idx[list.Content(src)] = append(idx[list.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		return
	}
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if c := list.NamedChild(i); c.Type() == goNodeIdentifier {
			idx[c.Content(src)] = append(idx[c.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		}
	}
}

func goHasToken(n *sitter.Node, token string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); !c.IsNamed() && c.Type() == token {
			return true
		}
	}
	return false
}

func goWalk(n *sitter.Node, visit func(*sitter.Node)) {
	visit(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		goWalk(n.NamedChild(i), visit)
	}
}

// goCollectBoundNames records what a scope node binds itself: the parameters,
// receiver and named results of a function or literal, and a type switch alias.
// They are in scope for the whole body.
func goCollectBoundNames(scope *sitter.Node, src []byte, idx map[string][]goDecl) {
	switch scope.Type() {
	case nodeFunctionDeclaration, javaNodeMethodDeclaration, goNodeFuncLiteral:
		for _, field := range []string{"receiver", "parameters", "result"} {
			if list := scope.ChildByFieldName(field); list != nil {
				goWalk(list, func(c *sitter.Node) {
					if c.Type() == goNodeParameterDecl || c.Type() == goNodeVariadicParam {
						goAddNames(c, 0, src, idx)
					}
				})
			}
		}
	case goNodeTypeSwitch:
		goAddIdentifiers(scope.ChildByFieldName("alias"), 0, src, idx)
	}
}
