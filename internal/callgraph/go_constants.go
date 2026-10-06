package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

const (
	goNodeConstDeclaration = "const_declaration"
	goNodeConstSpec        = "const_spec"
	goNodeSourceFile       = "source_file"
	goNodeStatementList    = "statement_list"
	goNodeArgumentList     = "argument_list"
	goNodeComment          = "comment"
	goNodeRangeClause      = "range_clause"
	goNodeTypeSwitch       = "type_switch_statement"
	goNodeIntLiteral       = "int_literal"
	goNodeInterpretedStr   = "interpreted_string_literal"
	goNodeRawStr           = "raw_string_literal"
)

// goArgumentSources traces each argument of a call expression that is a bare
// identifier naming a Go const initialized with an integer or string literal.
// The result is parallel to the call's Arguments and nil when no argument
// resolves. Every other argument shape stays unresolved.
func goArgumentSources(call *sitter.Node, src []byte) [][]SourceNode {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.Type() != goNodeArgumentList {
		return nil
	}
	var sources [][]SourceNode
	resolved := false
	for i := 0; i < int(args.NamedChildCount()); i++ {
		arg := args.NamedChild(i)
		if arg.Type() == goNodeComment {
			continue
		}
		var nodes []SourceNode
		if arg.Type() == goNodeIdentifier {
			if value, ok := goLookupConst(arg, arg.Content(src), src); ok {
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

type goDeclKind int

const (
	goDeclNone goDeclKind = iota
	// goDeclOpaque is a declaration of the name that yields no literal: a
	// variable, a parameter, or a const without a literal initializer.
	goDeclOpaque
	goDeclLiteral
)

// goLookupConst resolves name at use to the literal of the const it denotes.
// It walks outward through the lexical scopes enclosing use; the innermost
// scope that declares name decides, so a shadowed name never inherits an outer
// const.
func goLookupConst(use *sitter.Node, name string, src []byte) (string, bool) {
	for child, scope := use, use.Parent(); scope != nil; child, scope = scope, scope.Parent() {
		if goScopeBindsName(scope, name, src) {
			return "", false
		}
		before := child
		if scope.Type() == goNodeSourceFile {
			before = nil
		}
		value, kind := goDeclIn(scope, before, name, src)
		if kind != goDeclNone {
			return value, kind == goDeclLiteral
		}
	}
	return "", false
}

// goDeclIn scans the declarations among scope's children for name. With before
// set, only children that end before it count, which is Go's rule that a local
// declaration scopes from the end of its spec. Package scope passes nil. The
// last matching declaration wins, as a redeclaration cannot occur in valid Go.
func goDeclIn(scope, before *sitter.Node, name string, src []byte) (string, goDeclKind) {
	var value string
	kind := goDeclNone
	goEachDeclaration(scope, before, func(n *sitter.Node) {
		if v, k := goDeclarationValue(n, before, name, src); k != goDeclNone {
			value, kind = v, k
		}
	})
	return value, kind
}

// goEachDeclaration calls visit for every child of scope that ends before the
// given node, looking through the statement_list that wraps a block's body.
func goEachDeclaration(scope, before *sitter.Node, visit func(*sitter.Node)) {
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		n := scope.NamedChild(i)
		if before != nil && n.EndByte() > before.StartByte() {
			continue
		}
		if n.Type() == goNodeStatementList {
			goEachDeclaration(n, before, visit)
			continue
		}
		visit(n)
	}
}

func goDeclarationValue(n, before *sitter.Node, name string, src []byte) (string, goDeclKind) {
	switch n.Type() {
	case goNodeConstDeclaration:
		value, kind := "", goDeclNone
		for i := 0; i < int(n.NamedChildCount()); i++ {
			spec := n.NamedChild(i)
			if before != nil && spec.EndByte() > before.StartByte() {
				continue
			}
			if v, k := goConstSpecValue(spec, name, src); k != goDeclNone {
				value, kind = v, k
			}
		}
		return value, kind
	case goNodeVarDeclaration, goNodeShortVarDeclaration, goNodeRangeClause:
		if goDeclaresName(n, name, src) {
			return "", goDeclOpaque
		}
	}
	return "", goDeclNone
}

// goConstSpecValue returns the literal a const_spec gives name, or opaque when
// the spec declares name without a literal of its own (iota, an expression, or
// the implicit repetition of the previous spec).
func goConstSpecValue(spec *sitter.Node, name string, src []byte) (string, goDeclKind) {
	if spec.Type() != goNodeConstSpec {
		return "", goDeclNone
	}
	index := -1
	n := 0
	for i := 0; i < int(spec.ChildCount()); i++ {
		child := spec.Child(i)
		if !child.IsNamed() || spec.FieldNameForChild(i) != javaFieldName {
			continue
		}
		if child.Content(src) == name {
			index = n
		}
		n++
	}
	if index < 0 {
		return "", goDeclNone
	}
	values := spec.ChildByFieldName("value")
	if values == nil || int(values.NamedChildCount()) != n {
		return "", goDeclOpaque
	}
	literal := values.NamedChild(index)
	text := literal.Content(src)
	switch literal.Type() {
	case goNodeIntLiteral:
		if goPlainDecimal(text) {
			return text, goDeclLiteral
		}
	case goNodeInterpretedStr, goNodeRawStr:
		return text, goDeclLiteral
	}
	return "", goDeclOpaque
}

// goPlainDecimal accepts base-10 literals only: a leading zero, a base prefix,
// or an underscore changes what the digits mean downstream.
func goPlainDecimal(text string) bool {
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// goDeclaresName reports whether a var declaration, short variable declaration
// or range clause binds name.
func goDeclaresName(n *sitter.Node, name string, src []byte) bool {
	switch n.Type() {
	case goNodeVarDeclaration:
		found := false
		goWalk(n, func(c *sitter.Node) {
			if c.Type() == goNodeVarSpec && goFieldIdentifiers(c, javaFieldName, name, src) {
				found = true
			}
		})
		return found
	case goNodeShortVarDeclaration, goNodeRangeClause:
		left := n.ChildByFieldName(goFieldLeft)
		return left != nil && goIdentifierListHas(left, name, src)
	}
	return false
}

func goWalk(n *sitter.Node, visit func(*sitter.Node)) {
	visit(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		goWalk(n.NamedChild(i), visit)
	}
}

func goFieldIdentifiers(n *sitter.Node, field, name string, src []byte) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.IsNamed() && n.FieldNameForChild(i) == field && c.Content(src) == name {
			return true
		}
	}
	return false
}

func goIdentifierListHas(list *sitter.Node, name string, src []byte) bool {
	if list.Type() == goNodeIdentifier {
		return list.Content(src) == name
	}
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if c := list.NamedChild(i); c.Type() == goNodeIdentifier && c.Content(src) == name {
			return true
		}
	}
	return false
}

// goScopeBindsName reports whether scope itself binds name: the parameters,
// receiver or named results of a function or literal, or a type switch alias.
func goScopeBindsName(scope *sitter.Node, name string, src []byte) bool {
	switch scope.Type() {
	case nodeFunctionDeclaration, javaNodeMethodDeclaration, goNodeFuncLiteral:
		for _, field := range []string{"receiver", "parameters", "result"} {
			list := scope.ChildByFieldName(field)
			if list == nil {
				continue
			}
			found := false
			goWalk(list, func(c *sitter.Node) {
				if c.Type() == goNodeParameterDecl && goFieldIdentifiers(c, javaFieldName, name, src) {
					found = true
				}
			})
			if found {
				return true
			}
		}
	case goNodeTypeSwitch:
		alias := scope.ChildByFieldName("alias")
		return alias != nil && goIdentifierListHas(alias, name, src)
	}
	return false
}
