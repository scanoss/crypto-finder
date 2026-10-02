// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	// goRangeBoundMark prefixes a binding-map value written for a range
	// variable. Such a name is scoped to its loop, so any `:=` of the same name
	// below it is a new variable and drops the element type.
	goRangeBoundMark = "\x01"
	// goRangeFieldTag marks a range variable whose type waits on the
	// graph-wide struct field table: "<tag><part>|<pkg>|<type>|<field>".
	goRangeFieldTag = "field|"
	// goRangeKeyPart names the key part inside a field tag.
	goRangeKeyPart = "key"
)

// goTypeParamKey prefixes the binding-map key that records a type parameter of
// the enclosing generic function, which no package declares.
const goTypeParamKey = "\x02"

// goVarTypeIsTypeParam reports whether a binding's type text names, at its
// core, a type parameter of the enclosing function.
func goVarTypeIsTypeParam(varTypes map[string]string, typeText string) bool {
	text := strings.TrimPrefix(typeText, goRangeBoundMark)
	for {
		coll, ok := goCollectionTypes(text)
		if !ok {
			break
		}
		if coll.isMap && goVarTypeIsTypeParam(varTypes, coll.key) {
			return true
		}
		text = coll.elem
	}
	_, ok := varTypes[goTypeParamKey+strings.TrimLeft(strings.TrimSpace(text), "* ")]
	return ok
}

// goIdentifierRightTypes snapshots, before a `:=` rebinds its names, the type
// of each right-hand identifier: `v := v` keeps the type the outer v had.
func goIdentifierRightTypes(left, right *sitter.Node, src []byte, varTypes map[string]string) []string {
	count := int(left.NamedChildCount())
	if count == 0 || count != int(right.NamedChildCount()) {
		return nil
	}
	prior := make([]string, count)
	for i := 0; i < count; i++ {
		if rn := right.NamedChild(i); rn != nil && rn.Type() == goNodeIdentifier {
			prior[i] = varTypes[strings.TrimSpace(rn.Content(src))]
		}
	}
	return prior
}

// goCollection is the element (and, for a map, key) type text of a slice,
// array or map type.
type goCollection struct {
	key, elem string
	isMap     bool
}

// goCollectionTypes reads `[]T`, `[N]T` and `map[K]V`. Channels, pointers to
// arrays, named collection types and everything else are not collections here.
func goCollectionTypes(typeText string) (goCollection, bool) {
	text := strings.TrimSpace(typeText)
	isMap := strings.HasPrefix(text, "map[")
	open := 0
	switch {
	case isMap:
		open = len("map")
	case strings.HasPrefix(text, "["):
	default:
		return goCollection{}, false
	}
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth > 0 {
				continue
			}
			elem := strings.TrimSpace(text[i+1:])
			if elem == "" {
				return goCollection{}, false
			}
			coll := goCollection{elem: elem, isMap: isMap}
			if isMap {
				coll.key = strings.TrimSpace(text[open+1 : i])
			}
			return coll, true
		}
	}
	return goCollection{}, false
}

// goCollectionFieldType qualifies a collection field's element and key types.
// It is the zero value when neither names a type.
func goCollectionFieldType(coll goCollection, analysis *FileAnalysis, typeParams map[string]bool) GoFieldType {
	var ft GoFieldType
	if !typeParams[strings.TrimLeft(coll.elem, "* ")] {
		if pkg, typ, ok := goQualifyTypeText(coll.elem, analysis); ok {
			ft.ElemPackage, ft.ElemType = pkg, typ
		}
	}
	if coll.isMap && !typeParams[strings.TrimLeft(coll.key, "* ")] {
		if pkg, typ, ok := goQualifyTypeText(coll.key, analysis); ok {
			ft.KeyPackage, ft.KeyType = pkg, typ
		}
	}
	return ft
}

// partType is the type a receiver has when it is the given part of the field.
func (ft GoFieldType) partType(part GoFieldPart) GoFieldType {
	switch part {
	case GoFieldElem:
		return GoFieldType{Package: ft.ElemPackage, Type: ft.ElemType}
	case GoFieldKey:
		return GoFieldType{Package: ft.KeyPackage, Type: ft.KeyType}
	case GoFieldWhole:
		return GoFieldType{Package: ft.Package, Type: ft.Type}
	}
	return GoFieldType{}
}

// goCollectionSource is a ranged or indexed expression whose collection type
// is statically known: either as type text (a typed local, a parameter, a
// literal) or as a struct field the builder resolves later.
type goCollectionSource struct {
	goCollection
	viaField bool
	owner    FunctionID
	field    string
}

func (p *GoParser) goCollectionOf(
	expr *sitter.Node,
	src []byte,
	analysis *FileAnalysis,
	currentReceiverType, currentReceiverVar string,
	varTypes map[string]string,
) (goCollectionSource, bool) {
	if expr == nil {
		return goCollectionSource{}, false
	}
	switch expr.Type() {
	case goNodeIdentifier:
		name := expr.Content(src)
		text, ok := varTypes[name]
		if !ok || name == currentReceiverVar {
			return goCollectionSource{}, false
		}
		text = strings.TrimPrefix(text, goRangeBoundMark)
		if strings.HasPrefix(text, goRangeFieldTag) {
			return goCollectionSource{}, false
		}
		coll, ok := goCollectionTypes(text)
		return goCollectionSource{goCollection: coll}, ok
	case goNodeSelectorExpression:
		rootNode := expr.ChildByFieldName(goFieldOperand)
		fieldNode := expr.ChildByFieldName(goFieldField)
		if rootNode == nil || fieldNode == nil || rootNode.Type() != goNodeIdentifier {
			return goCollectionSource{}, false
		}
		root := rootNode.Content(src)
		if _, local := varTypes[root]; !local && root != currentReceiverVar {
			return goCollectionSource{}, false
		}
		pkg, typ := p.resolveSelectorReceiverType(root, analysis, currentReceiverType, currentReceiverVar, varTypes)
		if typ == "" {
			return goCollectionSource{}, false
		}
		return goCollectionSource{
			viaField: true,
			owner:    FunctionID{Package: pkg, Type: typ},
			field:    fieldNode.Content(src),
		}, true
	case goNodeCompositeLiteral:
		coll, ok := goCollectionTypes(goSyntacticType(expr, src))
		return goCollectionSource{goCollection: coll}, ok
	}
	return goCollectionSource{}, false
}

// bindGoRangeTypes types the variables of `for k, v := range xs` from the
// element type of xs when it is statically known. A slice or array yields an
// int index and the element; a map yields the key and the value. Channels,
// strings, integers and functions have no collection type here and stay
// untyped.
func (p *GoParser) bindGoRangeTypes(
	rangeNode, left *sitter.Node,
	src []byte,
	analysis *FileAnalysis,
	currentReceiverType, currentReceiverVar string,
	varTypes map[string]string,
) {
	coll, ok := p.goCollectionOf(rangeNode.ChildByFieldName("right"), src, analysis, currentReceiverType, currentReceiverVar, varTypes)
	if !ok {
		return
	}
	bind := func(i int, part GoFieldPart, text string) {
		n := left.NamedChild(i)
		if n == nil || n.Type() != goNodeIdentifier {
			return
		}
		name := strings.TrimSpace(n.Content(src))
		if name == "" || name == "_" {
			return
		}
		if coll.viaField {
			partName := "elem"
			if part == GoFieldKey {
				partName = goRangeKeyPart
			}
			varTypes[name] = goRangeBoundMark + goRangeFieldTag + strings.Join([]string{partName, coll.owner.Package, coll.owner.Type, coll.field}, "|")
			return
		}
		if text != "" {
			varTypes[name] = goRangeBoundMark + text
		}
	}
	// A field's kind is known only to the builder: its key part is empty for a
	// slice or array, so the first variable stays untyped there.
	if coll.isMap || coll.viaField {
		bind(0, GoFieldKey, coll.key)
	}
	bind(1, GoFieldElem, coll.elem)
}

// goCollectionElementCall types a call whose receiver is an element of a
// collection: a range variable bound from a struct field (`for _, s := range
// m.sources { s.Load() }`) or an indexed collection (`xs[i].Load()`,
// `m.sources[i].Load()`). It returns nil for every other shape.
func (p *GoParser) goCollectionElementCall(
	node, operandNode *sitter.Node,
	method string,
	src []byte,
	filePath string,
	line int,
	args []string,
	analysis *FileAnalysis,
	currentReceiverType, currentReceiverVar string,
	varTypes map[string]string,
) *FunctionCall {
	call := func(callee FunctionID, recv *GoFieldReceiver) *FunctionCall {
		callee.Name = method
		return &FunctionCall{
			Callee:        callee,
			FieldReceiver: recv,
			Raw:           node.Content(src),
			FilePath:      filePath,
			Line:          line,
			Arguments:     args,
		}
	}
	switch operandNode.Type() {
	case goNodeIdentifier:
		name := operandNode.Content(src)
		if name == currentReceiverVar {
			return nil
		}
		text := strings.TrimPrefix(varTypes[name], goRangeBoundMark)
		if !strings.HasPrefix(varTypes[name], goRangeBoundMark) || !strings.HasPrefix(text, goRangeFieldTag) {
			return nil
		}
		parts := strings.Split(strings.TrimPrefix(text, goRangeFieldTag), "|")
		if len(parts) != 4 {
			return nil
		}
		part := GoFieldElem
		if parts[0] == goRangeKeyPart {
			part = GoFieldKey
		}
		return call(FunctionID{}, &GoFieldReceiver{Owner: FunctionID{Package: parts[1], Type: parts[2]}, Name: parts[3], Part: part})
	case goNodeIndexExpression:
		coll, ok := p.goCollectionOf(operandNode.ChildByFieldName(goFieldOperand), src, analysis, currentReceiverType, currentReceiverVar, varTypes)
		if !ok {
			return nil
		}
		if coll.viaField {
			return call(FunctionID{}, &GoFieldReceiver{Owner: coll.owner, Name: coll.field, Part: GoFieldElem})
		}
		pkg, typ, ok := goQualifyTypeText(coll.elem, analysis)
		if !ok || goVarTypeIsTypeParam(varTypes, coll.elem) {
			return nil
		}
		return call(FunctionID{Package: pkg, Type: typ}, nil)
	}
	return nil
}

// goFieldTypeOf types a struct field's declaration: a named type, or the
// element (and key) types of a slice, array or map. It is false when nothing
// nameable remains.
func goFieldTypeOf(typeText string, analysis *FileAnalysis, typeParams map[string]bool) (GoFieldType, bool) {
	if coll, isColl := goCollectionTypes(typeText); isColl {
		ft := goCollectionFieldType(coll, analysis, typeParams)
		return ft, ft != (GoFieldType{})
	}
	if strings.Contains(typeText, "[") || typeParams[strings.TrimLeft(typeText, "* ")] {
		return GoFieldType{}, false
	}
	pkg, typ, ok := goQualifyTypeText(typeText, analysis)
	return GoFieldType{Package: pkg, Type: typ}, ok
}
