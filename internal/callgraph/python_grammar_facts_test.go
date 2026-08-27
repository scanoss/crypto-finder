// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

// parsePythonGrammarSnippet parses src with the pinned Python grammar and
// returns the root node. The caller must not close the tree; this helper
// keeps it alive for the duration of the test via t.Cleanup.
func parsePythonGrammarSnippet(t *testing.T, src string) (*sitter.Node, []byte) {
	t.Helper()
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(src))
	if err != nil {
		t.Fatalf("parse snippet: %v", err)
	}
	t.Cleanup(tree.Close)
	return tree.RootNode(), []byte(src)
}

// firstNodeOfType returns the first node of the given type found via
// pre-order (document-order) traversal, or nil when none exists.
func firstNodeOfType(node *sitter.Node, nodeType string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == nodeType {
		return node
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if found := firstNodeOfType(node.Child(i), nodeType); found != nil {
			return found
		}
	}
	return nil
}

// TestPythonGrammarFacts_PinnedNodeShapes pins the tree-sitter Python grammar
// node types and field-name bindings that the parity implementation (T1-T6)
// depends on. Each case parses a real snippet with the pinned grammar
// (smacker/go-tree-sitter, python/parser.c) and asserts the node
// type/field-name shape documented in design.md's grammar spike appendix.
//
// This test asserts against REAL parser output, never a hand-built fixture.
// If any case ever contradicts the design appendix, the appendix (and this
// table) must be corrected from what the parser actually does — the parser
// itself is never bent to match a wrong assumption.
func TestPythonGrammarFacts_PinnedNodeShapes(t *testing.T) {
	t.Run("with_as_binds_alias_via_as_pattern", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "with Cipher() as c:\n    c.encrypt(data)\n")
		withStmt := firstNodeOfType(root, "with_statement")
		if withStmt == nil {
			t.Fatal("with_statement not found")
		}
		withClause := firstNodeOfType(withStmt, "with_clause")
		if withClause == nil {
			t.Fatal("with_clause not found")
		}
		withItem := firstNodeOfType(withClause, "with_item")
		if withItem == nil {
			t.Fatal("with_item not found")
		}
		asPattern := withItem.ChildByFieldName("value")
		if asPattern == nil || asPattern.Type() != "as_pattern" {
			t.Fatalf("with_item value field = %v, want as_pattern", asPattern)
		}
		alias := firstNodeOfType(asPattern, "as_pattern_target")
		if alias == nil {
			t.Fatal("as_pattern_target not found")
		}
		aliasIdent := firstNodeOfType(alias, goNodeIdentifier)
		if aliasIdent == nil || aliasIdent.Content(src) != "c" {
			t.Fatalf("as_pattern_target identifier = %v, want \"c\"", aliasIdent)
		}
	})

	t.Run("async_with_as_is_same_node_shape", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "async def f():\n    async with Cipher() as c:\n        await c.encrypt(data)\n")
		withStmt := firstNodeOfType(root, "with_statement")
		if withStmt == nil {
			t.Fatal("with_statement not found for async with (async is not a distinct node type)")
		}
		if firstNodeOfType(withStmt, "as_pattern") == nil {
			t.Fatal("as_pattern not found under async with_statement")
		}
	})

	t.Run("for_in_uses_left_right_body_fields_no_pattern_field", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "for k in keys:\n    k.derive(salt)\n")
		forStmt := firstNodeOfType(root, "for_statement")
		if forStmt == nil {
			t.Fatal("for_statement not found")
		}
		left := forStmt.ChildByFieldName("left")
		right := forStmt.ChildByFieldName("right")
		body := forStmt.ChildByFieldName("body")
		if left == nil || left.Type() != goNodeIdentifier {
			t.Fatalf("for_statement left field = %v, want identifier", left)
		}
		if right == nil {
			t.Fatal("for_statement right field is nil")
		}
		if body == nil || body.Type() != "block" {
			t.Fatalf("for_statement body field = %v, want block", body)
		}
		if forStmt.ChildByFieldName("pattern") != nil {
			t.Fatal("for_statement unexpectedly has a 'pattern' field; this grammar has none")
		}
		// Cross-check via FieldNameForChild: the "left" child's own field name,
		// read by index rather than by name, must agree with ChildByFieldName.
		for i := 0; i < int(forStmt.ChildCount()); i++ {
			if forStmt.Child(i).Equal(left) {
				if got := forStmt.FieldNameForChild(i); got != "left" {
					t.Fatalf("FieldNameForChild(%d) = %q, want \"left\"", i, got)
				}
			}
		}
	})

	t.Run("async_for_in_is_same_node_shape", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "async def f():\n    async for k in akeys:\n        await k.derive(salt)\n")
		forStmt := firstNodeOfType(root, "for_statement")
		if forStmt == nil {
			t.Fatal("for_statement not found for async for (async is not a distinct node type)")
		}
		if forStmt.ChildByFieldName("left") == nil {
			t.Fatal("left field missing on async for_statement")
		}
	})

	t.Run("except_as_binds_alias_via_as_pattern", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "try:\n    pass\nexcept CryptoError as e:\n    e.cipher.close()\n")
		exceptClause := firstNodeOfType(root, "except_clause")
		if exceptClause == nil {
			t.Fatal("except_clause not found")
		}
		asPattern := firstNodeOfType(exceptClause, "as_pattern")
		if asPattern == nil {
			t.Fatal("as_pattern not found under except_clause")
		}
		alias := firstNodeOfType(asPattern, "as_pattern_target")
		if alias == nil {
			t.Fatal("as_pattern_target not found under except as_pattern")
		}
		aliasIdent := firstNodeOfType(alias, goNodeIdentifier)
		if aliasIdent == nil || aliasIdent.Content(src) != "e" {
			t.Fatalf("except as_pattern_target identifier = %v, want \"e\"", aliasIdent)
		}
	})

	t.Run("bare_except_has_no_as_pattern", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "try:\n    pass\nexcept CryptoError:\n    pass\n")
		exceptClause := firstNodeOfType(root, "except_clause")
		if exceptClause == nil {
			t.Fatal("except_clause not found")
		}
		if firstNodeOfType(exceptClause, "as_pattern") != nil {
			t.Fatal("bare except unexpectedly has an as_pattern")
		}
	})

	t.Run("walrus_binds_name_via_named_expression", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "if (c := Cipher()) is not None:\n    c.encrypt(data)\n")
		namedExpr := firstNodeOfType(root, "named_expression")
		if namedExpr == nil {
			t.Fatal("named_expression not found")
		}
		name := namedExpr.ChildByFieldName("name")
		value := namedExpr.ChildByFieldName("value")
		if name == nil || name.Type() != goNodeIdentifier || name.Content(src) != "c" {
			t.Fatalf("named_expression name field = %v, want identifier \"c\"", name)
		}
		if value == nil {
			t.Fatal("named_expression value field is nil")
		}
	})

	t.Run("tuple_star_unpacking_uses_pattern_list_and_list_splat_pattern", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "a, *rest = make_ciphers()\n")
		assignment := firstNodeOfType(root, pythonNodeAssignment)
		if assignment == nil {
			t.Fatal("assignment not found")
		}
		left := assignment.ChildByFieldName("left")
		right := assignment.ChildByFieldName("right")
		if left == nil || left.Type() != "pattern_list" {
			t.Fatalf("assignment left field = %v, want pattern_list", left)
		}
		if right == nil || right.Type() != pythonNodeCall {
			t.Fatalf("assignment right field = %v, want call", right)
		}
		firstIdent := firstNodeOfType(left, goNodeIdentifier)
		if firstIdent == nil || firstIdent.Content(src) != "a" {
			t.Fatalf("pattern_list first identifier = %v, want \"a\"", firstIdent)
		}
		splat := firstNodeOfType(left, "list_splat_pattern")
		if splat == nil {
			t.Fatal("list_splat_pattern not found under pattern_list")
		}
		splatIdent := firstNodeOfType(splat, goNodeIdentifier)
		if splatIdent == nil || splatIdent.Content(src) != "rest" {
			t.Fatalf("list_splat_pattern identifier = %v, want \"rest\"", splatIdent)
		}
	})

	t.Run("augmented_assignment_uses_left_right_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "x += 1\n")
		aug := firstNodeOfType(root, "augmented_assignment")
		if aug == nil {
			t.Fatal("augmented_assignment not found")
		}
		left := aug.ChildByFieldName("left")
		right := aug.ChildByFieldName("right")
		if left == nil || left.Type() != goNodeIdentifier || left.Content(src) != "x" {
			t.Fatalf("augmented_assignment left field = %v, want identifier \"x\"", left)
		}
		if right == nil {
			t.Fatal("augmented_assignment right field is nil")
		}
	})

	t.Run("typed_and_default_parameters_have_distinct_node_types", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "def f(a, b: int, c=1, d: int = 2, *args, **kwargs):\n    pass\n")
		fn := firstNodeOfType(root, pythonNodeFunctionDefinition)
		if fn == nil {
			t.Fatal("function_definition not found")
		}
		params := fn.ChildByFieldName("parameters")
		if params == nil {
			t.Fatal("parameters field is nil")
		}
		var sawTyped, sawDefault, sawTypedDefault, sawSplat, sawKwargSplat bool
		for i := 0; i < int(params.ChildCount()); i++ {
			switch params.Child(i).Type() {
			case "typed_parameter":
				sawTyped = true
			case "default_parameter":
				sawDefault = true
			case "typed_default_parameter":
				sawTypedDefault = true
			case "list_splat_pattern":
				sawSplat = true
			case pythonNodeDictSplatPattern:
				sawKwargSplat = true
			}
		}
		if !sawTyped {
			t.Error("typed_parameter node not found")
		}
		if !sawDefault {
			t.Error("default_parameter node not found")
		}
		if !sawTypedDefault {
			t.Error("typed_default_parameter node not found")
		}
		if !sawSplat {
			t.Error("list_splat_pattern (*args) node not found")
		}
		if !sawKwargSplat {
			t.Error("dictionary_splat_pattern (**kwargs) node not found")
		}
	})

	t.Run("relative_import_single_dot_uses_module_name_field", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "from . import helper\n")
		stmt := firstNodeOfType(root, "import_from_statement")
		if stmt == nil {
			t.Fatal("import_from_statement not found")
		}
		moduleName := stmt.ChildByFieldName("module_name")
		if moduleName == nil || moduleName.Type() != pythonNodeRelativeImport {
			t.Fatalf("module_name field = %v, want relative_import", moduleName)
		}
		if firstNodeOfType(moduleName, "import_prefix") == nil {
			t.Fatal("import_prefix not found under relative_import")
		}
		nameField := stmt.ChildByFieldName("name")
		if nameField == nil || nameField.Type() != pythonNodeDottedName {
			t.Fatalf("import_from_statement name field = %v, want dotted_name", nameField)
		}
	})

	t.Run("relative_import_double_dot_with_dotted_module", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "from ..other import Bar\n")
		stmt := firstNodeOfType(root, "import_from_statement")
		if stmt == nil {
			t.Fatal("import_from_statement not found")
		}
		moduleName := stmt.ChildByFieldName("module_name")
		if moduleName == nil || moduleName.Type() != pythonNodeRelativeImport {
			t.Fatalf("module_name field = %v, want relative_import", moduleName)
		}
		dotted := firstNodeOfType(moduleName, pythonNodeDottedName)
		if dotted == nil || dotted.Content(src) != "other" {
			t.Fatalf("relative_import dotted_name = %v, want \"other\"", dotted)
		}
	})

	t.Run("aliased_import_on_from_statement_uses_name_and_alias_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "from .foo import Bar as Baz\n")
		stmt := firstNodeOfType(root, "import_from_statement")
		if stmt == nil {
			t.Fatal("import_from_statement not found")
		}
		nameField := stmt.ChildByFieldName("name")
		if nameField == nil || nameField.Type() != pythonNodeAliasedImport {
			t.Fatalf("import_from_statement name field = %v, want aliased_import", nameField)
		}
		dotted := nameField.ChildByFieldName("name")
		alias := nameField.ChildByFieldName("alias")
		if dotted == nil || dotted.Type() != pythonNodeDottedName || dotted.Content(src) != "Bar" {
			t.Fatalf("aliased_import name field = %v, want dotted_name \"Bar\"", dotted)
		}
		if alias == nil || alias.Type() != goNodeIdentifier || alias.Content(src) != "Baz" {
			t.Fatalf("aliased_import alias field = %v, want identifier \"Baz\"", alias)
		}
	})

	t.Run("aliased_import_statement_uses_name_field", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "import a as b\n")
		stmt := firstNodeOfType(root, "import_statement")
		if stmt == nil {
			t.Fatal("import_statement not found")
		}
		nameField := stmt.ChildByFieldName("name")
		if nameField == nil || nameField.Type() != pythonNodeAliasedImport {
			t.Fatalf("import_statement name field = %v, want aliased_import", nameField)
		}
		alias := nameField.ChildByFieldName("alias")
		if alias == nil || alias.Content(src) != "b" {
			t.Fatalf("aliased_import alias field = %v, want \"b\"", alias)
		}
	})

	t.Run("nested_import_inside_try_except_is_ordinary_child", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "try:\n    import fastcrypto as crypto\nexcept ImportError:\n    import crypto\n")
		tryStmt := firstNodeOfType(root, "try_statement")
		if tryStmt == nil {
			t.Fatal("try_statement not found")
		}
		tryBody := tryStmt.ChildByFieldName("body")
		if tryBody == nil || tryBody.Type() != "block" {
			t.Fatalf("try_statement body field = %v, want block", tryBody)
		}
		if firstNodeOfType(tryBody, "import_statement") == nil {
			t.Fatal("import_statement not found nested inside try body block (confirms recursive walk is required)")
		}
		exceptClause := firstNodeOfType(root, "except_clause")
		if exceptClause == nil {
			t.Fatal("except_clause not found")
		}
		if firstNodeOfType(exceptClause, "import_statement") == nil {
			t.Fatal("import_statement not found nested inside except_clause block")
		}
	})

	t.Run("comprehension_for_in_clause_uses_left_right_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "[h(x) for x in xs]\n")
		comp := firstNodeOfType(root, "list_comprehension")
		if comp == nil {
			t.Fatal("list_comprehension not found")
		}
		body := comp.ChildByFieldName("body")
		if body == nil || body.Type() != pythonNodeCall {
			t.Fatalf("list_comprehension body field = %v, want call", body)
		}
		forIn := firstNodeOfType(comp, "for_in_clause")
		if forIn == nil {
			t.Fatal("for_in_clause not found under list_comprehension")
		}
		left := forIn.ChildByFieldName("left")
		right := forIn.ChildByFieldName("right")
		if left == nil || left.Type() != goNodeIdentifier || left.Content(src) != "x" {
			t.Fatalf("for_in_clause left field = %v, want identifier \"x\"", left)
		}
		if right == nil || right.Type() != goNodeIdentifier || right.Content(src) != "xs" {
			t.Fatalf("for_in_clause right field = %v, want identifier \"xs\"", right)
		}
	})

	t.Run("await_wraps_call_inside_expression_statement", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "async def f():\n    await g()\n")
		awaitNode := firstNodeOfType(root, "await")
		if awaitNode == nil {
			t.Fatal("await not found")
		}
		call := firstNodeOfType(awaitNode, pythonNodeCall)
		if call == nil {
			t.Fatal("call not found under await")
		}
	})

	t.Run("self_and_cls_attribute_assignment_uses_attribute_left_field", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class K:\n    def m(self, key):\n        self.k = Fernet(key)\n\n    @classmethod\n    def cm(cls, key):\n        cls.c = Fernet(key)\n")
		assignments := findAllNodesOfType(root, pythonNodeAssignment)
		var sawSelf, sawCls bool
		for _, assign := range assignments {
			left := assign.ChildByFieldName("left")
			right := assign.ChildByFieldName("right")
			if left == nil || left.Type() != pythonNodeAttribute {
				continue
			}
			object := left.ChildByFieldName("object")
			attr := left.ChildByFieldName("attribute")
			if object == nil || attr == nil {
				t.Fatalf("attribute assignment missing object/attribute fields: object=%v attr=%v", object, attr)
			}
			if right == nil || right.Type() != pythonNodeCall {
				t.Fatalf("attribute assignment right field = %v, want call", right)
			}
			switch object.Content(src) {
			case pythonSelfObjectName:
				sawSelf = true
				if attr.Content(src) != "k" {
					t.Errorf("self attribute name = %q, want \"k\"", attr.Content(src))
				}
			case "cls":
				sawCls = true
				if attr.Content(src) != "c" {
					t.Errorf("cls attribute name = %q, want \"c\"", attr.Content(src))
				}
			}
		}
		if !sawSelf {
			t.Error("self.k = Fernet(key) assignment not found")
		}
		if !sawCls {
			t.Error("cls.c = Fernet(key) assignment not found")
		}
	})

	t.Run("class_body_assignment_is_expression_statement_under_block", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class Foo:\n    default_cipher = Cipher()\n")
		classDef := firstNodeOfType(root, "class_definition")
		if classDef == nil {
			t.Fatal("class_definition not found")
		}
		name := classDef.ChildByFieldName("name")
		if name == nil || name.Content(src) != "Foo" {
			t.Fatalf("class_definition name field = %v, want \"Foo\"", name)
		}
		body := classDef.ChildByFieldName("body")
		if body == nil || body.Type() != "block" {
			t.Fatalf("class_definition body field = %v, want block", body)
		}
		exprStmt := body.Child(0)
		if exprStmt == nil || exprStmt.Type() != "expression_statement" {
			t.Fatalf("class body first child = %v, want expression_statement", exprStmt)
		}
		assignment := firstNodeOfType(exprStmt, pythonNodeAssignment)
		if assignment == nil {
			t.Fatal("assignment not found under class-body expression_statement")
		}
	})

	t.Run("module_level_statement_is_direct_expression_statement_child_of_module", func(t *testing.T) {
		root, _ := parsePythonGrammarSnippet(t, "cipher = Cipher()\n")
		if root.Type() != "module" {
			t.Fatalf("root node type = %q, want \"module\"", root.Type())
		}
		found := false
		for i := 0; i < int(root.ChildCount()); i++ {
			child := root.Child(i)
			if child.Type() == "expression_statement" {
				found = true
				if firstNodeOfType(child, pythonNodeAssignment) == nil {
					t.Fatal("module-level expression_statement does not contain the assignment")
				}
			}
		}
		if !found {
			t.Fatal("module-level statement is not a direct expression_statement child of module")
		}
	})

	t.Run("decorated_definition_wraps_classmethod_with_decorator_and_definition_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class K:\n    @classmethod\n    def setup(cls):\n        cls.cipher = Cipher()\n")
		decorated := firstNodeOfType(root, "decorated_definition")
		if decorated == nil {
			t.Fatal("decorated_definition not found")
		}
		decorator := firstNodeOfType(decorated, "decorator")
		if decorator == nil {
			t.Fatal("decorator not found under decorated_definition")
		}
		decoratorIdent := firstNodeOfType(decorator, goNodeIdentifier)
		if decoratorIdent == nil || decoratorIdent.Content(src) != "classmethod" {
			t.Fatalf("decorator identifier = %v, want \"classmethod\"", decoratorIdent)
		}
		definition := decorated.ChildByFieldName("definition")
		if definition == nil || definition.Type() != pythonNodeFunctionDefinition {
			t.Fatalf("decorated_definition definition field = %v, want function_definition", definition)
		}
		params := definition.ChildByFieldName("parameters")
		if params == nil {
			t.Fatal("function_definition parameters field is nil")
		}
		firstParam := firstNodeOfType(params, goNodeIdentifier)
		if firstParam == nil || firstParam.Content(src) != "cls" {
			t.Fatalf("first classmethod parameter = %v, want \"cls\"", firstParam)
		}
	})

	// The following cases extend the table with the design.md §10 grammar
	// appendix rows not yet pinned above (python-parser-parity-2, T0.1).

	t.Run("class_definition_superclasses_field_holds_base_names", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class Foo(Base1, pkg.Base2):\n    pass\n")
		classDef := firstNodeOfType(root, pythonNodeClassDefinition)
		if classDef == nil {
			t.Fatal("class_definition not found")
		}
		superclasses := classDef.ChildByFieldName("superclasses")
		if superclasses == nil || superclasses.Type() != pythonNodeArgumentList {
			t.Fatalf("class_definition superclasses field = %v, want argument_list", superclasses)
		}
		var sawIdent, sawAttr bool
		for i := 0; i < int(superclasses.ChildCount()); i++ {
			switch superclasses.Child(i).Type() {
			case goNodeIdentifier:
				sawIdent = true
			case pythonNodeAttribute:
				sawAttr = true
			}
		}
		if !sawIdent {
			t.Error("plain identifier base (Base1) not found under superclasses")
		}
		if !sawAttr {
			t.Error("attribute base (pkg.Base2) not found under superclasses")
		}
		_ = src
	})

	t.Run("decorated_definition_call_decorator_has_function_and_arguments", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class K:\n    @app.route(\"/x\")\n    def handler(self):\n        pass\n")
		decorated := firstNodeOfType(root, "decorated_definition")
		if decorated == nil {
			t.Fatal("decorated_definition not found")
		}
		decorator := firstNodeOfType(decorated, "decorator")
		if decorator == nil {
			t.Fatal("decorator not found")
		}
		call := firstNodeOfType(decorator, pythonNodeCall)
		if call == nil {
			t.Fatal("@app.route(...) decorator did not parse as a call node")
		}
		fn := call.Child(0)
		if fn == nil || fn.Type() != pythonNodeAttribute {
			t.Fatalf("decorator call function child = %v, want attribute", fn)
		}
		if fn.Content(src) != "app.route" {
			t.Fatalf("decorator call function content = %q, want %q", fn.Content(src), "app.route")
		}
	})

	t.Run("super_call_object_is_call_whose_function_is_identifier_super", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "class C(Base):\n    def __init__(self):\n        super().__init__()\n")
		call := firstNodeOfType(root, pythonNodeCall)
		// The outermost call in document order is super().__init__(); its
		// function is an attribute whose object is the inner super() call.
		fn := call.Child(0)
		if fn == nil || fn.Type() != pythonNodeAttribute {
			t.Fatalf("outer call function = %v, want attribute", fn)
		}
		obj := fn.ChildByFieldName("object")
		if obj == nil || obj.Type() != pythonNodeCall {
			t.Fatalf("super().__init__() object field = %v, want call", obj)
		}
		superFn := obj.Child(0)
		if superFn == nil || superFn.Type() != goNodeIdentifier || superFn.Content(src) != "super" {
			t.Fatalf("inner call function = %v, want identifier \"super\"", superFn)
		}
		methodAttr := fn.ChildByFieldName("attribute")
		if methodAttr == nil || methodAttr.Content(src) != "__init__" {
			t.Fatalf("outer call attribute field = %v, want \"__init__\"", methodAttr)
		}
	})

	t.Run("getattr_literal_call_shape_is_call_of_call_result", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "getattr(obj, 'encrypt')(data)\n")
		outer := firstNodeOfType(root, pythonNodeCall)
		if outer == nil {
			t.Fatal("outer call not found")
		}
		inner := outer.Child(0)
		if inner == nil || inner.Type() != pythonNodeCall {
			t.Fatalf("outer call function child = %v, want call (getattr(...))", inner)
		}
		innerFn := inner.Child(0)
		if innerFn == nil || innerFn.Type() != goNodeIdentifier || innerFn.Content(src) != "getattr" {
			t.Fatalf("inner call function = %v, want identifier \"getattr\"", innerFn)
		}
		strNode := firstNodeOfType(inner, "string")
		if strNode == nil {
			t.Fatal("string literal argument not found under getattr(...)")
		}
		content := firstNodeOfType(strNode, "string_content")
		if content == nil || content.Content(src) != "encrypt" {
			t.Fatalf("string_content = %v, want \"encrypt\"", content)
		}
	})

	t.Run("importlib_import_module_and_dunder_import_are_ordinary_calls", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "importlib.import_module('hashlib')\n__import__('hashlib')\n")
		calls := findAllNodesOfType(root, pythonNodeCall)
		if len(calls) != 2 {
			t.Fatalf("call count = %d, want 2", len(calls))
		}
		attrFn := calls[0].Child(0)
		if attrFn == nil || attrFn.Type() != pythonNodeAttribute {
			t.Fatalf("importlib.import_module call function = %v, want attribute", attrFn)
		}
		strContent := firstNodeOfType(calls[0], "string_content")
		if strContent == nil || strContent.Content(src) != "hashlib" {
			t.Fatalf("importlib.import_module argument = %v, want \"hashlib\"", strContent)
		}
		identFn := calls[1].Child(0)
		if identFn == nil || identFn.Type() != goNodeIdentifier || identFn.Content(src) != "__import__" {
			t.Fatalf("__import__ call function = %v, want identifier \"__import__\"", identFn)
		}
	})

	t.Run("typed_parameter_type_field_is_type_over_identifier", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "def f(x: Cipher):\n    pass\n")
		typedParam := firstNodeOfType(root, "typed_parameter")
		if typedParam == nil {
			t.Fatal("typed_parameter not found")
		}
		typeField := typedParam.ChildByFieldName("type")
		if typeField == nil || typeField.Type() != "type" {
			t.Fatalf("typed_parameter type field = %v, want type", typeField)
		}
		ident := firstNodeOfType(typeField, goNodeIdentifier)
		if ident == nil || ident.Content(src) != "Cipher" {
			t.Fatalf("typed_parameter type identifier = %v, want \"Cipher\"", ident)
		}
	})

	t.Run("typed_default_parameter_optional_uses_generic_type", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "def f(y: Optional[Cipher] = None):\n    pass\n")
		typedDefault := firstNodeOfType(root, "typed_default_parameter")
		if typedDefault == nil {
			t.Fatal("typed_default_parameter not found")
		}
		typeField := typedDefault.ChildByFieldName("type")
		if typeField == nil {
			t.Fatal("typed_default_parameter type field is nil")
		}
		generic := firstNodeOfType(typeField, "generic_type")
		if generic == nil {
			t.Fatal("generic_type not found under Optional[Cipher] annotation")
		}
		outerIdent := generic.Child(0)
		if outerIdent == nil || outerIdent.Type() != goNodeIdentifier || outerIdent.Content(src) != "Optional" {
			t.Fatalf("generic_type outer identifier = %v, want \"Optional\"", outerIdent)
		}
		typeParam := firstNodeOfType(generic, "type_parameter")
		if typeParam == nil {
			t.Fatal("type_parameter not found under generic_type")
		}
		innerType := firstNodeOfType(typeParam, "type")
		if innerType == nil {
			t.Fatal("inner type node not found under type_parameter")
		}
		innerIdent := firstNodeOfType(innerType, goNodeIdentifier)
		if innerIdent == nil || innerIdent.Content(src) != "Cipher" {
			t.Fatalf("Optional[Cipher] inner identifier = %v, want \"Cipher\"", innerIdent)
		}
	})

	t.Run("union_pipe_none_return_uses_binary_operator", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "def f() -> Cipher | None:\n    pass\n")
		fn := firstNodeOfType(root, pythonNodeFunctionDefinition)
		if fn == nil {
			t.Fatal("function_definition not found")
		}
		returnType := fn.ChildByFieldName("return_type")
		if returnType == nil || returnType.Type() != "type" {
			t.Fatalf("function_definition return_type field = %v, want type", returnType)
		}
		binOp := firstNodeOfType(returnType, "binary_operator")
		if binOp == nil {
			t.Fatal("binary_operator not found under Cipher | None return type")
		}
		left := binOp.ChildByFieldName("left")
		right := binOp.ChildByFieldName("right")
		if left == nil || left.Content(src) != "Cipher" {
			t.Fatalf("binary_operator left field = %v, want \"Cipher\"", left)
		}
		if right == nil || right.Type() != "none" {
			t.Fatalf("binary_operator right field = %v, want none", right)
		}
	})

	t.Run("string_forward_ref_return_type_wraps_string_content", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "def f() -> \"Cipher\":\n    pass\n")
		fn := firstNodeOfType(root, pythonNodeFunctionDefinition)
		if fn == nil {
			t.Fatal("function_definition not found")
		}
		returnType := fn.ChildByFieldName("return_type")
		if returnType == nil {
			t.Fatal("return_type field is nil")
		}
		strNode := firstNodeOfType(returnType, "string")
		if strNode == nil {
			t.Fatal("string node not found under forward-reference return type")
		}
		content := firstNodeOfType(strNode, "string_content")
		if content == nil || content.Content(src) != "Cipher" {
			t.Fatalf("string_content = %v, want \"Cipher\"", content)
		}
	})

	t.Run("annotated_assignment_uses_left_type_right_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "active: Cipher = default_cipher()\n")
		assignment := firstNodeOfType(root, pythonNodeAssignment)
		if assignment == nil {
			t.Fatal("assignment not found")
		}
		left := assignment.ChildByFieldName("left")
		typeField := assignment.ChildByFieldName("type")
		right := assignment.ChildByFieldName("right")
		if left == nil || left.Content(src) != "active" {
			t.Fatalf("annotated assignment left field = %v, want \"active\"", left)
		}
		if typeField == nil || typeField.Type() != "type" {
			t.Fatalf("annotated assignment type field = %v, want type", typeField)
		}
		if right == nil || right.Type() != pythonNodeCall {
			t.Fatalf("annotated assignment right field = %v, want call", right)
		}
	})

	t.Run("keyword_argument_uses_name_value_fields_positional_is_plain_child", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "PBKDF2HMAC(algorithm, length=32, salt=salt)\n")
		argList := firstNodeOfType(root, pythonNodeArgumentList)
		if argList == nil {
			t.Fatal("argument_list not found")
		}
		var sawPositionalIdent bool
		var kwArgs []*sitter.Node
		for i := 0; i < int(argList.ChildCount()); i++ {
			child := argList.Child(i)
			switch child.Type() {
			case goNodeIdentifier:
				sawPositionalIdent = true
			case "keyword_argument":
				kwArgs = append(kwArgs, child)
			}
		}
		if !sawPositionalIdent {
			t.Error("positional identifier argument not found as a direct argument_list child")
		}
		if len(kwArgs) != 2 {
			t.Fatalf("keyword_argument count = %d, want 2", len(kwArgs))
		}
		name := kwArgs[0].ChildByFieldName("name")
		value := kwArgs[0].ChildByFieldName("value")
		if name == nil || name.Content(src) != "length" {
			t.Fatalf("first keyword_argument name field = %v, want \"length\"", name)
		}
		if value == nil || value.Type() != "integer" || value.Content(src) != "32" {
			t.Fatalf("first keyword_argument value field = %v, want integer \"32\"", value)
		}
	})

	t.Run("module_constant_assignment_binds_identifier_to_integer", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "KEY_LEN = 32\n")
		assignment := firstNodeOfType(root, pythonNodeAssignment)
		if assignment == nil {
			t.Fatal("assignment not found")
		}
		left := assignment.ChildByFieldName("left")
		right := assignment.ChildByFieldName("right")
		if left == nil || left.Content(src) != "KEY_LEN" {
			t.Fatalf("module constant left field = %v, want \"KEY_LEN\"", left)
		}
		if right == nil || right.Type() != "integer" || right.Content(src) != "32" {
			t.Fatalf("module constant right field = %v, want integer \"32\"", right)
		}
	})

	t.Run("nested_constructor_call_arguments_are_direct_argument_list_children", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "outer(inner(value))\n")
		outer := firstNodeOfType(root, pythonNodeCall)
		if outer == nil {
			t.Fatal("outer call not found")
		}
		var argList *sitter.Node
		for i := 0; i < int(outer.ChildCount()); i++ {
			if outer.Child(i).Type() == pythonNodeArgumentList {
				argList = outer.Child(i)
			}
		}
		if argList == nil {
			t.Fatal("outer call argument_list not found")
		}
		var nestedCall *sitter.Node
		for i := 0; i < int(argList.ChildCount()); i++ {
			if argList.Child(i).Type() == pythonNodeCall {
				nestedCall = argList.Child(i)
			}
		}
		if nestedCall == nil {
			t.Fatal("inner(value) is not a direct child of outer's argument_list")
		}
		innerFn := nestedCall.Child(0)
		if innerFn == nil || innerFn.Type() != goNodeIdentifier || innerFn.Content(src) != "inner" {
			t.Fatalf("nested call function = %v, want identifier \"inner\"", innerFn)
		}
	})

	t.Run("lambda_uses_parameters_and_body_fields", func(t *testing.T) {
		root, src := parsePythonGrammarSnippet(t, "transform = lambda x: process(x)\n")
		lambdaNode := firstNodeOfType(root, "lambda")
		if lambdaNode == nil {
			t.Fatal("lambda not found")
		}
		params := lambdaNode.ChildByFieldName("parameters")
		if params == nil || params.Type() != "lambda_parameters" {
			t.Fatalf("lambda parameters field = %v, want lambda_parameters", params)
		}
		ident := firstNodeOfType(params, goNodeIdentifier)
		if ident == nil || ident.Content(src) != "x" {
			t.Fatalf("lambda parameter identifier = %v, want \"x\"", ident)
		}
		body := lambdaNode.ChildByFieldName("body")
		if body == nil || body.Type() != pythonNodeCall {
			t.Fatalf("lambda body field = %v, want call", body)
		}
	})
}

// TestPythonGrammarFacts_ReturnTypeField (T0.2, python-parser-parity-2) pins
// that function_definition carries a "return_type" field whose child is a
// "type" node — A2 depends on reading this field directly instead of
// re-deriving the return type from the whole definition's Content(src).
func TestPythonGrammarFacts_ReturnTypeField(t *testing.T) {
	root, src := parsePythonGrammarSnippet(t, "def encrypt(data: bytes) -> Cipher:\n    return active\n")
	fn := firstNodeOfType(root, pythonNodeFunctionDefinition)
	if fn == nil {
		t.Fatal("function_definition not found")
	}
	returnType := fn.ChildByFieldName("return_type")
	if returnType == nil {
		t.Fatal("function_definition return_type field is nil")
	}
	if returnType.Type() != "type" {
		t.Fatalf("return_type field node type = %q, want \"type\"", returnType.Type())
	}
	ident := firstNodeOfType(returnType, goNodeIdentifier)
	if ident == nil || ident.Content(src) != "Cipher" {
		t.Fatalf("return_type identifier = %v, want \"Cipher\"", ident)
	}
}

// findAllNodesOfType returns every node of the given type found via pre-order
// (document-order) traversal.
func findAllNodesOfType(node *sitter.Node, nodeType string) []*sitter.Node {
	if node == nil {
		return nil
	}
	var out []*sitter.Node
	if node.Type() == nodeType {
		out = append(out, node)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		out = append(out, findAllNodesOfType(node.Child(i), nodeType)...)
	}
	return out
}
