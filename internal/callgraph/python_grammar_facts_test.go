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
			case "dictionary_splat_pattern":
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
		if moduleName == nil || moduleName.Type() != "relative_import" {
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
		if moduleName == nil || moduleName.Type() != "relative_import" {
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
		if nameField == nil || nameField.Type() != "aliased_import" {
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
		if nameField == nil || nameField.Type() != "aliased_import" {
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
