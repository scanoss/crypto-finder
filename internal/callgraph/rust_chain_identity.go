package callgraph

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// Rust node kinds that participate in chain identity but carry no call of their
// own. `?` parses as try_expression, `.await` as await_expression, and a
// parenthesised link as parenthesized_expression; each sits BETWEEN a chain link
// and the field_expression that names the next one, so a walk that does not step
// over them reports `a().b()?.c()` as two chains instead of one.
const (
	rustNodeTryExpression           = "try_expression"
	rustNodeAwaitExpression         = "await_expression"
	rustNodeParenthesizedExpression = "parenthesized_expression"
	rustNodeAssignmentExpression    = "assignment_expression"
	rustNodeMutPattern              = "mut_pattern"
	rustNodeRefPattern              = "ref_pattern"
	rustNodeFieldIdentifier         = "field_identifier"
)

// rustCallChainContext returns the ChainID and AssignedVar of a Rust
// call_expression.
//
// ChainID groups the links of one fluent method chain so that downstream passes
// can treat them as a single crypto object:
// resolveFluentChainCalleesByContract re-qualifies each link from the previous
// link's KB return type, deriveObjectLifecycleCalls pulls sibling links into a
// terminal's supporting calls, and terminal_selection picks the chain root and
// the outermost link. Every one of those skips a call whose ChainID is empty, so
// leaving it unset does not degrade them — it turns them off.
//
// The identity is the chain root's start byte: unique per chain within a file,
// stable, and shared by every link because each link derives it from the same
// root. Mirrors nodeCallChainContext (node_parser.go) and
// pythonCallChainContext (python_parser.go).
//
// AssignedVar is set only on the chain root — the link whose result is what the
// binding receives — and only for a single-name or self-field target, matching
// the Java and Python parsers.
func rustCallChainContext(node *sitter.Node, src []byte) (chainID, assignedVar string) {
	if node == nil {
		return "", ""
	}
	root := rustChainRootNode(node)
	if !sameSyntaxNode(root, node) {
		// An inner link: it shares the root's identity and binds nothing itself.
		return fmt.Sprintf("%d", root.StartByte()), ""
	}
	// The root is only a chain when something is chained BELOW it. A lone
	// `Aes256Gcm::new(key)` is a call, not a chain, and marking it would make
	// terminal_selection treat it as one.
	if rustCallHasChainedReceiver(node) {
		chainID = fmt.Sprintf("%d", root.StartByte())
	}
	return chainID, rustAssignedVarFromParent(root, src)
}

// rustCallHasChainedReceiver reports whether this call is invoked on the result
// of another call — `A::builder().b()` for the outer link, but not `y.z(1)`,
// whose receiver is a plain variable.
func rustCallHasChainedReceiver(node *sitter.Node) bool {
	callee := node.ChildByFieldName("function")
	if callee == nil {
		return false
	}
	// A turbofish on this link wraps its callee in a generic_function.
	if callee.Type() == rustNodeGenericFunction && callee.NamedChildCount() > 0 {
		callee = callee.NamedChild(0)
	}
	if callee.Type() != rustNodeFieldExpression {
		return false
	}
	receiver := rustSkipChainWrappers(callee.ChildByFieldName("value"))
	return receiver != nil && receiver.Type() == rustNodeCallExpression
}

// rustChainRootNode walks UP from a chain link to the outermost call of the same
// fluent chain, returning node itself when nothing is chained above it.
//
// Rust nests a chain the same way Python and JavaScript do, outermost-first:
//
//	call[.unwrap()] → field_expression[….unwrap] → call[.d()] →
//	field_expression[….d] → try_expression[…?] → call[.c()] → …
func rustChainRootNode(node *sitter.Node) *sitter.Node {
	root := node
	for {
		next := rustEnclosingChainLink(root)
		if next == nil {
			return root
		}
		root = next
	}
}

// rustEnclosingChainLink returns the call_expression that invokes a method on
// the result of `node`, or nil when `node` is not the receiver of a further
// call.
func rustEnclosingChainLink(node *sitter.Node) *sitter.Node {
	// Step over the postfix wrappers first: from `c()` in `c()?.d()`, the parent
	// is the try_expression, and it is the TRY that the field_expression names
	// as its value.
	value := node
	for {
		parent := value.Parent()
		if parent == nil {
			return nil
		}
		if rustIsChainWrapper(parent) {
			value = parent
			continue
		}
		if parent.Type() != rustNodeFieldExpression ||
			!sameSyntaxNode(parent.ChildByFieldName("value"), value) {
			return nil
		}
		callee := parent
		// The next link may carry a turbofish: `a().collect::<Vec<_>>()`.
		if gp := callee.Parent(); gp != nil && gp.Type() == rustNodeGenericFunction &&
			gp.NamedChildCount() > 0 && sameSyntaxNode(gp.NamedChild(0), callee) {
			callee = gp
		}
		call := callee.Parent()
		if call == nil || call.Type() != rustNodeCallExpression ||
			!sameSyntaxNode(call.ChildByFieldName("function"), callee) {
			// A field_expression that is not a callee is a field READ
			// (`a().field`), which ends the chain rather than extending it.
			return nil
		}
		return call
	}
}

func rustIsChainWrapper(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	switch node.Type() {
	case rustNodeTryExpression, rustNodeAwaitExpression, rustNodeParenthesizedExpression:
		return true
	}
	return false
}

func rustSkipChainWrappers(node *sitter.Node) *sitter.Node {
	for rustIsChainWrapper(node) {
		if node.NamedChildCount() == 0 {
			return node
		}
		node = node.NamedChild(0)
	}
	return node
}

// rustAssignedVarFromParent returns the variable a chain root's result is bound
// to: `let cred = …` and `let mut cred = …` yield "cred", `self.inner = …`
// yields "self.inner". Any other target shape — a tuple destructure, a struct
// pattern, an index — returns "", because AssignedVar identifies ONE object and
// those bind several or none.
func rustAssignedVarFromParent(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	// The binding may sit above a postfix wrapper: `let x = a().b()?;` puts the
	// try_expression between the chain root and the let.
	for rustIsChainWrapper(parent) {
		node = parent
		parent = parent.Parent()
	}
	if parent == nil {
		return ""
	}
	switch parent.Type() {
	case rustNodeLetDeclaration:
		if !sameSyntaxNode(parent.ChildByFieldName("value"), node) {
			return ""
		}
		return rustBindingTargetIdentity(parent.ChildByFieldName("pattern"), src)
	case rustNodeAssignmentExpression:
		if !sameSyntaxNode(parent.ChildByFieldName("right"), node) {
			return ""
		}
		return rustBindingTargetIdentity(parent.ChildByFieldName("left"), src)
	}
	return ""
}

// rustBindingTargetIdentity reads the single name a binding target introduces,
// unwrapping the `mut` and `ref` pattern nodes that carry no identity of their
// own.
func rustBindingTargetIdentity(target *sitter.Node, src []byte) string {
	for target != nil &&
		(target.Type() == rustNodeMutPattern || target.Type() == rustNodeRefPattern) {
		if target.NamedChildCount() == 0 {
			return ""
		}
		target = target.NamedChild(0)
	}
	if target == nil {
		return ""
	}
	switch target.Type() {
	case goNodeIdentifier:
		return target.Content(src)
	case rustNodeFieldExpression:
		// `self.inner = …`. Canonicalized to "self.<field>" exactly as the
		// Python parser canonicalizes self/cls attributes, so a field-held
		// object has one identity across the calls that touch it.
		value := target.ChildByFieldName("value")
		field := target.ChildByFieldName("field")
		if value == nil || field == nil ||
			value.Type() != rustNodeSelf || field.Type() != rustNodeFieldIdentifier {
			return ""
		}
		return rustNodeSelf + "." + field.Content(src)
	}
	return ""
}

// rustReceiverVarIdentity returns the variable identity of a method call's
// receiver: a plain binding verbatim, `self`, and a field held on self as
// "self.<field>".
//
// The field shape is what a builder stored in a struct looks like —
// `self.inner.connect(cred, socket)` — and without it every call on such a
// builder is an object with no identity, so none of them can be linked to the
// call that produced it.
//
// A receiver that is not a name — a call (the chain case, which ChainID
// covers), a temporary, an index — has no variable identity and returns "".
func rustReceiverVarIdentity(receiver *sitter.Node, src []byte) string {
	if receiver == nil {
		return ""
	}
	switch receiver.Type() {
	case goNodeIdentifier, rustNodeSelf:
		return receiver.Content(src)
	case rustNodeFieldExpression:
		value := receiver.ChildByFieldName("value")
		field := receiver.ChildByFieldName("field")
		if value == nil || field == nil ||
			value.Type() != rustNodeSelf || field.Type() != rustNodeFieldIdentifier {
			return ""
		}
		return rustNodeSelf + "." + field.Content(src)
	}
	return ""
}
