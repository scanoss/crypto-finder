package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// pythonLocalSources indexes, for ONE outermost function scope, every name the
// function can bind, in the same descent pythonWalk already makes, so a call
// argument that names a local resolves with one map lookup and no rescan of the
// function body.
//
// A local resolves only when EVERY binding of that name anywhere in the
// function subtree is a plain `name = <literal>` whose source text is
// identical. Python makes a name local to the whole function, so a use that
// runs before any binding raises instead of reading a different value: the
// shared value is the only one the use can ever observe. Anything else poisons
// the name, and a poisoned name resolves to nothing: an extra assignment, an
// augmented assignment, a loop or `with`/`except` target, tuple unpacking,
// walrus, a parameter of the function or of a nested def/lambda, an import, a
// nested def/class of that name, `global`/`nonlocal`/`del`, a match capture, or
// a value that is not an integer literal or a zero-argument constructor call.
// The index is deliberately flow-insensitive: where the assignment sits
// (if/else, loop, try) cannot change the value, only whether it exists.
type pythonLocalSources struct {
	byName map[string]*pythonLocalSource
}

type pythonLocalSource struct {
	// value is the right-hand side node shared by every binding, kept so the
	// use site resolves it in its own binding layer.
	value    *sitter.Node
	text     string
	poisoned bool
}

func (s *pythonLocalSources) entry(name string) *pythonLocalSource {
	if s.byName == nil {
		s.byName = make(map[string]*pythonLocalSource)
	}
	e := s.byName[name]
	if e == nil {
		e = &pythonLocalSource{}
		s.byName[name] = e
	}
	return e
}

func (s *pythonLocalSources) bind(name string, value *sitter.Node, text string) {
	e := s.entry(name)
	switch {
	case e.poisoned:
	case e.value == nil && e.text == "":
		e.value, e.text = value, text
	case e.text != text:
		e.poisoned = true
	}
}

func (s *pythonLocalSources) poison(name string) {
	s.entry(name).poisoned = true
}

func (s *pythonLocalSources) poisonIdentifiers(node *sitter.Node, src []byte) {
	if node == nil {
		return
	}
	if node.Symbol() == pythonSyms.identifier {
		s.poison(node.Content(src))
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.poisonIdentifiers(node.NamedChild(i), src)
	}
}

// lookup returns the resolvable source of a local name, with known reporting
// whether the function binds the name at all (a known name never falls back to
// a same-named module constant).
func (s *pythonLocalSources) lookup(name string) (source *pythonLocalSource, known bool) {
	if s == nil {
		return nil, false
	}
	e, ok := s.byName[name]
	if !ok {
		return nil, false
	}
	if e.poisoned {
		return nil, true
	}
	return e, true
}

// observe records the bindings one node of the function subtree creates.
func (s *pythonLocalSources) observe(node *sitter.Node, sym sitter.Symbol, src []byte) {
	switch sym {
	case pythonSyms.assignment:
		s.observeAssignment(node, src)
	case pythonSyms.augmentedAssignment, pythonSyms.forStatement, pythonSyms.forInClause:
		s.poisonTarget(node.ChildByFieldName("left"), src)
	case pythonSyms.namedExpression:
		s.poisonIdentifiers(node.ChildByFieldName("name"), src)
	case pythonSyms.asPattern:
		if alias := node.ChildByFieldName("alias"); alias != nil {
			s.poisonIdentifiers(alias, src)
		} else {
			s.poisonIdentifiers(node, src)
		}
	case pythonSyms.functionDefinition:
		s.poisonIdentifiers(node.ChildByFieldName("name"), src)
		s.poisonIdentifiers(node.ChildByFieldName("parameters"), src)
	case pythonSyms.lambdaParameters:
		s.poisonIdentifiers(node, src)
	case pythonSyms.importStatement, pythonSyms.importFromStatement,
		pythonSyms.globalStatement, pythonSyms.nonlocalStatement, pythonSyms.deleteStatement,
		pythonSyms.casePattern, pythonSyms.typeAliasStatement:
		s.poisonIdentifiers(node, src)
	}
}

// observeClassName poisons a class statement's own name; pythonWalkClass
// returns before observe sees the node.
func (s *pythonLocalSources) observeClassName(node *sitter.Node, src []byte) {
	s.poisonIdentifiers(node.ChildByFieldName("name"), src)
}

func (s *pythonLocalSources) observeAssignment(node *sitter.Node, src []byte) {
	left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
	if left == nil {
		return
	}
	if left.Symbol() != pythonSyms.identifier {
		s.poisonTarget(left, src)
		return
	}
	name := left.Content(src)
	if right != nil && isPythonLocalSourceValue(right) {
		s.bind(name, right, right.Content(src))
		return
	}
	s.poison(name)
}

// poisonTarget poisons every name a binding target introduces. An attribute
// or subscript target binds no name.
func (s *pythonLocalSources) poisonTarget(target *sitter.Node, src []byte) {
	if target == nil {
		return
	}
	if sym := target.Symbol(); sym == pythonSyms.attribute || sym == pythonSyms.subscript {
		return
	}
	s.poisonIdentifiers(target, src)
}

// isPythonLocalSourceValue admits the two value shapes a key size can come
// from: an integer literal and a zero-argument call through a dotted name (a
// curve constructor such as ec.SECP521R1()).
func isPythonLocalSourceValue(value *sitter.Node) bool {
	switch value.Symbol() {
	case pythonSyms.integer:
		return true
	case pythonSyms.call:
		args := value.ChildByFieldName("arguments")
		return args != nil && args.NamedChildCount() == 0 && isPythonDottedName(value.ChildByFieldName("function"))
	default:
		return false
	}
}

func isPythonDottedName(node *sitter.Node) bool {
	for node != nil {
		switch node.Symbol() {
		case pythonSyms.identifier:
			return true
		case pythonSyms.attribute:
			if attr := node.ChildByFieldName("attribute"); attr == nil || attr.Symbol() != pythonSyms.identifier {
				return false
			}
			node = node.ChildByFieldName("object")
		default:
			return false
		}
	}
	return false
}
