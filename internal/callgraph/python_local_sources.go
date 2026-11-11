package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

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
	// root is the StartByte of the outermost function_definition this index
	// belongs to. A binding under a nested def, class or lambda binds in THAT
	// scope, not the function's, so it can only poison the name here.
	root uint32
	// work, when non-nil, counts every map probe and ancestor step the index
	// takes, so a test can bound the cost per binding and per argument.
	work *int
	// module marks the file-level index: comprehension targets, lambda
	// parameters and a def's parameters bind in their own scope there, so only
	// a def's name poisons.
	module bool
	// all poisons every name in the file-level index: the file rebinds names
	// dynamically (exec, globals(), setattr on the module).
	all bool
}

func (s *pythonLocalSources) tick() {
	if s.work != nil {
		*s.work++
	}
}

type pythonLocalSource struct {
	// value is the right-hand side node shared by every binding, kept so the
	// use site resolves it in its own binding layer.
	value *sitter.Node
	text  string
	// root is the leading name of a dotted constructor call (`ec` in
	// `ec.SECP521R1()`), empty for an integer literal.
	root     string
	poisoned bool
	// parameter marks a parameter of the indexed function that callers can
	// pass by position, at parameterIndex. rebound records any other binding
	// of the name, after which the value at a use may differ from the
	// caller's argument.
	parameter      bool
	rebound        bool
	parameterIndex int
	// bindings counts the statements that bind the name, and kind is what
	// the first one binds, so a use can require one import or one class.
	bindings int
	kind     pythonBindingKind
	// construction is the call the first binding assigns, for a receiver
	// bound exactly once; mutated records an attribute write through the name.
	construction *sitter.Node
	mutated      bool
}

type pythonBindingKind uint8

const (
	pythonBoundOther pythonBindingKind = iota
	pythonBoundImport
	pythonBoundClass
)

func (e *pythonLocalSource) note(kind pythonBindingKind) {
	if e.bindings == 0 {
		e.kind = kind
	}
	e.bindings++
}

// boundOnlyBy reports whether exactly one statement binds name, of kind.
func (s *pythonLocalSources) boundOnlyBy(name string, kind pythonBindingKind) bool {
	if s.all {
		return false
	}
	e := s.byName[name]
	return e != nil && e.bindings == 1 && e.kind == kind
}

func (s *pythonLocalSources) entry(name string) *pythonLocalSource {
	s.tick()
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

func (s *pythonLocalSources) bind(name string, value *sitter.Node, text, root string) {
	e := s.entry(name)
	e.rebound = e.rebound || e.parameter
	e.note(pythonBoundOther)
	switch {
	case e.poisoned:
	case e.value == nil && e.text == "":
		e.value, e.text, e.root = value, text, root
	case e.text != text:
		e.poisoned = true
	}
}

func (s *pythonLocalSources) poison(name string) {
	e := s.entry(name)
	e.note(pythonBoundOther)
	e.poisoned = true
	e.rebound = e.rebound || e.parameter
}

// bindParameters records the indexed function's parameters. Every name stays
// poisoned for lookup, since its value comes from the caller; the first
// positional ones are kept as parameters a caller fills by position.
func (s *pythonLocalSources) bindParameters(names []string, positional int) {
	for i, name := range names {
		e := s.entry(name)
		e.poisoned = true
		if i < positional {
			e.parameter, e.parameterIndex = true, i
		}
	}
}

// parameterSource returns the parameter index a use of name reads, ok only
// when the function never rebinds the parameter.
func (s *pythonLocalSources) parameterSource(name string) (index int, ok bool) {
	if s == nil || s.all {
		return 0, false
	}
	e := s.byName[name]
	if e == nil || !e.parameter || e.rebound {
		return 0, false
	}
	return e.parameterIndex, true
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
	s.tick()
	if s.all {
		return nil, true
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
	case pythonSyms.forInClause:
		if !s.module {
			s.poisonTarget(node.ChildByFieldName("left"), src)
		}
	case pythonSyms.augmentedAssignment, pythonSyms.forStatement:
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
		if !s.module {
			s.poisonIdentifiers(node.ChildByFieldName("parameters"), src)
		}
	case pythonSyms.lambdaParameters:
		if !s.module {
			s.poisonIdentifiers(node, src)
		}
	case pythonSyms.wildcardImport:
		s.poisonExisting()
	case pythonSyms.importStatement, pythonSyms.importFromStatement:
		s.observeImport(node, src)
	case pythonSyms.globalStatement, pythonSyms.nonlocalStatement, pythonSyms.deleteStatement,
		pythonSyms.casePattern, pythonSyms.typeAliasStatement:
		s.poisonIdentifiers(node, src)
	}
}

// inNestedScope reports whether node sits under a def, class or lambda nested
// inside the indexed function. The climb is bounded by the node's own
// statement nesting depth.
func (s *pythonLocalSources) inNestedScope(node *sitter.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		s.tick()
		switch p.Symbol() {
		case pythonSyms.functionDefinition:
			return p.StartByte() != s.root
		case pythonSyms.classDefinition, pythonSyms.lambda:
			return true
		}
	}
	return false
}

// observeClassName poisons a class statement's own name; pythonWalkClass
// returns before observe sees the node.
func (s *pythonLocalSources) observeClassName(node *sitter.Node, src []byte) {
	if name := node.ChildByFieldName(pythonFieldName); name != nil {
		e := s.entry(name.Content(src))
		e.poisoned = true
		e.note(pythonBoundClass)
	}
}

// observeImport poisons every name an import statement spells and counts one
// import binding for each name it binds: `import a.b` binds a, `as x` binds x.
func (s *pythonLocalSources) observeImport(node *sitter.Node, src []byte) {
	s.markPoisoned(node, src)
	from := node.Symbol() == pythonSyms.importFromStatement
	for i := 0; i < int(node.ChildCount()); i++ {
		if from && node.FieldNameForChild(i) != pythonFieldName {
			continue
		}
		var bound string
		switch child := node.Child(i); child.Symbol() {
		case pythonSyms.dottedName:
			bound, _, _ = strings.Cut(child.Content(src), ".")
		case pythonSyms.aliasedImport:
			if alias := child.ChildByFieldName("alias"); alias != nil {
				bound = alias.Content(src)
			}
		}
		if bound != "" {
			s.entry(bound).note(pythonBoundImport)
		}
	}
}

func (s *pythonLocalSources) markPoisoned(node *sitter.Node, src []byte) {
	if node.Symbol() == pythonSyms.identifier {
		e := s.entry(node.Content(src))
		e.poisoned = true
		e.rebound = e.rebound || e.parameter
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.markPoisoned(node.NamedChild(i), src)
	}
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
	if right != nil && !s.inNestedScope(node) {
		if root, ok := pythonLocalSourceRoot(right, src); ok {
			s.bind(name, right, right.Content(src), root)
			return
		}
	}
	s.poison(name)
	if e := s.byName[name]; right != nil && right.Symbol() == pythonSyms.call && e.bindings == 1 && !s.inNestedScope(node) {
		e.construction = right
	}
}

// construction returns the call that constructs the receiver name, when the
// function binds name exactly once, to that call, and writes none of its
// attributes. A module-level name is left out: any module may rebind it.
func (s *pythonLocalSources) construction(name string) *sitter.Node {
	if s == nil || s.all || s.module {
		return nil
	}
	e := s.byName[name]
	if e == nil || e.bindings != 1 || e.parameter || e.mutated {
		return nil
	}
	return e.construction
}

// poisonTarget poisons every name a binding target introduces. An attribute
// or subscript target binds no name.
func (s *pythonLocalSources) poisonTarget(target *sitter.Node, src []byte) {
	if target == nil {
		return
	}
	if sym := target.Symbol(); sym == pythonSyms.attribute || sym == pythonSyms.subscript {
		if object := target.ChildByFieldName("object"); sym == pythonSyms.attribute && object != nil && object.Symbol() == pythonSyms.identifier {
			s.entry(object.Content(src)).mutated = true
		}
		return
	}
	s.poisonIdentifiers(target, src)
}

// pythonLocalSourceRoot admits the value shapes a key size or an algorithm name
// can come from: an integer literal or a plain string literal (empty root),
// and a zero-argument call through a dotted name (a curve constructor such as
// ec.SECP521R1()), whose leading name is returned so the use site can require
// it to be an import.
func pythonLocalSourceRoot(value *sitter.Node, src []byte) (root string, ok bool) {
	switch value.Symbol() {
	case pythonSyms.integer:
		return "", true
	case pythonSyms.string:
		return "", pythonPlainString(value, src)
	case pythonSyms.call:
		args := value.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 0 {
			return "", false
		}
		fn := value.ChildByFieldName("function")
		if fn == nil || fn.Symbol() != pythonSyms.attribute {
			return "", false
		}
		return pythonDottedRoot(fn, src)
	default:
		return "", false
	}
}

// pythonPlainString admits a string literal whose source text is its value:
// one quote character, no prefix (f, b, r, u), no escape sequence, no
// interpolation.
func pythonPlainString(value *sitter.Node, src []byte) bool {
	for i := 0; i < int(value.NamedChildCount()); i++ {
		child := value.NamedChild(i)
		switch child.Type() {
		case "string_start":
			if start := child.Content(src); start != `"` && start != "'" {
				return false
			}
		case "string_content":
			if child.NamedChildCount() != 0 {
				return false
			}
		case "string_end":
		default:
			return false
		}
	}
	return true
}

func pythonDottedRoot(node *sitter.Node, src []byte) (string, bool) {
	for node != nil {
		switch node.Symbol() {
		case pythonSyms.identifier:
			return node.Content(src), true
		case pythonSyms.attribute:
			if attr := node.ChildByFieldName("attribute"); attr == nil || attr.Symbol() != pythonSyms.identifier {
				return "", false
			}
			node = node.ChildByFieldName("object")
		default:
			return "", false
		}
	}
	return "", false
}

// poisonExisting poisons every name bound so far: `from m import *` can
// rebind any of them, while a name bound after it overrides the import.
func (s *pythonLocalSources) poisonExisting() {
	for _, e := range s.byName {
		s.tick()
		e.note(pythonBoundOther)
		e.poisoned = true
		e.rebound = e.rebound || e.parameter
	}
}

// observeDynamicBinding poisons the whole file-level index when a call can
// bind module names by string: exec, globals()/vars()/locals() (a module-level
// locals() is the module dict) and setattr on the module object.
func (s *pythonLocalSources) observeDynamicBinding(call *sitter.Node, src []byte) {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Symbol() != pythonSyms.identifier {
		return
	}
	switch string(src[fn.StartByte():fn.EndByte()]) {
	case "exec", "globals", "vars", "locals":
		s.all = true
	case "setattr":
		if args := call.ChildByFieldName("arguments"); args != nil {
			text := args.Content(src)
			if strings.Contains(text, "sys.modules") || strings.Contains(text, "__name__") || strings.Contains(text, "globals") {
				s.all = true
			}
		}
	}
}
