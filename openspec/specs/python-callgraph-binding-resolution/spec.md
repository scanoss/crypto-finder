# python-callgraph-binding-resolution Specification

## Purpose

Python object-identity resolution (receiver/assignment/chain), synthetic entry
points, and import/re-export resolution feeding reachability and
supporting-call derivation in `internal/callgraph/python_parser.go`, so Python
reaches the same structural precision Java already has. This is a new
capability (`openspec/specs/` is currently empty for Python); all requirements
below are ADDED. Out of scope: KB YAML, export schema, `supporting_calls.go`
semantics, and deferred exploration rows 6-9, 11, 13, 14, 17, 18, 20.

## Requirements

### Requirement: Parameter-as-receiver binding

The parser MUST register every function/method parameter name as a known
local variable so a crypto object passed as a parameter resolves as
`ReceiverVar`/`AssignedVar` on calls made through it, matching Java's
`collectParameterTypes`/`collectParameterOrigins` coverage.

#### Scenario: Parameter used as a call receiver

- GIVEN a Python function `def encrypt(cipher): cipher.update(data)`
- WHEN the parser builds the `FunctionDecl` for `encrypt`
- THEN the `cipher.update(data)` call's `ReceiverVar` MUST equal `"cipher"`
- Pinned by: `TestPythonParser_ReceiverVar_Parameter` in `internal/callgraph/python_parser_test.go`

#### Scenario: Parameter feeding supporting-call grouping

- GIVEN a function with a parameter object receiving a terminal crypto call and a prior setup call, both on the same parameter
- WHEN `internal/scan/supporting_calls.go` derives object lifecycle for the terminal finding
- THEN the setup call on the parameter MUST be grouped as a supporting call
- Pinned by: `TestDeriveObjectLifecycleCalls_ParameterReceiver` in `internal/scan/supporting_calls_test.go`

### Requirement: Non-assignment binding coverage

The parser MUST resolve `ReceiverVar`/`AssignedVar` for objects bound by
`with...as`, `for...in`, `except...as`, `async with...as`, `async for...in`,
walrus (`:=`), tuple/star unpacking, and comprehension targets — not only
plain `x = ...` assignment.

#### Scenario: `with...as` binds a receiver

- GIVEN `with Cipher() as c: c.encrypt(data)`
- WHEN the parser walks the `with_statement` body
- THEN `c.encrypt(data)`'s `ReceiverVar` MUST equal `"c"`
- Pinned by: `TestPythonParser_ReceiverVar_WithAs` in `internal/callgraph/python_parser_test.go`

#### Scenario: `async with...as` binds a receiver

- GIVEN `async with AsyncCipher() as c: await c.encrypt(data)`
- WHEN the parser walks the `with_statement` (async variant) body
- THEN `c.encrypt(data)`'s `ReceiverVar` MUST equal `"c"`
- Pinned by: `TestPythonParser_ReceiverVar_AsyncWithAs` in `internal/callgraph/python_parser_test.go`

#### Scenario: `for...in` binds a receiver

- GIVEN `for k in keys: k.derive(salt)`
- WHEN the parser walks the `for_statement` body
- THEN `k.derive(salt)`'s `ReceiverVar` MUST equal `"k"`
- Pinned by: `TestPythonParser_ReceiverVar_ForIn` in `internal/callgraph/python_parser_test.go`

#### Scenario: `async for...in` binds a receiver

- GIVEN `async for k in akeys: await k.derive(salt)`
- WHEN the parser walks the `for_statement` (async variant) body
- THEN `k.derive(salt)`'s `ReceiverVar` MUST equal `"k"`
- Pinned by: `TestPythonParser_ReceiverVar_AsyncForIn` in `internal/callgraph/python_parser_test.go`

#### Scenario: `except...as` binds a receiver

- GIVEN `except CryptoError as e: e.cipher.close()`
- WHEN the parser walks the `except_clause` body
- THEN `e.cipher.close()`'s receiver chain MUST resolve `e` as a known local
- Pinned by: `TestPythonParser_ReceiverVar_ExceptAs` in `internal/callgraph/python_parser_test.go`

#### Scenario: Walrus operator binds a receiver

- GIVEN `if (c := Cipher()) is not None: c.encrypt(data)`
- WHEN the parser walks the `named_expression` inside the `if` condition and the `if` body
- THEN `c.encrypt(data)`'s `ReceiverVar` MUST equal `"c"`
- Pinned by: `TestPythonParser_ReceiverVar_Walrus` in `internal/callgraph/python_parser_test.go`

#### Scenario: Tuple/star unpacking binds every target

- GIVEN `a, *rest = make_ciphers()` followed by `a.encrypt(data)`
- WHEN the parser walks the `assignment` with a `pattern_list`/`tuple_pattern` left side
- THEN `a` MUST be registered as a known local and `a.encrypt(data)`'s `ReceiverVar` MUST equal `"a"`
- Pinned by: `TestPythonParser_ReceiverVar_TupleUnpacking` in `internal/callgraph/python_parser_test.go`

#### Scenario: Comprehension target does not leak outside its scope

- GIVEN `[c.encrypt(x) for c in ciphers]` inside a function, followed by a call on an unrelated bare name `c` outside the comprehension
- WHEN the parser walks the `list_comprehension`'s `for_in_clause` target and the enclosing function body
- THEN `c.encrypt(x)` inside the comprehension MUST resolve `ReceiverVar="c"`
- AND a `c.method()` call outside the comprehension MUST NOT be silently attributed to the comprehension-scoped binder if no such name exists in the enclosing scope
- Pinned by: `TestPythonParser_ReceiverVar_ComprehensionTarget` in `internal/callgraph/python_parser_test.go`

### Requirement: `self`/`cls` instance-attribute provenance

The parser MUST track class-scoped attribute assignments of the shape
`self.attr = <expr>` (and `cls.attr = <expr>` in classmethods) made in ANY
method of the enclosing class, and MUST resolve `self.attr`/`cls.attr` as a
stable receiver identity on calls elsewhere in the same class, mirroring
Java's `collectClassFieldAssignments`. Inheritance (base-class attribute
assignments) is NOT followed in this change — only assignments within the
literal class body being parsed. Reassignment of `self.attr` rebinds its
identity going forward: calls made after a later `self.attr = ...` group
under the new binding, and calls made before it group under the prior one —
mirroring Java field-rebinding lifecycle scoping (commit `a9dae82`). Known
ceiling: `deriveObjectLifecycleCalls` examines one `FunctionDecl`, so
cross-method lifecycle grouping (assignment in `__init__`, calls in another
method) is NOT joined by this change — the gain is stable receiver/callee
identity, not cross-method grouping.

#### Scenario: `self.attr` assigned in `__init__`, used in another method

- GIVEN `def __init__(self): self.cipher = Cipher()` and, in a sibling method, `def run(self): self.cipher.encrypt(data)`
- WHEN the parser builds both method `FunctionDecl`s for the enclosing class
- THEN `self.cipher.encrypt(data)`'s receiver MUST resolve to a stable identity for `self.cipher` shared with the `__init__` assignment
- Pinned by: `TestPythonParser_SelfAttr_CrossMethodProvenance` in `internal/callgraph/python_parser_test.go`

#### Scenario: `cls.attr` assigned in a classmethod

- GIVEN `@classmethod\ndef setup(cls): cls.cipher = Cipher()` and, in a sibling method, `cls.cipher.encrypt(data)`
- WHEN the parser resolves the class-scoped attribute map
- THEN the `cls.cipher` receiver MUST resolve using the same class-scoped identity as a `self.cipher` binding would
- Pinned by: `TestPythonParser_ClsAttr_ClassmethodProvenance` in `internal/callgraph/python_parser_test.go`

#### Scenario: Reassignment splits lifecycle scope

- GIVEN, all within one method body, `self.cipher = AES()` followed by `self.cipher.encrypt(a)`, then `self.cipher = RSA()` followed by `self.cipher.encrypt(b)`
- WHEN `internal/scan/supporting_calls.go` derives object lifecycle for both terminal `encrypt` findings in that single `FunctionDecl`
- THEN calls before the second `self.cipher = RSA()` MUST group under the first binding, and calls after it MUST group under the second, never mixed
- Pinned by: `TestDeriveObjectLifecycleCalls_SelfAttrRebinding` in `internal/scan/supporting_calls_test.go`

#### Scenario: Inheritance is not followed

- GIVEN a base class assigning `self.cipher = Cipher()` in `__init__`, and a subclass method calling `self.cipher.encrypt(data)` without its own assignment
- WHEN the parser resolves the subclass's class-scoped attribute map
- THEN `self.cipher` in the subclass MUST NOT resolve to the base class's assignment (no receiver identity is fabricated across class bodies)
- Pinned by: `TestPythonParser_SelfAttr_NoInheritance` in `internal/callgraph/python_parser_test.go`

### Requirement: Synthetic module-level and class-body entry points

The parser MUST emit one synthetic `FunctionDecl` per module for calls made
directly in module-level statements (outside any function/class), named
`FunctionID{Package: <module dotted path>, Type: "", Name: "<module>"}`,
mirroring CPython's own module code-object name. `Package` MUST be the
module's own dotted path — `pkg.a` for `pkg/a.py`, `pkg` for
`pkg/__init__.py` — not the directory package path, so sibling files in one
package never collide on the `<module>` key. The parser MUST emit one
synthetic `FunctionDecl` per class for calls made directly in class-body
statements (outside any method), named `FunctionID{Package: <module package
path>, Type: <class name>, Name: "<clinit>"}`, reusing Java's synthetic
`<clinit>` name for cross-language consistency even though it names a
crypto-finder synthetic construct, not a Python runtime symbol. Both names
MUST serialize through the existing `FunctionDecl`/`FunctionID` fields only —
no new export schema field. A module or class body with no calls in its
direct statements MUST NOT produce a synthetic entry point (no
`<module>`/`<clinit>` decl for an empty or call-free body).

#### Scenario: Module-level crypto call gets a synthetic entry point

- GIVEN a module with a top-level statement `cipher = Cipher()` and no other functions
- WHEN the parser builds `FileAnalysis.Functions` for that file
- THEN a `FunctionDecl` with `ID.Name == "<module>"` and `ID.Type == ""` MUST exist, containing the `Cipher()` call
- AND its `ID.Package` MUST equal the module's dotted path (`pkg.a` for `pkg/a.py`; `pkg` for `pkg/__init__.py`)
- AND it MUST be an entry point (no incoming call edges) in the resulting graph
- Pinned by: `TestPythonParser_SyntheticEntryPoint_ModuleLevel` in `internal/callgraph/python_parser_test.go`

#### Scenario: Class-body statement crypto call gets a synthetic entry point

- GIVEN `class Foo:\n    default_cipher = Cipher()` with no calls in `default_cipher = Cipher()` routed through any method
- WHEN the parser builds the class-body synthetic decl for `Foo`
- THEN a `FunctionDecl` with `ID.Name == "<clinit>"` and `ID.Type == "Foo"` MUST exist, containing the `Cipher()` call
- Pinned by: `TestPythonParser_SyntheticEntryPoint_ClassBody` in `internal/callgraph/python_parser_test.go`

#### Scenario: No synthetic entry point when the body has no calls

- GIVEN a module containing only `import os` and `X = 5`, and a class containing only `x: int` (no initializer, no calls)
- WHEN the parser builds `FileAnalysis.Functions`
- THEN no `<module>` decl MUST be emitted for that file, and no `<clinit>` decl MUST be emitted for that class
- Pinned by: `TestPythonParser_SyntheticEntryPoint_EmptyBodyOmitted` in `internal/callgraph/python_parser_test.go`

#### Scenario: Synthetic receivers are grouped by supporting-call derivation

- GIVEN a module-level `cipher = Cipher()` followed by `cipher.set_key(k)` and `cipher.encrypt(data)`, all at module scope
- WHEN `internal/scan/supporting_calls.go` derives object lifecycle for the `encrypt` finding inside the `<module>` decl
- THEN `set_key` MUST group as a supporting call for the same `cipher` receiver
- Pinned by: `TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver` in `internal/scan/supporting_calls_test.go`

### Requirement: Import resolution robustness

The parser MUST recurse into nested blocks (`try`/`except`, `if`, function
bodies) to discover `import`/`import_from` statements, not only direct
children of the file root. The parser MUST honor `import_prefix` dot count on
`from`-imports: a `from . import x` MUST resolve relative to the current
package (not an absolute empty-string module path), and `from ..pkg import y`
MUST resolve `pkg` one level above the current package, not as an absolute
top-level module.

#### Scenario: Import inside `try/except ImportError`

- GIVEN `try:\n    import fastcrypto as crypto\nexcept ImportError:\n    import crypto`
- WHEN the parser extracts imports for the file
- THEN the nested `import fastcrypto as crypto` MUST be discovered inside the `try` block and recorded in `analysis.Imports`
- AND because both statements bind the same name `crypto`, the first binding in document order MUST win: `Imports["crypto"] == "fastcrypto"` (the later `import crypto` MUST NOT overwrite it)
- Pinned by: `TestPythonParser_Import_TryExcept` in `internal/callgraph/python_parser_test.go`

#### Scenario: Import inside `if TYPE_CHECKING:`

- GIVEN `if TYPE_CHECKING:\n    from mypkg import Cipher`
- WHEN the parser extracts imports for the file
- THEN `Cipher` MUST be recorded with module path `mypkg`
- Pinned by: `TestPythonParser_Import_TypeChecking` in `internal/callgraph/python_parser_test.go`

#### Scenario: Function-local import

- GIVEN `def f():\n    import hashlib\n    hashlib.sha256()`
- WHEN the parser extracts imports for the file
- THEN `hashlib` MUST be recorded as an import even though the `import` statement is nested inside a function body
- Pinned by: `TestPythonParser_Import_FunctionLocal` in `internal/callgraph/python_parser_test.go`

#### Scenario: Relative import with a single dot

- GIVEN a file at `pkg/mod.py` containing `from . import helper`
- WHEN the parser resolves the `import_from_statement`'s `import_prefix`
- THEN `helper` MUST resolve to module path `pkg` (the current package), not an empty/absolute path
- Pinned by: `TestPythonParser_Import_RelativeSingleDot` in `internal/callgraph/python_parser_test.go`

#### Scenario: Relative import with dotted module and double dot

- GIVEN a file at `pkg/sub/mod.py` containing `from ..other import Bar`
- WHEN the parser resolves the `import_prefix` (two dots) plus dotted name `other`
- THEN `Bar` MUST resolve to module path `pkg.other` (one level above `pkg.sub`), not `other` as an absolute top-level module
- Pinned by: `TestPythonParser_Import_RelativeDoubleDot` in `internal/callgraph/python_parser_test.go`

### Requirement: `__init__.py` re-export propagation

When a package's `__init__.py` contains `from .mod import Name`, the builder
MUST propagate that re-export so a sibling file in the same package that
does `from pkg import Name` resolves `Name` to its true declaring module's
dotted path. This propagation is limited to direct re-exports
(`from .submodule import X` statements present verbatim in `__init__.py`);
it MUST NOT perform inferred type resolution or follow indirection beyond
one `__init__.py` hop. Because `FunctionID.Package` is keyed at directory
granularity (one directory = one package path, not one file = one package
path), a re-export whose target lives in a FLAT sibling file (e.g.
`pkg/mod.py`, sharing the same directory as `pkg/__init__.py`) is already
resolved before any rewrite runs: `pkg/mod.py`'s declarations are already
keyed under the same `pkg` package path that `from pkg import Name` resolves
to directly, so the rewrite gate correctly finds the ORIGINAL FQN already
present in the graph and leaves it untouched (see the "no rewrite needed"
scenario below). The rewrite has observable effect only for a SUB-PACKAGE
layout, where the re-exported symbol's true declaring module lives in a
subdirectory (e.g. `pkg/mod/__init__.py`, package path `pkg.mod`) distinct
from `pkg/__init__.py`'s own package path (`pkg`). This propagation MUST
also apply ONLY to project-local packages (an empty `PackageDir.Version`):
a versioned dependency's own `__init__.py` re-exports MUST NOT be recorded
or applied, because contract KB YAMLs key their methods on a dependency's
PUBLIC re-export FQN, and rewriting it to an internal sub-package path would
break KB matching for every consumer of that dependency when its source is
present in the graph (dependency scan / mining).

#### Scenario: Sibling file resolves a name through a sub-package `__init__.py` re-export

- GIVEN `pkg/__init__.py` containing `from .mod import Cipher`, `pkg/mod/__init__.py` (a sub-package directory, package path `pkg.mod`) defining `Cipher`, and a sibling file `pkg/user.py` containing `from pkg import Cipher` and `Cipher().encrypt(data)`
- WHEN the builder stitches package analyses for `pkg` (a project-local package, empty `Version`)
- THEN the `Cipher` call site in `pkg/user.py` MUST resolve its FQN to `pkg.mod.Cipher`
- Pinned by: `TestBuilder_InitPyReexport_SiblingResolution` in `internal/callgraph/python_parser_reexport_test.go`

#### Scenario: Flat-layout re-export needs no rewrite (already resolved)

- GIVEN `pkg/__init__.py` containing `from .mod import Cipher` and a FLAT sibling file `pkg/mod.py` (same directory, package path `pkg`) defining `Cipher`, and a sibling file `pkg/user.py` containing `from pkg import Cipher` and `Cipher().encrypt(data)`
- WHEN the builder stitches package analyses for `pkg`
- THEN the `Cipher` call site in `pkg/user.py` MUST resolve its FQN to `pkg.Cipher` (unchanged — directory-keyed packaging already places `pkg/mod.py`'s declarations under `pkg`, so the rewrite gate's "original FQN not yet in graph" condition never holds and no rewrite occurs)
- Pinned by: `TestBuilder_InitPyReexport_FlatLayoutAlreadyResolved` in `internal/callgraph/python_parser_reexport_test.go`

#### Scenario: Re-export propagation does not infer beyond the re-export statement

- GIVEN `pkg/__init__.py` containing `from .mod import Cipher` and `pkg/mod/__init__.py` internally aliasing `Cipher = SomeOtherThing`
- WHEN the builder stitches package analyses for `pkg`
- THEN the re-export MUST resolve only the name binding (`pkg.Cipher` → `pkg.mod.Cipher`), and MUST NOT attempt to resolve `SomeOtherThing`'s own type
- Pinned by: `TestBuilder_InitPyReexport_NoInferredType` in `internal/callgraph/python_parser_reexport_test.go`

#### Scenario: A non-project-local dependency's re-export is never applied

- GIVEN a versioned dependency package `authlib` (non-empty `PackageDir.Version`) whose `authlib/jose/__init__.py` re-exports `JsonWebSignature` from a `.rfc7515` sub-package, and a project-local consumer file containing `from authlib.jose import JsonWebSignature` and `JsonWebSignature()`
- WHEN the builder stitches package analyses across both the dependency and the project-local consumer
- THEN the `JsonWebSignature` constructor callee MUST remain at its original, KB-keyed FQN (`authlib.jose.(JsonWebSignature).<init>`), never rewritten to the dependency's internal sub-package path
- Pinned by: `TestBuilder_InitPyReexport_DoesNotRewriteKBKeyedDependency` in `internal/callgraph/python_parser_reexport_test.go`

### Requirement: Export schema and downstream semantics unchanged

None of the above requirements MUST introduce a new field, change field
meaning, or bump a schema version. `pkg/graphfrag.CallgraphSchemaVersion`
MUST remain `"6.13"` and `pkg/graphfrag.SchemaVersion` MUST remain
`"graph-fragment-1.13"`. `internal/scan/supporting_calls.go` MUST remain
byte-for-byte unchanged — new receiver identities are consumed by its
existing string-equality grouping logic, not by new logic added to it.

#### Scenario: Export schema tests still pin the unchanged schema versions

- GIVEN the completed change, with `internal/scan/python_e2e_integration_test.go` still passing against a fixture exercising all six rows above
- WHEN `internal/scan/export_schema_test.go` and `internal/scan/fragment_export_test.go` run
- THEN the exported callgraph schema version MUST equal `"6.13"` and the fragment schema version MUST equal `"graph-fragment-1.13"`
- Pinned by: existing `internal/scan/export_schema_test.go` and `internal/scan/fragment_export_test.go` assertions (unchanged, run as a guard); the Python e2e file carries no schema assertion and is not extended for this purpose

#### Scenario: `supporting_calls.go` is not modified

- GIVEN the completed change diff
- WHEN reviewing `internal/scan/supporting_calls.go`
- THEN the file MUST show zero diff against its pre-change state
- Pinned by: manual diff check in design/tasks review; no dedicated Go test (structural invariant, not runtime behavior)
