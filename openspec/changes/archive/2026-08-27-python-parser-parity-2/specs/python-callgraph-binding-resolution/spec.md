# Delta for python-callgraph-binding-resolution

## ADDED Requirements

### Requirement: Opengrep column-convention pinning for Python

The opengrep 1-based-inclusive-start/exclusive-end column convention MUST be
pinned for Python against a REAL opengrep run, mirroring
`TestOpengrep_EndColConventionPinning` (Java).

#### Scenario: Real opengrep run confirms the column convention

- GIVEN a Python fixture with a crypto call and a real opengrep binary
  invocation against it
- WHEN opengrep's match columns are compared to the call node's
  `StartCol`/`EndCol`
- THEN they MUST agree under the pinned convention; if the opengrep binary
  is absent the test MUST skip AND explicitly report that it skipped (never
  a silent pass)
- Pinned by: `TestOpengrep_PythonEndColConventionPinning`

### Requirement: Bounded dynamic dispatch

`getattr`/`importlib.import_module`/`__import__` resolve ONLY when their
target argument is a literal string; a non-literal argument MUST produce no
fabricated identity (grammar: `call{function: call{function: identifier
getattr, arguments}}` for `getattr`; `call{function: attribute{object:
importlib, attribute: import_module}}` for the module form).

#### Scenario: `getattr` with a literal attribute resolves

- GIVEN `getattr(obj, "encrypt")(data)`
- WHEN the parser resolves the outer call
- THEN `ReceiverVar` MUST equal `"obj"` and the callee MUST resolve as
  `obj.encrypt`

#### Scenario: `importlib.import_module`/`__import__` register the import

- GIVEN `importlib.import_module("hashlib")` and `__import__("hashlib")`,
  each with a literal string argument
- WHEN the parser processes the call
- THEN `hashlib` MUST be registered as an import for that scope

#### Scenario: Non-literal argument fabricates nothing

- GIVEN `getattr(obj, name)` where `name` is a variable, not a literal
- WHEN the parser resolves the call
- THEN `ReceiverVar`/callee MUST stay unresolved — no identity is guessed

### Requirement: Decorator-aware receiver semantics

`@staticmethod` methods have no implicit receiver parameter. `@classmethod`
methods bind `cls` as the class receiver. A custom (non-builtin) decorator
MUST preserve the wrapped function's `FunctionID` (grammar:
`decorated_definition{decorator: identifier|attribute|call, definition:
function_definition}`; bare `identifier` decorators are
`@staticmethod`/`@classmethod`/`@property`).

#### Scenario: `@staticmethod` has no implicit receiver

- GIVEN `@staticmethod\ndef encrypt(data): ...`
- WHEN the parser builds parameters/receiver binding
- THEN the first declared parameter MUST be treated as an ordinary
  parameter, never an implicit `self`/`cls` receiver

#### Scenario: `@classmethod` binds `cls` as the class receiver

- GIVEN `@classmethod\ndef make(cls): return cls()`
- WHEN the parser resolves `cls`
- THEN `cls` MUST behave as a class-typed receiver, same identity class as
  `self` in an instance method

#### Scenario: `@property` getter and custom decorators

- GIVEN `@property\ndef prop(self): ...` used as `self.prop.method()`, AND
  `@my_custom_decorator\ndef encrypt(self, data): ...`
- WHEN the parser resolves both
- THEN `self.prop.method()` MUST resolve at least a bounded receiver
  identity for `.method()` (best-effort, not a fabricated concrete type),
  AND the custom-decorated function's `FunctionID` MUST remain the wrapped
  function's original identity (name unchanged by the decorator)

### Requirement: `super()` resolves to the first declared base

`super().__init__(...)`/`super().m()` and the explicit-arg form
`super(B, self).m()` MUST resolve their callee against `OwnerBases[0]`
(grammar: `call{function: attribute{object: call{function: identifier
super, arguments}, attribute}}`). `super()` MUST NEVER resolve to
`FunctionID{Name:"super"}` in the local package.

#### Scenario: `super().__init__()` resolves to the first base

- GIVEN `class Sub(Base):` with `def __init__(self): super().__init__(x)`
- WHEN the parser resolves the `super().__init__(x)` call
- THEN the callee MUST resolve to `Base.__init__`, using `OwnerBases[0]`

#### Scenario: Explicit-arg `super(B, self)` resolves the same way

- GIVEN `super(B, self).m()` inside a subclass of `B`
- WHEN the parser resolves the call
- THEN the callee MUST resolve to `B.m`, same as the no-arg form

#### Scenario: `super()` is never a local `FunctionID{Name:"super"}`

- GIVEN any `super()...` call site
- WHEN the parser builds the `FunctionCall`
- THEN the resolved callee MUST NEVER be a synthetic local
  `FunctionID{Name:"super"}`

### Requirement: `functools.partial` and instance `__call__`

`functools.partial(f, a)` bound to `p`, then called as `p(b)`, resolves
callee `f`. `obj(...)` where `obj` is bound to an instance of an in-file
class declaring `__call__` resolves to `Class.__call__`.

#### Scenario: Bound `partial` resolves the wrapped function

- GIVEN `p = functools.partial(f, a)` followed by `p(b)`
- WHEN the parser resolves `p(b)`
- THEN the callee MUST resolve to `f`

#### Scenario: Callable-instance invocation resolves `__call__`

- GIVEN an in-file class `C` declaring `def __call__(self, x): ...`, and
  `obj = C()` followed by `obj(data)`
- WHEN the parser resolves `obj(data)`
- THEN the callee MUST resolve to `C.__call__`

### Requirement: Type-hint-fed receiver/return resolution

Parameter and return annotations, resolvable only via imports/KB (never
inferred), feed receiver/`AssignedVar` typing. `Optional[X]`, `Union[X,
None]`, `X | None`, and the string forward-reference `"X"` all normalize to
`X`. Annotated assignment (`x: X = make()`) and `TYPE_CHECKING`-only imports
participate. An unresolvable name yields no type (grammar:
`typed_parameter`, `typed_default_parameter{type: generic_type{...}}`,
`function_definition.return_type`, `assignment{type: type>identifier}`).

#### Scenario: Parameter and annotated-assignment types feed the receiver

- GIVEN `def f(x: Cipher): x.encrypt(d)` and, separately,
  `x: Cipher = make(); x.encrypt(d)`
- WHEN the parser builds receiver typing for `x`
- THEN `x` MUST carry a resolvable type usable by the KB resolver, in both
  forms

#### Scenario: Return annotation propagates to `AssignedVar`

- GIVEN `def make() -> Cipher: ...` and `c = make(); c.encrypt(d)`
- WHEN the parser resolves `c`'s type from `make`'s return annotation
- THEN `c`'s inferred type MUST be `Cipher`

#### Scenario: Optional/Union/`|`/string-forward-ref all normalize

- GIVEN parameters typed `Optional[Cipher]`, `Union[Cipher, None]`,
  `Cipher | None`, and `"Cipher"` (four separate declarations)
- WHEN the parser normalizes each annotation
- THEN all four MUST normalize to `Cipher`

#### Scenario: `TYPE_CHECKING`-only import still resolves the annotation

- GIVEN `if TYPE_CHECKING: from mypkg import Cipher` and `def f(x: Cipher):
  ...`
- WHEN the parser resolves `x`'s annotation
- THEN it MUST resolve `Cipher` using the `TYPE_CHECKING`-guarded import

#### Scenario: Unresolvable annotation yields no type

- GIVEN `def f(x: SomeUnknownName): x.encrypt(d)` with no matching import
- WHEN the parser resolves `x`'s type
- THEN `x` MUST carry no fabricated type

### Requirement: Dependency-mode external stub/source type resolution

For a pip-resolved dependency with `.pyi` stubs or annotated `.py` sources,
declared return annotations of public functions/methods and class bases
feed receiver typing in the consumer. Results are cached per distribution;
no network access is made; project-local code is unaffected; absent
annotations degrade gracefully (no fabricated type).

#### Scenario: Consumer receiver is typed from a dependency's stub

- GIVEN a pip-resolved dependency exposing `def make() -> Cipher: ...` (via
  `.pyi` or annotated source) and a consumer `from dep import make; c =
  make(); c.encrypt()`
- WHEN the parser resolves `c`'s type in the consumer, with dependency
  results cached per distribution and no network call made
- THEN `c` MUST resolve to `dep.Cipher`

#### Scenario: Missing annotations degrade gracefully

- GIVEN a dependency function with no return annotation
- WHEN the consumer's receiver type is resolved
- THEN no type MUST be fabricated, and project-local (non-dependency) code
  resolution MUST remain unaffected

### Requirement: Leading-underscore visibility convention

`_name` → `protected`; `__name` (non-dunder) → `private`; `__dunder__` and
plain names → `public`. `OwnerVisibility` follows the same convention
applied to the class name. Values reuse the existing `Visibility` enum
(`VisibilityPublic`/`VisibilityProtected`/`VisibilityPrivate` in
`types.go`) — no new enum value.

#### Scenario: Name-based visibility mapping

- GIVEN methods named `_hash`, `__derive` (non-dunder), `__init__`
  (dunder), and `encrypt` (plain)
- WHEN the parser sets `Visibility`
- THEN they MUST resolve to `protected`, `private`, `public`, and `public`
  respectively

#### Scenario: `OwnerVisibility` follows class-name convention

- GIVEN a class named `_InternalCipher`
- WHEN the parser sets `OwnerVisibility` on its methods
- THEN `OwnerVisibility` MUST equal `protected`, mirroring the method-name
  rule

### Requirement: Constructor/call argument provenance recursion

A nested crypto call passed as an argument to another call MUST contribute
its own origin, recursively. **Field decision**: reuses the existing
`SourceNode.SourceNodes`/`CallTarget` recursive structure (already consumed
by `resolvedKeyLengthFromSourceNodes`/`resolvedKeyLengthFromProducer` in
`internal/scan/key_length.go`) — no new field (grammar: nested calls are
direct children of `argument_list`).

#### Scenario: Nested constructor calls record their own provenance

- GIVEN `Cipher(algorithms.AES(key), modes.CBC(iv))`
- WHEN the parser builds `ArgumentSources` for the outer `Cipher(...)` call
- THEN it MUST include a `CALL_RESULT` source node for
  `algorithms.AES(key)` and one for `modes.CBC(iv)`, each carrying its own
  `CallTarget`, with the outer `Cipher` call as their consumer
