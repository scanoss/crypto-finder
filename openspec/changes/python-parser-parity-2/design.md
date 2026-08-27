# Design: Python parser parity round 2 — throughput, deferred rows, KDF key length

**Tool constraint (must be reported):** this executor has no Bash tool. No test,
benchmark, or `go build` was executed. Every performance figure below is an
analytic node-touch count, not a measurement, and every empirical claim is
delegated to a named pinning test in section 9. Grammar shapes come from the
orchestrator's pinned-grammar spike (appendix, section 10) and the archived
`python-parser-java-parity` design appendix.

## 1. Technical approach

Three independent workstreams on one branch, ordered so the performance gate is
established before any capability row can erode it.

- **A (perf)** rewrites the Python parser's traversal into ONE descent per file
  with a lexical binding-layer stack and **deferred call resolution**: the
  descent collects call *nodes*; `parseCallExpr` runs afterwards, per scope,
  against that scope's now-complete binding table. This deletes `walkForCalls`,
  `walkPrunedForCalls`, and `withComprehensionTargets` while preserving every
  existing per-call code path byte-for-byte.
- **B (rows 6–20)** are parser-local resolution rules with hard bounds, plus one
  genuinely new component (row 14). Each row adds tables/fields that already
  exist on `FunctionDecl`/`FunctionCall`/`CallGraph` — **no new exported field**
  (verified against `pkg/graphfrag/model.go`: `Visibility`, `OwnerVisibility`,
  `ResolvedReceiverType`, `ParameterTypes`, `ResolvedKeyLength` are all present).
- **C (KDF key length)** is KB YAML plus one new `Derivation` enum value plus one
  additive resolution path in `internal/scan/key_length.go`.

`internal/scan/supporting_calls.go` and `pkg/graphfrag/` stay zero-diff.

## 2. Architecture decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| D1 | ONE descent + **deferred** per-scope call resolution (collect nodes, resolve after the scope closes) | Single-pass immediate resolution; keep the prepass + `walkForCalls` pair | A call may precede a binder in document order (`[c.encrypt(x) for c in ciphers]`, a body-top call with a body-bottom `with ... as`). Immediate resolution would silently lose those bindings. Deferring costs exactly one revisit per **call** node, not per node — the only shape that hits the `1 + O(calls)` target without changing semantics. |
| D2 | Bindings become a **layer stack** (`pythonBindingLayer{parent, names}`) instead of a cloned map per comprehension | Keep `withComprehensionTargets`' map clone | Removes one `map[string]bool` allocation + full copy per comprehension node, and makes comprehension scoping expressible under deferral (a pending call holds a pointer to its innermost layer; the layer is finalized when the comprehension's descent ends). Lookup walks a chain of depth 1 + comprehension nesting (≤3 in practice). |
| D3 | Deferred resolution appends to `decl.Calls` in **document order**, identical to today | Resolve grouped by kind | `lifecycleSelector.selectDescendants(objectVar, since)` in `internal/scan/supporting_calls.go` splits a reassigned name **positionally by call index**. Reordering `Calls` would silently corrupt `self.attr` rebinding lifecycle scoping. This is a load-bearing invariant, pinned by T0.6. |
| D4 | Visit counter lives on the `PythonParser` **instance** (`visits *int`, nil in production) | Package-level counter; build tag | A package-global counter races under `-race` with `parallel_parse_test.go`; a build tag would exclude the guard from `go test ./...` (the spec forbids a skipping guard). A `PythonParser` is never shared across goroutines (`CloneParser` per worker), so an instance field is race-free. Production cost is one nil compare per node, ~0.1% of a cgo `Symbol()` call. |
| D5 | `map[string]bool` membership tests use `locals[string(src[a:b])]`, never `node.Content(src)` | Intern table | `Node.Content` allocates a Go string unconditionally; `m[string(b)]` is compiler-optimised to zero allocation. An intern table trades allocation for hashing the same bytes plus a map write — a win only at high name repetition, unproven here. Allocate only when the string is **stored**. |
| D6 | C's keyword→parameter mapping lives in `internal/scan/key_length.go`, **not** `mergeCallParameters` | The spec's stated field decision (see section 11) | `mergeCallParameters` builds the exported `parameters[]` for every call in every ecosystem; rewriting `parameter_index` there desyncs it from the declared-order-aligned `parameter_roles[]`/`parameter_types[]`, and populating `resolved_value` there changes export output for *every* Python keyword argument, not just KDFs. `key_length.go` already interprets raw argument text (`byteArrayAllocation`, `unquoteLiteral`, `looksLikeIntegerLiteralExpr`) and owns key-length policy. Zero export-surface collateral. |
| D7 | B13's assigned-var type propagation is a **graph pass in the resolver chain**, and B14 only feeds it more `ReturnType`s | Do it in the parser | The parser cannot see a dependency's annotations (resolvers run after Phase 1). Putting the propagation last in `PythonTypeResolverChain.ResolveTypes` means B13 works from parser-derived annotations and B14 is purely additive — reverting B14 leaves B13 green. |
| D8 | B14 reads `sourceRoots []PackageDir` and filters `Version != ""` | Extend `dependency_scanner.go`'s Java-only `typeOnlyPackages` fast path (`:621`) | `builder.go:148-154` already passes `packages + typeOnlyPackages` to `ResolveTypes`, and Python dependencies are already fully source-parsed into `graphPackages`. **No `dependency_scanner.go` change is needed**, and `Version != ""` is exactly "not project-local", satisfying the spec's project-local-unaffected requirement. |

## 3. Performance architecture (A)

### 3.1 Current cost

| Pass | Nodes touched |
|---|---|
| `collectPythonFilePrepass(root)` | every node in the file (1.00×) |
| `walkForCalls(body)` per function/method decl | every node inside every function body (~0.80–0.90× of a typical file) |
| `walkPrunedForCalls(root)` for `<module>` | module-direct statements only |
| `walkPrunedForCalls(classBody)` per class | class-direct statements only |
| `parsePythonReturnType(node.Content(src))` (`python_parser.go:784`) | O(body bytes) string allocation **per declaration** |

Total ≈ **1.85× nodes** plus one whole-body string per decl.

### 3.2 Target shape

```
parseFile
  └─ pythonWalk(root)                       ← ONE descent, every node exactly once
       ├─ symbol-dispatch on node.Symbol()  (one cgo call per node, cached)
       ├─ imports / __init__.py re-exports  (never pruned)
       ├─ scope stack push/pop:  module | class | function | comprehension layer
       ├─ binder recording into the innermost applicable layer(s)
       ├─ module-level int constants  (C(iii))
       └─ append &pythonPendingCall{node, layer} to the innermost SCOPE
     ↓
extractDeclarations / processClass / buildModuleInitDecl / buildClassInitDecl
  └─ for each pending call of that scope:  parseCallExpr(node, bindings)   ← O(calls)
```

Data structures (all unexported, all inside `python_parser.go`):

```go
type pythonBindingLayer struct { parent *pythonBindingLayer; names map[string]bool }
type pythonPendingCall  struct { node *sitter.Node; layer *pythonBindingLayer }
type pythonScope struct {
    locals   *pythonBindingLayer
    attrs    map[string]bool   // class scopes only
    varTypes map[string]string // B13: annotation-derived, resolved via imports
    pending  []pythonPendingCall
}
type pythonFileWalk struct {
    moduleScope  *pythonScope
    funcScopes   map[uint32]*pythonScope      // keyed by function_definition StartByte
    classScopes  map[uint32]*pythonClassScope // attrs + own direct scope
    moduleConsts map[string]string            // C: KEY_LEN -> "32"
}
```

`pythonFileWalk` keeps the existing `StartByte`-keyed shape, so
`parseFunctionDef` / `processClass` / `buildModuleInitDecl` /
`buildClassInitDecl` change **only** in where they obtain calls — every field
they set stays identical.

Scope rules preserved verbatim from the current prepass contract: entering a
`function_definition` while a function scope is already active does **not** open
a new scope (a closure's calls and locals stay in the enclosing decl); a nested
`class_definition` opens a fresh `pythonClassScope`; `moduleDirect`/`classDirect`
prune at `function_definition | class_definition | decorated_definition | lambda`
(`isPythonPrunedDefinitionSymbol`), so `<module>`/`<clinit>` pending calls are
exactly what `walkPrunedForCalls` produced — with the pruned walks deleted.

### 3.3 Symbol-id dispatch and allocation plan

- Extend `pythonSymbolTable`/`resolvePythonSymbols` (one map literal) with:
  `block`, `parameters`, `attribute`, `argumentList`, `dottedName`,
  `aliasedImport`, `wildcardImport`, `relativeImport`, `importPrefix`,
  `typedParameter`, `defaultParameter`, `typedDefaultParameter`, `patternList`,
  `tuplePattern`, `listPattern`, `listSplatPattern`, `dictSplatPattern`,
  `expressionStatement`, `keywordArgument`, `integer`, `string`,
  `stringContent`, `type`, `genericType`, `typeParameter`, `binaryOperator`,
  `none`, `decorator`, `await`, `lambdaParameters`.
- Replace `Type()` string compares in `parseFunctionDef`, `pythonParameterNames`,
  `firstIdentifierChild`, `collectPythonAssignmentTargets`, `parseCallExpr`,
  `parseAttributeCall`, `extractPythonCallArguments`, `processImportStatement`,
  `processImportFromStatement`, `pythonImportFromModulePath`,
  `pythonChainRootNode`, `isPythonCallNode`, `isPythonAttributeCallNode`,
  `pythonAssignedVarFromParent`, `extractPythonBaseClassNames`.
- `ReturnType` from `node.ChildByFieldName("return_type")` only (A2). Delete the
  `node.Content(src)`-on-`function_definition` call site; `parsePythonReturnType`
  survives only as the string-normalisation helper B13 reuses.
- `Parameters` from `typed_parameter`/`typed_default_parameter` `type` field nodes
  instead of `parsePythonParameters(paramNode.Content(src))`; this also
  populates the existing `FunctionParameter.Name` (previously Java-only) and
  feeds B13 for free.
- Cache `ChildCount()` per node (already done in the prepass; extend everywhere).
- `pending` slices allocate lazily (nil until a scope's first call).

### 3.4 Expected result

| Metric | `c6ee180` baseline | HEAD (measured in verify: +19.9%) | This design (analytic) |
|---|---|---|---|
| Node touches / file | ≈0.85× nodes (bodies only, no binding work) | ≈1.85× nodes | **1.00× nodes + O(calls)** |
| Whole-body `Content(src)` per decl | yes | yes | **none** |
| `Type()` cgo string alloc per visited node | yes | partly removed | **none on any walker or hot reader** |

Prediction: at or below the `c6ee180` baseline on both ns/op and B/op
(the round-1 `B/op` regression of +34.8% was dominated by the removed
whole-body strings and per-comprehension map clones). **Unmeasured.** The gate
stays the spec's ≤10% ns/op and ≤1.15× B/op.

### 3.5 CI guard design (A3)

- **`TestPythonParser_NodeVisitBudget`** — table over a committed corpus of ≤40
  small deterministic files at `internal/callgraph/testdata/python_visit_budget/`
  (one file per idiom: comprehensions, `with/as`, decorators, `super()`,
  nested classes, keyword args, annotations, module constants). For each file the
  test asserts, using the instrumented visit counter (D4):
  `visits >= nodeCount` (proves the whole tree is walked) **and**
  `visits <= nodeCount + pythonVisitBudgetPerCall*callCount` with
  `pythonVisitBudgetPerCall = 8`. Deterministic, machine-independent, never
  skips — this is the CI-enforceable guard the spec requires.
- **`BenchmarkPythonParseDirectory_Bindings`** stays as-is (generated 200-module
  corpus, `t.Skip` when absent) for humans; the apply phase records **≥8 reps in
  one continuous run** with combined mean **and** min/max range, per row.
- A benchmark-derived *assertion* on a committed corpus is explicitly rejected:
  round 1 saw 12.5%–27.5% swing across rounds on the same machine.

## 4. Rows 6–20

All rows are `internal/callgraph/python_parser.go` unless stated. None adds a
field to `FunctionCall`/`FunctionDecl`.

### Row 6 — Opengrep column pinning (test-only, S)

Mirror `TestOpengrep_EndColConventionPinning`
(`internal/scanner/semgrep/transformer_test.go`) for Python: run the real
opengrep binary over a Python fixture with one crypto call, compare its match
columns to the parser's `StartCol`/`EndCol` (1-based, start inclusive, end
exclusive). Absent binary → `t.Skip` **with an explicit `t.Logf` skip reason**
(spec: never a silent pass).
Test: `TestOpengrep_PythonEndColConventionPinning`.

### Row 18 — Visibility (S)

`pythonVisibilityForName(name)`: `__dunder__` → `VisibilityPublic`; `__x`
(non-dunder) → `VisibilityPrivate`; `_x` → `VisibilityProtected`; else
`VisibilityPublic`. Set `FunctionDecl.Visibility` in `parseFunctionDef` (using
the **source** name, before the `__init__`→`<init>` rename) and
`OwnerVisibility` from the class name in `processClass`/`extractClassMethods`
(empty `OwnerVisibility` for module-level functions, matching Java's
package-private-vs-absent distinction: Python has no package-private, so a
module-level function gets `Visibility` only). Java analogue:
`java_parser.go:915-1020`, `827fe39`.
Tests: `TestPythonParser_Visibility_Underscore`, `_DoubleUnderscore`, `_Dunder`,
`_OwnerVisibility`.

### Row 20 — Argument provenance recursion (M)

Populate `FunctionCall.ArgumentSources [][]SourceNode`, index-parallel to
`Arguments`, for exactly three bounded argument shapes (grammar: nested calls
are direct children of `argument_list`; a keyword argument wraps its value under
field `value`):

| Argument shape | Emitted `SourceNode` |
|---|---|
| nested `call` | `{Type: CALL_RESULT, CallTarget: &calleeID, Location, SourceNodes: <its own arguments, recursively, depth ≤ 4>}` |
| bare `identifier` bound to a module-level integer constant | `{Type: VARIABLE, Name: n, SourceNodes: [{Type: VALUE, Value: "32"}]}` |
| `integer` / `string` literal | `{Type: VALUE, Value: <text>}` |

Anything else emits nothing (no fabrication). The nested-call callee is resolved
through the **same** `parseCallExpr` path as a top-level call, so KB-keyed FQNs
are identical. Depth cap 4 mirrors `maxKeyLengthSourceDepth`'s spirit and bounds
cost at O(arguments). Adopted per the orchestrator's field decision: reuses
`SourceNode.SourceNodes`/`CallTarget`, already walked by
`resolvedKeyLengthFromSourceNodes`/`resolvedKeyLengthFromProducer`.
Java analogue: `2959b64` `extractFieldAssignments` recursion.
Test: `TestPythonParser_ArgProvenance_NestedConstructorCalls`.

### Row 8 — Decorator semantics (M)

In `extractDecoratedMethod`/`processDecorated`, read each `decorator` child; a
bare `identifier` decorator is classified against a fixed set
(`staticmethod`, `classmethod`, `property`). Effects:

- `@staticmethod`: do **not** treat parameter 0 as an implicit receiver — the
  binding layer records it as an ordinary local, and `receiverIdentity` no
  longer special-cases it. (Today parameter 0 named `self` would be refused as a
  receiver; a static method's first parameter must be usable.)
- `@classmethod`: `cls` behaves exactly as `self` — already true via
  `pythonSelfOrClsAttr` canonicalisation; the row adds the parameter-0 marking
  so a classmethod whose first parameter is named something else still
  canonicalises.
- `@property`: record the property name in the class scope's `attrs`, so
  `self.prop.method()` resolves a bounded `self.prop` receiver identity (a
  string identity, **not** a concrete type).
- Any other decorator (`identifier` not in the set, `attribute`, or `call` such
  as `@app.route('/x')`) is ignored: the wrapped `FunctionID` is unchanged.

Tests: `TestPythonParser_Decorator_StaticMethodNoReceiver`, `_ClassMethodCls`,
`_PropertyReceiver`, `_CustomKeepsIdentity`.

### Row 9 — `super()` (S)

In `parseAttributeCall`, when the object node is a `call` whose function is the
identifier `super` (both `super()` and `super(B, self)`), resolve the callee as
`FunctionID{Package: packagePath, Type: OwnerBases[0], Name: method}` instead of
falling through to `FunctionID{Name:"super"}`. Requires threading the enclosing
class's `bases` into the scope (already available in `processClass`; add
`bases []string` to `pythonScope`). Empty `OwnerBases` → leave unresolved, never
fabricate. `__init__` maps to `<init>` for the callee name, matching
`parseFunctionDef`. Java analogue: `2287a76`.
Tests: `TestPythonParser_Super_InitResolvesBase`, `_MethodResolvesBase`,
`_NeverLocalSuper`.

### Row 7 — Bounded dynamic dispatch (M)

Literal-string arguments only.

- `getattr(obj, "encrypt")(data)` — grammar: outer `call` whose `function` is
  itself a `call` with `function: identifier getattr`. When argument 1 is a
  `string` with a single `string_content` child, rewrite the outer call as if it
  were `obj.encrypt(data)`: same `ReceiverVar`/callee resolution path.
  Non-literal argument 1 → emit nothing new (unresolved, as today).
- `importlib.import_module("hashlib")` and `__import__("hashlib")` — register
  `analysis.Imports["hashlib"] = "hashlib"` via `recordPythonImportOnce`
  (first-binding-wins preserved). Non-literal → no registration.

Java analogue: `7ee21ca` reflection dispatch.
Tests: `TestPythonParser_DynamicDispatch_GetattrLiteral`, `_ImportlibLiteral`,
`_NonLiteralNoIdentity`.

### Row 11 — `functools.partial` / `__call__` (M)

Two per-scope maps on `pythonScope`, both populated during deferred resolution
(so document order is respected):

- `partials map[string]FunctionID`: on a resolved call to
  `functools.partial`/`partial` with `AssignedVar == p`, record argument 0's
  resolved callee. A later `p(b)` (function node is a plain `identifier` that is
  a known local and a `partials` key) resolves to that callee.
- `callables map[string]string`: `obj = C()` where `C` is an in-file class
  declaring `__call__` → `obj` maps to `C`; a later `obj(data)` resolves to
  `FunctionID{Package: packagePath, Type: "C", Name: "__call__"}`. The in-file
  class set comes from `pythonFileWalk.classScopes` plus a
  `classesWithDunderCall map[string]bool` collected in the same descent.

Both are strictly local to one file and one scope; no cross-file inference.
Tests: `TestPythonParser_Partial_ResolvesTarget`,
`TestPythonParser_Call_DunderCall`.

### Row 13 — Type hints (M, parser + `python_type_resolver.go`)

Two halves, both bounded to names resolvable via `analysis.Imports`,
`analysis.ImportedTypes`, or in-file class declarations.

**Parser half** — `pythonNormalizeAnnotation(typeNode, src) string`, driven by
the pinned shapes: `type > identifier` → the name; `type > generic_type
{identifier Optional|Union, type_parameter{...}}` → the single non-`none` type
argument; `type > binary_operator{left, right: none}` → `left`; `type > string
{string_content}` → the quoted forward reference verbatim. Anything else → `""`.
Populate `pythonScope.varTypes` from: `typed_parameter`/`typed_default_parameter`
(parameter annotations), annotated assignment (`assignment{left: identifier,
type: type>identifier}`), and `FunctionDecl.ReturnType` (return annotations).
`TYPE_CHECKING`-guarded imports need no work — `pythonWalk`'s import discovery is
already unpruned.

In `parseAttributeCall`, consult `varTypes[object]` **after** the import check
and **before** the local-name fallback: when `varTypes[object] == "Cipher"` and
`Imports["Cipher"]` exists with `FromImports["Cipher"]`, emit
`FunctionID{Package: imports["Cipher"] + ".Cipher", Name: method}` and set
`FunctionCall.ResolvedReceiverType` to that FQN. `ReceiverVar` still equals the
local name. Unresolvable annotation → no type, no `ResolvedReceiverType`.

**Resolver half** — `propagatePythonAssignedVarTypes(graph)`, the last step of
the new `PythonTypeResolverChain` (see row 14): per `FunctionDecl`, one ordered
pass over `Calls` maintaining `var → type` from `AssignedVar` + the callee
decl's `ReturnType`; a later call whose `ReceiverVar` matches gets its callee
`Package`/`Type` rewritten and `ResolvedReceiverType` set. Never crosses decls.

Tests: `TestPythonParser_TypeHint_ParamAnnotation`, `_ReturnAnnotation`,
`_OptionalUnionNormalization`, `_StringForwardRef`, `_AnnotatedAssignment`,
`_TypeCheckingImport`, `_UnresolvableNoType`.

### Row 14 — `PythonDependencyTypeResolver` (L, lands last)

New file `internal/callgraph/python_dependency_type_resolver.go` (the proposal
called it `python_stub_type_resolver.go`; the resolver reads both `.pyi` **and**
annotated `.py`, so the name is generalised), plus
`internal/callgraph/python_signature_cache.go`.

```go
// maxPythonDistributionWorkers mirrors maxJavaJARWorkers.
const maxPythonDistributionWorkers = 8

type pythonSignature struct {
    fullName   string   // "dep.mod.Cipher.encrypt" / "dep.mod.make"
    paramTypes []string
    returnType string
}

type PythonSignatureIndexCache interface {  // mirrors BytecodeIndexCache
    Get(ctx context.Context, key string) (*CachedPythonSignatureIndex, bool, error)
    Put(ctx context.Context, key string, value *CachedPythonSignatureIndex) error
}

type PythonDependencyTypeResolver struct {
    cache        PythonSignatureIndexCache
    readDir      func(string) ([]os.DirEntry, error) // test seam
}

type PythonTypeResolverChain struct {
    contract   *PythonContractTypeResolver
    dependency *PythonDependencyTypeResolver
}
```

Algorithm:
1. `ResolveTypes(graph, sourceRoots)`: select `sourceRoots` with
   `Version != ""` (D8). Project-local roots are skipped entirely.
2. Per distribution, cache key `sanitize(ImportPath) + "@" + Version` +
   `pythonSignatureCacheSchemaVersion`; on miss, index the distribution in a
   worker pool of `min(max(NumCPU/2,1), maxPythonDistributionWorkers)`.
3. Indexing is a **pruned** tree-sitter descent per file (`.pyi` preferred over a
   same-stem `.py`, matching the existing stub-precedence rule): only top-level
   and class-body `function_definition`/`class_definition` nodes; read
   `return_type` and `superclasses` field nodes; normalise annotations with the
   row-13 helper. Never reads a function body. No network, no subprocess.
4. Merge into **existing** graph fields: `graph.TypeHierarchy` (class bases) and
   `graph.ExternalMethodSignatures` (via `ExternalMethodSignatureKey`); fill
   `FunctionDecl.ReturnType` only when currently empty.
5. `PythonTypeResolverChain.ResolveTypes` order: contract KB → dependency
   signatures → `propagatePythonAssignedVarTypes`. KB always wins.

Degradation rules: unreadable dir, absent `.pyi`, absent annotation, cache
read/write error, or an unresolvable annotation name → log at debug, resolve
nothing, return `nil` error. `StrictFailure()` is **not** implemented (Python
resolver failures are never fatal), matching `PythonContractTypeResolver`.

Wiring: `parser_registry.go` `NewTypeResolverForEcosystem("python")` returns
`NewPythonTypeResolverChain()`; `internal/cli/scan.go:331-340` gains a Python
branch mirroring the Java one, injecting `NewDiskPythonSignatureIndexCache()`.
`parser_options.go` needs no change (the resolver is not a parser).
`internal/engine/dependency_scanner.go` needs **no** change (D8).

Tests: `TestPythonDepTypeResolver_StubReturnAnnotation`, `_SourceAnnotation`,
`_ClassBases`, `_CachePerDistribution`, `_NoAnnotationsDegrades`,
`_ProjectLocalUnaffected` — all against committed `.pyi`/`.py` fixtures under
`internal/callgraph/testdata/python_stubs/` and `t.TempDir()` caches.

## 5. KDF key length (C)

### 5.1 Where each piece lands

| Concern | Location | Change |
|---|---|---|
| keyword name capture | none needed | `Arguments[i]` already holds `dklen=32` verbatim (`extractPythonCallArguments` → `parseArgumentsFromDelimitedContent` → `splitTopLevelCommaList`, no `keyword_argument` stripping). Adopted per the orchestrator's field decision. |
| declared parameter **names** | none needed | `contracts.ParameterContract.Name` already exists (yaml `name`), already exported as `parameter_roles[].name`. **No KB schema field is added.** |
| bytes→bits | `contracts.go` `validDerivation` (`:404`) + its error string (`:547`) + `resolveContractKeyBits` (`key_length.go:227`) | new `DerivationArgumentByteLength Derivation = "argument_byte_length"`; `bits = bytes*8`, reject `<=0` and `> maxKeyMaterialBytes`. |
| keyword→role matching | `key_length.go` only (D6) | new step 3a below. |
| positional Python calls | `key_length.go` only | new step 3b below. |
| `KEY_LEN = 32` | parser (row 20's VARIABLE→VALUE node) + existing `resolveSimpleExportSourceValue` | `pythonFileWalk.moduleConsts` feeds `ArgumentSources`; `resolveSimpleExportParameterValue` already resolves `VARIABLE → VALUE` chains into `callGraphParameter.ResolvedValue`. **Zero export change.** |

### 5.2 `resolvedKeyLengthFromContract` becomes a three-step ladder

Steps 1 and 2 are **byte-for-byte today's code**, including
`contractParameterTypesMatch`. Both new steps run only after they yield nothing.

- **Step 3a — keyword-name path.** For a contract in `matches` whose keySize
  `ParameterContract` has a non-empty `Name`, find the single call parameter
  whose `ArgumentExpression` matches
  `^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$` with group 1 == `Name`. Derive bits
  from `parameter.ResolvedValue` when non-empty (the `KEY_LEN` case), else from
  group 2 (the `length=32` case), via `resolveContractKeyBits(value,
  role.Contributes.Derivation)`. `SourceCall.ParameterIndex` = the contract's
  declared `*role.Index`. Emits `constant` or `unknown` provenance exactly as
  step 1 does. **The `contractParameterTypesMatch` overload gate is deliberately
  bypassed here**: a keyword name identifies the parameter exactly, which is
  strictly stronger evidence than a positional declared-type match.
- **Step 3b — positional, type-evidence-absent path.** Contract declares
  `parameter_types` (asserting one unambiguous signature per AGENTS.md), the
  call site supplies **no** declared type for the keySize index (no
  `SourceNode.DeclaredType`, empty `parameterTypes[index]`), **and** the value
  resolves to a constant (`ok == true`). Emits only `constant`; an unresolved
  value returns nil. This is what makes purely positional
  `PBKDF2(password, salt, 32)` resolve.

Java neutrality argument (the load-bearing claim): step 3a cannot fire on a
Java/Go/Rust call site because those languages have no `name=value` argument
syntax; step 3b can only **add** a record carrying a real constant, and only
when steps 1 and 2 already returned nothing, so no existing Java record is
changed, lost, or downgraded. Residual: a C call written `f(nbits = 2048)` can
match step 3a; that is correct resolution, not fabrication, and is covered by
keeping the C/Java suites green.

**Java positional-vs-keyword parity statement.** Java has no keyword arguments;
it selects among same-arity overloads by declared parameter type, with an
`expected == "int" && looksLikeIntegerLiteralExpr` literal-shape escape, and its
keySize roles are index-based (`jdk-crypto.yaml`: `- index: 0, name: keyBits`).
Python is the mirror image — no overloads, but keyword arguments — so name-based
selection with no type gate is the parity-preserving analogue. Every Python KDF
contract below declares **both** `index` and `name`, exactly as `jdk-crypto`
does, so `keySizeParameterRole` (which requires `Index != nil`) is unchanged.

### 5.3 Exact YAML entries

All use `role: metadata-contributing` and
`contributes: {property: keySize, derivation: argument_byte_length}`.
Author each with `name:` **and** `index:`; add `parameter_types` (length ==
arity) so step 3b is eligible.

| KB file | method | arity | index | name |
|---|---|---|---|---|
| `pyca-cryptography.yaml` | `...kdf.pbkdf2.PBKDF2HMAC.<init>` | 4 | 1 | `length` |
| | `...kdf.scrypt.Scrypt.<init>` | 4 | 1 | `length` |
| | `...kdf.hkdf.HKDF.<init>` | 4 | 1 | `length` |
| | `...kdf.hkdf.HKDFExpand.<init>` | 3 | 1 | `length` |
| | `...kdf.concatkdf.ConcatKDFHash.<init>` | 3 | 1 | `length` |
| | `...kdf.x963kdf.X963KDF.<init>` | 3 | 1 | `length` |
| `python/hashlib.yaml` (new KB file) | `hashlib.pbkdf2_hmac` | 5 | 4 | `dklen` |
| | `hashlib.scrypt` | 6 | 5 | `dklen` |
| `argon2-cffi.yaml` | `argon2.PasswordHasher.<init>` | 6 | 4 | `hash_len` |
| `bcrypt.yaml` | `bcrypt.kdf` | 4 | 2 | `desired_key_bytes` |
| `pycryptodome.yaml` | `Crypto.Protocol.KDF.PBKDF2.<init>` | 3 | 2 | `dkLen` |
| | `Crypto.Protocol.KDF.scrypt` | 4 | 2 | `key_len` |
| | `Crypto.Protocol.KDF.HKDF.<init>` | 3 | 1 | `key_len` |
| `pycryptodomex.yaml` | same three under `Cryptodome.Protocol.KDF.*` | " | " | " |

`HKDFExpand`, `ConcatKDFHash`, `X963KDF`, `hashlib.*`, `argon2 PasswordHasher`,
and `bcrypt.kdf` contracts do not exist yet — apply must author the full
contract entry (method, arity, `return`, `role`) alongside the parameter role,
verifying arity and the length parameter's declared index against the library's
own signature/stubs before writing (crypto-kb-author Step 2b). The exact indices
above are the design's expectation and **must be corrected from primary sources
during apply, not asserted on faith**.

Tests: `TestResolvedKeyLength_Python_KeywordDklen`,
`_PositionalLength`, `_ModuleConstant`, `_NonConstantStaysUnknown`,
`_EveryListedAPI` (table over the whole KB table above) in
`internal/scan`; plus `TestLoadEmbeddedPython_KDFKeySizeRoles` in
`internal/callgraph/contracts`; plus a Java-neutrality guard
`TestResolvedKeyLength_JavaUnchangedByKeywordPath`.

## 6. Existing tests whose expectations change

No golden **files** exist: `internal/scan/testdata/` holds only two `.java`
fixtures, and there are no `*.golden` files anywhere in the repo. The
`python_golden_fixtures_test.go` "goldens" are inline source strings with
`>= 1` / `t.Logf` assertions. **No golden regeneration step is required.**

| Test | Change | Reason |
|---|---|---|
| `internal/callgraph/python_grammar_facts_test.go` `TestPythonGrammarFacts_PinnedNodeShapes` | **extend** the 22-case table with the section-10 appendix rows | new node/field bindings become load-bearing (T0) |
| `internal/callgraph/python_parser_test.go` `TestPythonParser_ParseFile` and any test asserting `FunctionDecl` equality/`Parameters` | may need `Visibility`/`OwnerVisibility`/`Parameters[].Name` in expectations | row 18 + A2's field-node parameter parsing now populate previously-empty fields |
| `TestPythonParser_SelfNamedReceiver_FreeFunction`, `_ReceiverVar_ParameterShadowsImport` | re-verify unchanged | row 8's static-method rule touches parameter-0 receiver handling; the import-before-locals check order must survive |
| `TestPythonParser_ReceiverVar_ComprehensionTarget` | re-verify unchanged | D2 replaces the cloned-map comprehension scoping with layers; positive **and** negative sub-assertions must both still hold |
| `internal/scan` `TestPythonE2E_*`, `TestPythonGolden_*`, `python_multilib_smoke_test.go`, `python_fidelity_deployed_rules_test.go` | counts may **rise**; all assertions are `>= 1` or `t.Logf` | rows 7/9/11/13 resolve more callees; `crypto_entry_points` now carry `visibility`/`owner_visibility` |
| `internal/scan/resolved_key_length_test.go` (incl. the `wantAbsent` non-int-overload case) | must stay green **unchanged** | proves steps 1–2 are byte-identical and step 3b did not leak into Java |
| `internal/callgraph/python_perf_test.go` | modify doc comment; benchmark body unchanged | corpus and harness are unchanged; the new guard is a separate test |
| `internal/callgraph/contracts` loader tests | add `argument_byte_length` to any exhaustive-derivation assertion | new enum value + new error-message text |

## 7. Implementation order

Each step is RED-first (write the named test, observe failure), then GREEN, then
**re-run the perf guard** (`TestPythonParser_NodeVisitBudget` +
`BenchmarkPythonParseDirectory_Bindings`, ≥8 reps, mean + range) before the
commit is considered done, per the perf spec's fourth requirement.

| # | Row | RED test first | Then |
|---|---|---|---|
| 0 | T0 | `TestPythonGrammarFacts_*` (section 9) | correct expectations from real parser output, never the reverse |
| 1 | A1/A2/A3 | `TestPythonParser_NodeVisitBudget`, `TestPythonParser_ReturnTypeFromFieldNode` | single-descent rewrite, layer stack, deferred resolution, symbol table extension, `return_type`/`type` field nodes, committed budget corpus |
| 2 | A4 | — (measurement) | mining-scale `--scan-dependencies` before/after on a real large pip tree, recorded in apply-progress |
| 3 | 6 | `TestOpengrep_PythonEndColConventionPinning` | test-only; explicit skip reporting |
| 4 | 18 | `TestPythonParser_Visibility_*`, `_OwnerVisibility` | `pythonVisibilityForName` |
| 5 | 20 | `TestPythonParser_ArgProvenance_NestedConstructorCalls` | `ArgumentSources` for the three bounded shapes + `moduleConsts` |
| 6 | 8 | `TestPythonParser_Decorator_*` (4) | decorator classification, parameter-0 receiver rule, `@property` → attrs |
| 7 | 9 | `TestPythonParser_Super_*` (3) | `bases` on `pythonScope`, `super()` callee rewrite |
| 8 | 7 | `TestPythonParser_DynamicDispatch_*` (3) | literal-only `getattr`/`import_module`/`__import__` |
| 9 | 11 | `TestPythonParser_Partial_ResolvesTarget`, `_Call_DunderCall` | `partials`/`callables` scope maps |
| 10 | 13 | `TestPythonParser_TypeHint_*` (7) | annotation normalisation, `varTypes`, `propagatePythonAssignedVarTypes` |
| 11 | C | `TestResolvedKeyLength_Python_*` (5), `TestLoadEmbeddedPython_KDFKeySizeRoles`, `TestResolvedKeyLength_JavaUnchangedByKeywordPath` | derivation enum, steps 3a/3b, KB YAML |
| 12 | 14 | `TestPythonDepTypeResolver_*` (6) | dependency resolver, disk cache, chain, CLI wiring |
| 13 | — | full gates | `go test -race ./...`, `make lint`, `make coverage-check`, `git diff --check`, CHANGELOG `[Unreleased]`, `docs/user-guide/user-guide.html` |

Ordering rationale: A must land first because every later row is measured
against it; 6/18/20 are small confidence builders that also produce the fields
rows 8/13/C consume; C depends on 20's `ArgumentSources`; 14 is last and
abandonable (D7).

## 8. Risks, rejected alternatives, rollback

| Risk | Mitigation |
|---|---|
| Deferred resolution changes `decl.Calls` order and silently breaks `self.attr` rebinding lifecycle scoping | D3 + T0.6 pinning test asserting document order over a mixed fixture; `TestDeriveObjectLifecycleCalls_SelfAttrRebinding` re-run |
| Instance visit counter's nil check measurably costs throughput | one register compare per node vs a cgo `Symbol()` call per node; if the benchmark disagrees, move to a build-tagged file **and** add the tag to CI (never drop the guard) |
| Step 3b changes Java `resolved_key_length` output | only reachable after steps 1–2 return nil, only emits resolved constants; `TestResolvedKeyLength_JavaUnchangedByKeywordPath` + the existing `wantAbsent` case are the gate |
| KDF arities/indices in section 5.3 are wrong | they are design expectations, not facts; apply verifies each against library stubs/docs before authoring (crypto-kb-author) |
| Row 13/14 drift into inference | hard bounds in the spec and here: names resolvable via imports/KB/in-file classes only; no cross-file dataflow; unresolvable → no type |
| Rows re-inflate parse cost | every row re-runs both guards (section 7); a breaching row is optimised or dropped, never accepted |

**Rejected alternatives**: full Python type inference (contradicts the
documented `PythonContractTypeResolver` scope cut, enormous surface); Python
bytecode/`.pyc` reading (build-artifact-dependent, version-locked, absent for
source distributions); keeping the two-walk prepass + `walkForCalls` pair
(leaves ~1.85× node touches and cannot reach the budget); adding an exported
`FunctionCall`/`FunctionDecl` field (unnecessary — `ResolvedReceiverType`,
`Visibility`, `OwnerVisibility`, `ArgumentSources`, `FunctionParameter.Name`,
`graph.TypeHierarchy`, `graph.ExternalMethodSignatures` all already exist and are
already exported); a new KB `parameters[].name`-style schema field (already
present); relaxing `contractParameterTypesMatch` globally (would emit
unknown-provenance records for Java's `initialize(spec)`/`ECGenParameterSpec`
flow and break the existing `wantAbsent` test); a benchmark-derived CI assertion
(round-1 noise was 12.5%–27.5% on one machine).

**Rollback**: same branch (`matiasdaloia/parser-parity-multi-language`, PR #310),
one commit series per row in section 7's order. `git revert` of a row's range
leaves every earlier row intact; reverting 14 leaves A–C green; reverting C
leaves A–B green. No schema, cache-format, CLI-flag, or rule change, so no
consumer-visible rollback (the new Python signature cache is additive and
regenerates).

## 9. T0 pinning tests apply MUST write first (nothing here was executed)

| ID | Test | Pins |
|---|---|---|
| T0.1 | `TestPythonGrammarFacts_PinnedNodeShapes` (extend) | every appendix row in section 10 — decorators, `superclasses`, `super()`, `getattr`, `importlib`, params/annotations, `return_type`, annotated assignment, `keyword_argument`, module constants, nested call args, lambda, `await` |
| T0.2 | `TestPythonGrammarFacts_ReturnTypeField` | `function_definition` field `return_type` exists and its child is `type` (A2 depends on it) |
| T0.3 | `TestPythonSymbolTable_AllSymbolsResolved` | every entry added to `resolvePythonSymbols` resolved to a non-zero `sitter.Symbol` (a typo would silently match nothing) |
| T0.4 | `TestPythonParser_NodeVisitBudget` | visit count within `nodeCount + 8*callCount` and `>= nodeCount`, per committed fixture |
| T0.5 | `TestPythonParser_ReturnTypeFromFieldNode` | `ReturnType` correct for a 500+-line body without materialising it |
| T0.6 | `TestPythonParser_CallOrderIsDocumentOrder` | `decl.Calls` order under deferred resolution equals source order across comprehensions, nested defs, and chains (D3) |
| T0.7 | `TestOpengrep_PythonEndColConventionPinning` | real opengrep columns vs `StartCol`/`EndCol`; explicit skip report when the binary is absent |
| T0.8 | `TestPythonPerf_BaselineRecorded` (or apply-progress record) | `BenchmarkPythonParseDirectory_Bindings` at `c6ee180` and at HEAD, ≥8 reps one continuous run, mean + min/max |
| T0.9 | `TestLoadEmbeddedPython_KDFKeySizeRoles` | each section-5.3 contract loads with the expected arity, index, name, and `argument_byte_length` |
| T0.10 | `TestResolvedKeyLength_JavaUnchangedByKeywordPath` | Java's key-length output is identical before/after step 3a/3b |

## 10. Grammar appendix (pinned-grammar spike, orchestrator, 2026-08-27)

Field: type. Verified against the vendored `smacker/go-tree-sitter` Python
grammar; the spike file was deleted, so T0.1 must re-encode this table.

- `decorated_definition { decorator > identifier | attribute | call{function, arguments}, definition: function_definition }`. `@staticmethod`/`@property` are bare `identifier`s; `@app.route('/x')` is a `call`.
- `class_definition { name, superclasses: argument_list { identifier | attribute{object, attribute} }, body: block }`.
- `super().__init__()` → `call { function: attribute { object: call { function: identifier «super», arguments «()» }, attribute: identifier «__init__» }, arguments }`. `super(B, self).m()` is identical with arguments.
- `getattr(obj, 'encrypt')(data)` → `call { function: call { function: identifier «getattr», arguments { identifier obj, string { string_start, string_content «encrypt», string_end } } }, arguments }`.
- `importlib.import_module('hashlib')` → `call { function: attribute, arguments { string > string_content } }`; `__import__('hashlib')` → `call { function: identifier «__import__» }`.
- `functools.partial(f, a)` is an ordinary `call`; `p(b)` / `obj(x)` → `call { function: identifier }`.
- Parameters: `x: Cipher` → `typed_parameter { identifier, type: type > identifier }`; `y: Optional[Cipher] = None` → `typed_default_parameter { name, type: type > generic_type { identifier «Optional», type_parameter { type > identifier } }, value }`; `*args` → `list_splat_pattern > identifier`; `**kw` → `dictionary_splat_pattern > identifier`.
- Return: `function_definition` field `return_type: type`. `Cipher | None` → `type > binary_operator { left: identifier, right: none }`; `"Cipher"` → `type > string { string_content }`; `Union[Cipher, None]` → `type > generic_type { identifier «Union», type_parameter { type>identifier, type>none } }`.
- Annotated assignment: `assignment { left: identifier, type: type > identifier, right }`.
- Keyword arguments: `argument_list > keyword_argument { name: identifier, value: <expr> }`; positional arguments are direct children of `argument_list`.
- Module constants: `assignment { left: identifier «KEY_LEN», right: integer «32» }`.
- Nested constructor arguments: `call { function, arguments: argument_list { call, call } }` — nested calls are direct children.
- `_priv`, `__mangled`, `_Hidden` are plain `identifier`s; visibility is lexical on the name text.
- `await c.encrypt(x)` → `assignment { right: await > call }`; `lambda { parameters: lambda_parameters > identifier, body: call }`.
- Earlier-verified: `async def`/`async with`/`async for` are keyword-only variants of the ordinary nodes; relative imports use `module_name: relative_import { import_prefix, dotted_name }`.

## 11. Spec reconciliation

One deviation from the spec's stated field decisions, per D6.

**`python-kdf-key-length-resolution` → Requirement "Keyword-argument-aware
parameter-index mapping".** The spec's field decision names
`mergeCallParameters` (`internal/scan/export.go:2234`) as the place that parses
the leading `identifier=` and matches contract parameter names. Design deviates:
the parsing and matching live in `internal/scan/key_length.go`;
`mergeCallParameters` is **not** modified. Reason: `mergeCallParameters` builds
the exported `parameters[]` array for every call in every ecosystem, so
rewriting `parameter_index` there desyncs it from the declared-order-aligned
`parameter_roles[]`/`parameter_types[]` exports, and populating `resolved_value`
there changes output for every Python keyword argument rather than only KDFs.
`key_length.go` already interprets raw argument text and owns key-length policy.

Exact spec edits requested:
1. In that requirement's field-decision sentence, replace "the
   merge/resolution layer MUST parse that leading `identifier=`" with
   "`internal/scan/key_length.go` MUST parse that leading `identifier=`", and
   drop the implication that `parameter_index` is remapped.
2. Both of that requirement's scenarios remain valid verbatim; "Existing
   positional calls are unaffected" is strengthened, since
   `mergeCallParameters` and `contractParameterTypesMatch` are untouched.
3. Add one scenario under the same requirement for step 3b, otherwise
   `contractParameterTypesMatch` silently blocks every positional Python KDF
   call and the "KB coverage ... in both positional and keyword forms"
   requirement is untestable: *GIVEN a Python KDF contract declaring
   `parameter_types` and a purely positional call whose length argument is an
   integer literal, WHEN no call-site declared type is available for that index,
   THEN `resolved_key_length.bits` MUST resolve with `provenance: "constant"`,
   and a non-constant positional argument MUST resolve nothing.*

The orchestrator's other two field decisions are **adopted unchanged**: keyword
mapping reuses `FunctionCall.Arguments []string` (no new field), and row 20
provenance reuses `SourceNode.SourceNodes`/`CallTarget`.

Also carried forward: row 14's file is named
`python_dependency_type_resolver.go`, not the proposal's
`python_stub_type_resolver.go`, because it reads annotated `.py` sources as well
as `.pyi` stubs; and `internal/engine/dependency_scanner.go` is **not** in the
affected-areas set (D8).

## 12. Threat matrix

Row 6 invokes a real opengrep binary from a test, and row 14 walks
dependency-provided files, so two rows are `Applicable`; everything else is
`N/A`.

| Boundary | Applicability | Expected safe behavior | RED test |
|---|---|---|---|
| Subprocess execution | **Applicable** (row 6, test-only) | reuse the existing opengrep invocation helper used by `TestOpengrep_EndColConventionPinning`; no shell string interpolation; absent binary → explicit skip, never a fabricated pass | `TestOpengrep_PythonEndColConventionPinning` |
| Untrusted file reads / path traversal | **Applicable** (row 14) | index only files under the resolved distribution dir; no symlink following outside it; unreadable/oversized file → skip that file, resolve nothing, no error | `TestPythonDepTypeResolver_NoAnnotationsDegrades` + `_ProjectLocalUnaffected` |
| Network access | N/A | row 14 makes none by construction (filesystem + tree-sitter only); tests use committed fixtures | — |
| Routing / VCS / PR automation / executable-file classification / process integration | N/A — no such boundary; all other work is in-process tree-sitter parsing of files the scanner already reads | — | — |

## 13. Open questions

- [ ] None blocking. Two items need the orchestrator's acknowledgement rather
      than a decision: the section-11 spec edits (D6), and the section-5.3
      arities/indices, which apply must verify against primary library sources
      before authoring.
