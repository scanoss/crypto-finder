# Design: Python parser parity with Java (callgraph binding resolution)

## Technical Approach

Everything lands in `internal/callgraph/python_parser.go` plus one ecosystem-scoped
post-parse pass in `builder.go`. The parser gains the layer Java already has: a
per-scope **binding table** (parameters + every syntactic binder) and a
**class-scoped attribute set**, both collected in one pass and consulted by the
existing `pythonReceiverVarName` / `pythonAssignedVarFromParent` seams. Two
synthetic decls (`<module>`, `<clinit>`) give module-load and class-body calls a
real container, mirroring `parseClassInitDecl`. Imports become a recursive walk
with real `relative_import` handling. `__init__.py` re-exports are stitched by
rewriting callee packages after Phase 1, never by cross-file type inference.

`PythonContractTypeResolver` is untouched: this change improves *structure*, not
type inference.

## Grammar facts (pre-flight)

**Tool constraint (must be reported):** this executor has no Bash tool, so the
S-expression dump and the baseline `go test` run could not be executed. Instead
the pinned grammar (`smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82`,
`python/parser.c`) was read directly. Its symbol and field tables are
authoritative for **names**; per-node field *bindings* are pinned by mandatory
task T0 below rather than asserted here on faith.

Verified node types present: `module`, `with_statement`, `with_clause`,
`with_item`, `as_pattern`, `as_pattern_target` (alias node), `for_statement`,
`for_in_clause`, `except_clause`, `except_group_clause`, `named_expression`,
`pattern_list`, `tuple_pattern`, `list_pattern`, `list_splat_pattern`,
`dictionary_splat_pattern`, `augmented_assignment`, `typed_parameter`,
`default_parameter`, `typed_default_parameter`, `import_prefix`,
`relative_import`, `aliased_import`, `wildcard_import`, `list_comprehension`,
`generator_expression`, `decorator`, `decorated_definition`, `lambda`, `await`.

Verified complete field-name set: `alias, alternative, argument, arguments,
attribute, body, cause, code, condition, consequence, definition, expression,
format_specifier, function, guard, key, left, module_name, name, object,
operator, operators, parameters, return_type, right, subject, subscript,
superclasses, type, type_conversion, type_parameters, value`.

Three consequences are load-bearing:

1. There is **no `pattern` field** in this grammar. `for_statement` and
   `for_in_clause` expose `left`/`right`. Any code written against a `pattern`
   field would silently bind nothing.
2. `async def` / `async with` / `async for` are **not distinct node types** —
   `async` is an anonymous keyword child of the ordinary node. Exploration row 17
   is therefore structurally free: the same handlers cover both variants.
3. `import_from_statement` has a `module_name` field whose child is either a
   `dotted_name` **or** a `relative_import` wrapping `import_prefix` +
   `dotted_name`. The current loop scans direct children for `dotted_name`, so
   for `from .foo import Bar` the *first* `dotted_name` it meets is `Bar` (the
   `foo` is nested inside `relative_import`) — the module path is set to `Bar`
   and the import is lost. `Node.FieldNameForChild(i)` exists in this binding and
   is the correct way to read the repeated `name:` fields.

## Architecture decisions

### Decision: `self.attr` identity is the literal string `self.<attr>`

**Choice**: `ReceiverVar`/`AssignedVar` carry `"self.cipher"` verbatim;
`cls.<attr>` is canonicalised to `self.<attr>` so a classmethod binding and an
instance-method use share one identity. `Callee.Type` uses the same token.
**Alternatives**: bare `"cipher"` (Java's shape, because Java has an implicit
`this`); a minted token per rebinding (`self.cipher@2`).
**Rationale**: `deriveObjectLifecycleCalls` (`internal/scan/supporting_calls.go`)
groups by pure string equality and never parses the token, so `self.cipher`
works unchanged. Bare `cipher` would collide with a local `cipher` in the same
method and mis-group two different objects. Minted tokens would leak synthetic
text into the export and force a change to `supporting_calls.go`, which the spec
forbids.

### Decision: rebinding is left to the existing positional selector

**Choice**: emit one canonical string per attribute name; do **not** model
rebinding in the parser, and do **not** port Java's `mergeFieldAssignment`
invalidation.
**Alternatives**: invalidate on multiple assignments (Java `a9dae82`); mint
per-binding identities.
**Rationale**: `lifecycleSelector.selectDescendants(objectVar, since)` already
splits a reassigned name positionally by call index ("a name is not an
identity"). Java's invalidation protects `resolvedType`, a field this change
never populates for Python. So the spec's rebinding scenario is satisfied with
zero new logic — but only **within one `FunctionDecl`**, which is the only scope
lifecycle grouping ever examines. The `TestDeriveObjectLifecycleCalls_SelfAttrRebinding`
fixture must therefore put both bindings in the same method.

### Decision: `<module>` is keyed by the module's dotted path

**Choice**: adopt the spec's names verbatim — `<module>` (`Type: ""`) and
`<clinit>` (`Type: <class>`) — but set `Package` to the module's own dotted path
(`packagePath + "." + <file stem>`; plain `packagePath` for `__init__.py`, whose
module name *is* the package).
**Alternatives**: `Package = packagePath` for every file, as the spec's wording
reads literally.
**Rationale**: in Python one directory is one package, so
`FunctionID{Package:"pkg", Type:"", Name:"<module>"}` collides for every sibling
file. `addAnalyses` would fall into `preservePythonModuleCollision`, keeping one
decl under the shared `pkg.<module>` key and emitting *alias copies* of both — a
duplicated export row per file at mining scale. The dotted path is collision-free
by construction, is exactly CPython's module identity, and reuses the convention
`addPythonModuleAlias` already encodes (`Package + "." + stem`). Both spec
scenarios assert only `ID.Name` and `ID.Type`, so both still pass.

### Decision: `<clinit>` reuses Java's name

**Choice**: reuse `clinitMethodName` for Python class bodies (bare, no arity
suffix — Python names never carry one).
**Rationale**: `builder.go:890` already suppresses virtual dispatch fan-out for
`<clinit>` callees; reusing the name inherits that guard for free. `<init>` is
already reused this way (`__init__` → `<init>`), so it is the established
cross-language convention here.

### Decision: the synthetic walk prunes at every deferred-execution node

**Choice**: `<module>` aggregates the direct children of `module` and `<clinit>`
the direct children of the class `block`, in both cases pruning the subtree at
`function_definition`, `class_definition`, `decorated_definition`, and `lambda`.
Decorator *expressions* are excluded. No decl is emitted when the resulting call
list is empty.
**Alternatives**: walk everything (attribute nested defs to module scope);
include decorator arguments.
**Rationale**: pruning keeps behaviour identical to today for
conditionally-defined functions (their calls stay unregistered — a pre-existing
gap, since `extractDeclarations` only scans direct root children) instead of
*mis*-attributing a function body's calls to a module-load entry point, which
would fabricate reachability. `lambda` bodies run on invocation, not at load.
Decorators belong to deferred row 8 and carry their own evaluation-semantics
question. The empty-list rule is what keeps
`TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis` at zero.

### Decision: re-export stitching is a builder post-parse rewrite, gated on in-graph evidence

**Choice**: the parser records `FileAnalysis.PythonReExports` (symbol → origin
module path) **only** from `__init__.py`, **only** from explicit relative
`from .mod import Sym [as Alias]`. The builder accumulates them in `addAnalyses`
and, at the end of Phase 1, runs `applyPythonReExports(graph, table)` — which
rewrites `Callee.Package` **only when the rewritten FQN exists as a declaration
in the graph and the original does not**.
**Alternatives**: resolve inside `ParseDirectory` (an `__init__.py` is a sibling
of its package's modules); emit alias decls; rewrite unconditionally.
**Rationale**: parse order is parent-directory-first and workers are parallel
with cloned parsers, so no parser-local cache is order-safe. `markCPPProjectLocalCalls`
is the existing precedent for an ecosystem-scoped post-parse pass. The in-graph
gate is the precision rule that matters: KB YAMLs are keyed on **public**
re-export paths (`Crypto.Cipher.AES.new`), so an unconditional rewrite to a
private impl path would *destroy* KB resolution. Gated, a rewrite can only ever
create an edge that was otherwise missing. Wildcard re-exports (`from .mod import *`),
absolute imports inside `__init__.py`, and `__all__` are all ignored.

### Decision: imports are recursive, first binding wins

**Choice**: `extractImports` recurses over the whole tree (no pruning — function-local
imports are in scope per the spec) and does not overwrite an existing
`Imports[name]`.
**Rationale**: pre-order traversal is document order, so file-scope imports are
seen before nested fallbacks. For the spec's
`try: import fastcrypto as crypto / except ImportError: import crypto`, both
bindings share the key `crypto`; first-wins deterministically keeps the primary
(`crypto → fastcrypto`). See *Spec reconciliation*.

## Interfaces

```go
// pythonBindings is the per-scope answer to "can this receiver text be an
// object identity?". Every binder node type lives behind it.
type pythonBindings struct {
    locals map[string]bool // parameters + all binder forms in this body
    attrs  map[string]bool // class-scoped attribute names (canonical, no prefix)
}

func collectPythonBindings(body, params *sitter.Node, src []byte, attrs map[string]bool) pythonBindings
func (b pythonBindings) receiverIdentity(object string) string // "" when not an object
func collectPythonClassAttrs(classBody *sitter.Node, src []byte) map[string]bool
func pythonParameterNames(params *sitter.Node, src []byte) []string
func pythonRelativeModulePath(packagePath, prefix, dotted string) (string, bool)
```

`receiverIdentity` subsumes `pythonReceiverVarName` and keeps its **check order**:
`objectIsCall` → import → `self`/`cls` bare → CapitalCase type name → attribute
set → locals. Imports must stay ahead of locals or `TestPythonParser_ModuleCall_NoReceiverVar`
regresses once parameters become locals. `self` and `cls` bare receivers still
return `""` (a class receiver is not an object).

Binder node types feeding `locals`: `assignment` (identifier, `pattern_list`,
`tuple_pattern`, `list_pattern`, `list_splat_pattern` targets),
`augmented_assignment`, `as_pattern` (covers both `with ... as` and
`except ... as`), `for_statement`/`for_in_clause` `left`, `named_expression`
`name`, and parameters (`identifier`, `typed_parameter`, `default_parameter`,
`typed_default_parameter`, `list_splat_pattern`, `dictionary_splat_pattern`;
`/` and `*` separators skipped, `self`/`cls` recorded but never returned as
identities).

## Data flow

    parseFile
      ├─ extractImports (recursive; relative_import → pythonRelativeModulePath)
      ├─ collectPythonReExports (only when basename == __init__.py)
      └─ extractDeclarations
           ├─ function_definition ─┐
           ├─ class_definition ────┤ collectPythonClassAttrs(classBody)
           │    └─ methods ────────┤        │
           ├─ <clinit> decl (class body, pruned)
           └─ <module> decl (module body, pruned)
                                   ↓
                      collectPythonBindings(body, params, attrs)
                                   ↓
                      walkForCalls → parseCallExpr → parseAttributeCall
                                   ↓
                 ReceiverVar / AssignedVar / ChainID  (unchanged field set)
                                   ↓
    Builder Phase 1 end → applyPythonReExports(graph, table)   [python only]
                                   ↓
    export.go ContainingFunction (tightest span: real methods still win)
                                   ↓
    scan/supporting_calls.go deriveObjectLifecycleCalls (byte-for-byte unchanged)

## File changes

| File | Action | Description |
|---|---|---|
| `internal/callgraph/python_parser.go` | Modify | All six rows: binding table, class attrs, `<module>`/`<clinit>`, recursive + relative imports, re-export collection |
| `internal/callgraph/builder.go` | Modify | `PythonReExports` accumulation in `addAnalyses`; `applyPythonReExports` pass at end of Phase 1 |
| `internal/callgraph/types.go` | Modify | Add `moduleInitMethodName = "<module>"`, `functionTypeModuleInit`; rename `javaFunctionTypeClassInit` → `functionTypeClassInit` (shared) and add `FileAnalysis.PythonReExports map[string]string` |
| `internal/callgraph/java_parser.go` | Modify | Mechanical: 2 references to the renamed constant |
| `internal/callgraph/java_parser_clinit_test.go` | Modify | Mechanical: 2 references to the renamed constant |
| `internal/callgraph/python_grammar_facts_test.go` | Create | **T0** pinning test: node type + field bindings per idiom |
| `internal/callgraph/python_parser_test.go` | Modify | Row 1/3/2/12/4 unit tests (spec-named) |
| `internal/callgraph/python_parser_reexport_test.go` | Create | `TestBuilder_InitPyReexport_*` (two-file package layout) |
| `internal/scan/supporting_calls_test.go` | Modify | `TestDeriveObjectLifecycleCalls_{ParameterReceiver,SelfAttrRebinding,ModuleSyntheticReceiver}` |
| `internal/callgraph/testdata/python_perf/generate_fixture.go` | Create | Generator for the parse benchmark corpus |
| `internal/callgraph/python_perf_test.go` | Create | `BenchmarkPythonParseDirectory_Bindings` (skips if fixture absent) |
| `CHANGELOG.md` | Modify | `[Unreleased] → Fixed`/`Changed` |
| `pkg/graphfrag`, `internal/scan/export.go`, `internal/scan/supporting_calls.go`, `internal/callgraph/contracts/` | Unchanged | Zero diff — verified against `exportFunctionFQN`, which renders `<module>`/`<clinit>` through existing fields only |

Note: the proposal lists `internal/callgraph/python_e2e_integration_test.go`.
That file does not exist; the e2e suite is `internal/scan/python_e2e_integration_test.go`.

## Performance

Single pass, no per-call re-walk. Per function body: one binding walk O(nodes)
plus the existing call walk O(nodes) — unchanged asymptotics, one extra constant-factor
traversal. Per class: one attribute walk over the class body, shared by all its
methods (collected once in `processClass`, passed down — never recollected per
method). Imports move from O(root children) to O(nodes) once per file.
`applyPythonReExports` is O(calls) with map lookups and only runs for Python.
The only volume growth is at most one `<module>` decl per file and one `<clinit>`
per class, each only when calls exist.

Benchmark plan mirrors the existing `testdata/inference_perf` convention: a
committed `generate_fixture.go` emits N synthetic modules exercising every binder
form (generated corpus not committed; the benchmark `t.Skip`s when absent), and
`BenchmarkPythonParseDirectory_Bindings` is recorded before and after. Guard: no
more than 10% added parse time, matching `TestPerformance_InferenceOverhead`'s
precedent. A pip-resolved dependency tree was rejected as a benchmark base — it
is non-deterministic and network-dependent.

## Existing Python tests: exposure analysis

No existing Python test is expected to change its expectations. Each real
exposure is closed by a named design rule; apply must not "fix" a test by
weakening it.

| Test | Exposure | Protecting rule | Expected |
|---|---|---|---|
| `TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis` (`internal/scan`) | a `<module>` decl could add a synthesizable definition → count ≠ 0 | no decl when the body has no direct calls; that file has none | pass unchanged |
| `TestPythonParser_ModuleCall_NoReceiverVar` | parameters becoming locals could let an import name resolve as a receiver | import check stays ahead of the locals check in `receiverIdentity` | pass unchanged |
| `TestPythonParser_ParseFile`, `TestPythonParser_DunderMethodSkip` | presence/absence maps over `analysis.Functions` gain new names | both fixtures have zero module-level and zero class-body calls → no synthetic decls | pass unchanged |
| `TestPythonParser_FunctionCallCarriesNonZeroColumns` | now also iterates synthetic decls' calls | synthetic calls go through the same `parseCallExpr` column path | pass, with wider coverage |
| `python_chain_integration_test.go` (4 tests) | `ChainID`/`AssignedVar` on chain roots | chain walker untouched; parameters only *add* identities | pass unchanged |
| `internal/scan/python_golden_fixtures_test.go`, `python_multilib_smoke_test.go`, `python_fidelity_deployed_rules_test.go` | fixtures with module-level calls gain a `<module>` decl, growing entry-point/supporting-call counts | all assertions are `>= 1` or `t.Logf`; no exact-count assertion exists in `internal/scan` | pass; counts may rise (intended precision gain) |
| `internal/callgraph/python_parser_from_import_test.go`, `python_mro_dispatch_test.go`, `python_type_resolver_test.go` | import-map shape / MRO | recursive walk only *adds* keys (first-wins); MRO and resolver untouched | pass unchanged |

Baseline note: the green baseline (`go test ./internal/callgraph/ -run Python -count=1`)
could not be re-run here — no Bash tool. The proposal records it verified on
2026-08-26. The Python test inventory is 6 files in `internal/callgraph`
(`python_parser_test.go` 9 tests, `python_parser_lifecycle_test.go` 5,
`python_chain_integration_test.go` 4, `python_parser_from_import_test.go` 3,
`python_type_resolver_test.go` 5, `python_mro_dispatch_test.go` 1 exported +
MRO cases) and 4 files in `internal/scan` (`python_e2e_integration_test.go` 12,
`python_golden_fixtures_test.go` 8+1, `python_multilib_smoke_test.go` 1,
`python_fidelity_deployed_rules_test.go`). Apply must run both packages and
record the real counts.

## Implementation order (strict TDD, one RED test first per step)

| # | Row | RED test first | Then |
|---|---|---|---|
| T0 | — | `TestPythonGrammarFacts_PinnedNodeShapes` (table: snippet → node type → field name, incl. `with/as`, `for/in`, `except/as`, walrus, `a, *rest =`, `from . import`, `from ..pkg import`, `async def/with/for`, comprehension, `self.k = F(key)`, class-body and module-level assignment) | Correct expectations from real parser output, never the reverse. Every later step reads this table. |
| T1 | 1 | `TestPythonParser_ReceiverVar_Parameter` | `pythonParameterNames` + `pythonBindings`, thread `paramNode` into `extractCalls` |
| T2 | 3 | `_WithAs`, `_AsyncWithAs`, `_ForIn`, `_AsyncForIn`, `_ExceptAs`, `_Walrus`, `_TupleUnpacking`, `_ComprehensionTarget` | binder node coverage inside `collectPythonBindings` |
| T3 | 2 | `_SelfAttr_CrossMethodProvenance`, `_ClsAttr_ClassmethodProvenance`, `_SelfAttr_NoInheritance`, `TestDeriveObjectLifecycleCalls_SelfAttrRebinding` | `collectPythonClassAttrs`, `self.x` receiver + `AssignedVar`, `cls`→`self` canonicalisation |
| T4 | 12 | `_SyntheticEntryPoint_ModuleLevel`, `_ClassBody`, `_EmptyBodyOmitted`, `TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver` | `<module>`/`<clinit>` decls, pruning rule, shared `functionTypeClassInit` |
| T5 | 4 | `_Import_TryExcept`, `_TypeChecking`, `_FunctionLocal`, `_RelativeSingleDot`, `_RelativeDoubleDot` | recursive `extractImports`, `relative_import` via `module_name`/`FieldNameForChild` |
| T6 | 15 | `TestBuilder_InitPyReexport_SiblingResolution`, `_NoInferredType` | `PythonReExports` + gated `applyPythonReExports` |
| T7 | — | `BenchmarkPythonParseDirectory_Bindings` | fixture generator, before/after record, CHANGELOG |

Dependency order is the prompt's 1 → 3 → 2 → 12 → 4 → 15: the binding table must
exist before the attribute set uses it, and both must exist before the synthetic
decls (whose calls run through the same resolution path). T5/T6 are
independent of T1–T4 and can slice into a separate PR if review load demands it.

## Spec reconciliation

Adopt `<module>` and `<clinit>` as named; no naming disagreement. Three items
must be carried into tasks so the artifacts do not silently diverge:

1. **`<module>` Package component** — read "module package path" as the module's
   dotted path (`pkg.a` for `pkg/a.py`, `pkg` for `pkg/__init__.py`). Rationale
   above (sibling-file key collision). Affected scenario: *Module-level crypto
   call gets a synthetic entry point*; its assertions (`ID.Name`, `ID.Type`) are
   unaffected, but `TestPythonParser_SyntheticEntryPoint_ModuleLevel` should also
   assert `ID.Package == "<pkg>.<stem>"`.
2. **`try/except ImportError` scenario** — "both bindings MUST be recorded" is
   unsatisfiable: `import fastcrypto as crypto` and `import crypto` share the key
   `crypto`. `TestPythonParser_Import_TryExcept` must assert
   `Imports["crypto"] == "fastcrypto"` (first binding wins).
3. **Schema-version pin location** — the last scenario cites
   `internal/callgraph/python_e2e_integration_test.go`. The `6.13` /
   `graph-fragment-1.13` assertions actually live in
   `internal/scan/export_schema_test.go` and `internal/scan/fragment_export_test.go`;
   the Python e2e file has no schema assertion. Point the scenario at those two
   files (unchanged, run as a guard) instead of extending the Python e2e file.

Additionally: the rebinding scenario is only meaningful within one method decl
(lifecycle grouping never crosses decls) — the fixture must be single-method.

## Alternatives considered and rejected

| Option | Why rejected |
|---|---|
| Real Python type inference (assignment/import chain walking) | Contradicts the documented `PythonContractTypeResolver` scope cut (REQ-4.2/CC-4); enormous surface for a structural problem |
| Solve `self.attr` in the KB YAML | Not a KB concern — the KB already fires once calls carry the right FQN and structure; no YAML can invent receiver identity |
| Resolve `__init__.py` re-exports inside `ParseDirectory` | Parent dirs are parsed before subdirs and workers run in parallel with cloned parsers; no parser-local cache is order-safe |
| Rewrite re-exported callee packages unconditionally | Would rewrite public KB-keyed paths (`Crypto.Cipher.AES.new`) to private impl paths and destroy KB resolution |
| Mint per-rebinding receiver tokens | Leaks synthetic text into the export and forces a change to `supporting_calls.go`, which the spec forbids |
| Bare `cipher` for `self.cipher` (Java's textual shape) | Collides with a same-named local in the same method and mis-groups two distinct objects |
| Walk nested/conditional defs into `<module>` | Fabricates entry-point reachability for code that does not run at import |
| Include decorator arguments in the synthetic decls | Straddles deferred row 8 and adds a second evaluation-semantics question with no evidence of frequency |
| pip-resolved dependency tree as benchmark base | Non-deterministic and network-dependent; the repo's precedent is a committed fixture generator |

## Threat Matrix

N/A — no routing, shell, subprocess, VCS/PR automation, executable-file
classification, or process-integration boundary. All work is in-process
tree-sitter parsing of files the scanner already reads.

## Migration / rollout

No migration. No schema version, persisted state, cache format, CLI flag, rule,
or KB change. Rollback is a single revert; stale callgraph cache entries
regenerate on the next scan.

## Open questions

- [ ] None blocking. T0 must run before T1–T6; if it contradicts any node/field
      binding assumed above, the binding table changes but no decision does.

## Appendix: grammar spike — executed by the orchestrator (2026-08-26)

The pre-flight spike was run against the pinned `smacker/go-tree-sitter`
(`v0.0.0-20240827094217-dd81d9e9be82`) Python grammar with a throwaway test
(deleted afterwards). Verified node shapes, `field: type`:

- `with x as y` → `with_statement > with_clause > with_item > value: as_pattern { <expr>, alias: as_pattern_target > identifier }`. `async with` is identical (keyword only).
- `for k in keys` → `for_statement { left: identifier, right: <expr>, body: block }`. `async for` identical.
- `except E as e` → `except_clause > as_pattern { identifier, alias: as_pattern_target > identifier }`; a bare `except E:` has `identifier` then `block` directly.
- `(m := f())` → `named_expression { name: identifier, value: <expr> }`.
- `a, *rest = f()` → `assignment { left: pattern_list { identifier, list_splat_pattern > identifier }, right: call }`.
- `x: T = v` → `assignment { left: identifier, type: type, right: <expr> }`; `x += 1` → `augmented_assignment { left, right }`.
- `from . import x` → `import_from_statement { module_name: relative_import { import_prefix }, name: dotted_name }`.
- `from ..pkg import y` → `module_name: relative_import { import_prefix, dotted_name }`.
- `from .foo import Bar as Baz` → `name: aliased_import { name: dotted_name, alias: identifier }`.
- `import a as b` → `import_statement { name: aliased_import { name: dotted_name, alias: identifier } }`; nested imports inside `try_statement > body: block` and `except_clause > block` are ordinary children (confirms recursive walk is required).
- `[h(x) for x in xs]` → `list_comprehension { body: call, for_in_clause { left: identifier, right: <expr> } }`.
- `await g()` → `expression_statement > await > call`.
- `self.k = Fernet(key)` / `cls.c = Fernet(k)` → `assignment { left: attribute { object: identifier, attribute: identifier }, right: call }`.
- Class-body `K = ...` → `class_definition { name, body: block > expression_statement > assignment }`.
- Module-level statements are direct `expression_statement` children of `module`.
- `@classmethod` → `decorated_definition { decorator > identifier, definition: function_definition { parameters: parameters > identifier… } }`.

Task T0 (`TestPythonGrammarFacts_PinnedNodeShapes`) should encode exactly this table.
