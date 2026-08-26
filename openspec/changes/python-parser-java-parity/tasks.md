# Tasks: Python parser parity with Java (callgraph binding resolution)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1800-2400 (python_parser.go ~350-450, builder.go ~100, types.go ~20, java_parser.go ~4, ~10 new/modified test files ~1200-1700; generated perf fixture corpus not committed) |
| 400-line budget risk | High |
| Chained PRs recommended | No — `delivery_strategy=exception-ok` already accepted by the user; single PR ships under `size:exception` |
| Suggested split | Single PR (informational work-unit table below documents the internal T0-T7 slices, not separate PRs) |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

### Suggested Work Units (informational — not split into separate PRs)

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| T0 | Pin grammar node/field shapes | single PR | `go test ./internal/callgraph/ -run TestPythonGrammarFacts_PinnedNodeShapes -count=1` | N/A — parses inline snippets only | Delete `python_grammar_facts_test.go` |
| T1 | Parameter receivers | single PR | `go test ./internal/callgraph/ -run TestPythonParser_ReceiverVar_Parameter -count=1` | `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_ParameterReceiver -count=1` | Revert `pythonParameterNames`/binding-table param wiring |
| T2 | Non-assignment binders | single PR | `go test ./internal/callgraph/ -run TestPythonParser_ReceiverVar_ -count=1` | N/A — parser-unit only | Revert binder cases in `collectPythonBindings` |
| T3 | `self`/`cls` attribute provenance | single PR | `go test ./internal/callgraph/ -run 'TestPythonParser_SelfAttr\|TestPythonParser_ClsAttr' -count=1` | `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_SelfAttrRebinding -count=1` | Revert `collectPythonClassAttrs` |
| T4 | Synthetic `<module>`/`<clinit>` | single PR | `go test ./internal/callgraph/ -run TestPythonParser_SyntheticEntryPoint -count=1` | `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver -count=1` | Revert synthetic decl emission + rename |
| T5 | Import robustness | single PR | `go test ./internal/callgraph/ -run TestPythonParser_Import_ -count=1` | N/A — parser-unit only | Revert recursive `extractImports` |
| T6 | `__init__.py` re-export stitching | single PR | `go test ./internal/callgraph/ -run TestBuilder_InitPyReexport -count=1` | `go test ./internal/scan/ -run TestPythonE2E -count=1` (fixture regression) | Revert `applyPythonReExports` + `PythonReExports` field |
| T7 | Perf guard | single PR | `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -run ^$ -count=1` | N/A — benchmark skips without committed fixture | Delete `python_perf_test.go`/`generate_fixture.go` |

## Phase 0: Grammar-Facts Pin (T0)

- [ ] 0.1 Create `internal/callgraph/python_grammar_facts_test.go` with `TestPythonGrammarFacts_PinnedNodeShapes`: table-driven, one case per idiom in design Appendix (with/as, async with, for/in, async for, except/as, walrus, tuple/star unpack, augmented assign, typed/default params, relative import single/double dot, aliased import, comprehension, `self.k=F(key)`, class-body assign, module-level assign) asserting node type + field name via `Node.FieldNameForChild`.
- [ ] 0.2 Run `go test ./internal/callgraph/ -run TestPythonGrammarFacts_PinnedNodeShapes -count=1`; must pass on first run (validates real parser against the design table, no production code changes). If any case contradicts the table, stop and update the table only — no downstream task starts until 0.2 is green. Depends on: none.

## Phase 1: Row 1 — Parameter-as-receiver binding (T1)

- [ ] 1.1 RED: add `TestPythonParser_ReceiverVar_Parameter` to `python_parser_test.go` (fixture: `def encrypt(cipher): cipher.update(data)`; assert `ReceiverVar == "cipher"`). Run `go test ./internal/callgraph/ -run TestPythonParser_ReceiverVar_Parameter -count=1`; observe fail. Depends on: 0.2.
- [ ] 1.2 RED: add `TestDeriveObjectLifecycleCalls_ParameterReceiver` to `internal/scan/supporting_calls_test.go` (parameter object with terminal + setup call). Run `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_ParameterReceiver -count=1`; observe fail. Depends on: 1.1.
- [ ] 1.3 GREEN: implement `pythonParameterNames(params, src)` and `pythonBindings.locals` param coverage (`identifier`, `typed_parameter`, `default_parameter`, `typed_default_parameter`, `list_splat_pattern`, `dictionary_splat_pattern`; skip `/`,`*` separators; record but never return `self`/`cls`); thread `paramNode` into `extractCalls`. Files: `internal/callgraph/python_parser.go`. Re-run 1.1 and 1.2 green.
- [ ] 1.4 REFACTOR: fold `pythonReceiverVarName`/`pythonAssignedVarFromParent` into `pythonBindings.receiverIdentity`, preserving check order `objectIsCall → import → self/cls bare → CapitalCase type → attrs → locals`. Re-run `go test ./internal/callgraph/ -run TestPythonParser_ModuleCall_NoReceiverVar -count=1` to confirm imports still outrank locals.

## Phase 2: Row 3 — Non-assignment binding coverage (T2)

- [ ] 2.1 RED: add to `python_parser_test.go`: `TestPythonParser_ReceiverVar_WithAs`, `_AsyncWithAs`, `_ForIn`, `_AsyncForIn`, `_ExceptAs`, `_Walrus`, `_TupleUnpacking`, `_ComprehensionTarget` (each fixture per spec scenario). Run `go test ./internal/callgraph/ -run TestPythonParser_ReceiverVar_ -count=1`; observe failures for the 8 new cases. Depends on: 1.4.
- [ ] 2.2 GREEN: extend `collectPythonBindings` to walk `as_pattern` (with/except alias target), `for_statement`/`for_in_clause` `left`, `named_expression` `name`, `pattern_list`/`tuple_pattern`/`list_splat_pattern` assignment targets, and comprehension `for_in_clause` targets scoped to the comprehension only (do not leak into enclosing scope). File: `internal/callgraph/python_parser.go`. Re-run 2.1 green.
- [ ] 2.3 REFACTOR: dedupe binder-node dispatch into one switch keyed by node type inside `collectPythonBindings`; confirm `async` variants need no separate case (keyword-only, per T0 finding).

## Phase 3: Row 2 — `self`/`cls` instance-attribute provenance (T3)

- [ ] 3.1 RED: add `TestPythonParser_SelfAttr_CrossMethodProvenance`, `TestPythonParser_ClsAttr_ClassmethodProvenance`, `TestPythonParser_SelfAttr_NoInheritance` to `python_parser_test.go`. Run `go test ./internal/callgraph/ -run 'TestPythonParser_SelfAttr|TestPythonParser_ClsAttr' -count=1`; observe fail. Depends on: 2.3.
- [ ] 3.2 RED: add `TestDeriveObjectLifecycleCalls_SelfAttrRebinding` to `internal/scan/supporting_calls_test.go`; fixture: `self.cipher = AES(); self.cipher.encrypt(a); self.cipher = RSA(); self.cipher.encrypt(b)` all in ONE method (cross-method grouping is out of scope — lifecycle selection never crosses `FunctionDecl`). Run `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_SelfAttrRebinding -count=1`; observe fail.
- [ ] 3.3 GREEN: implement `collectPythonClassAttrs(classBody, src)` scanning only the literal class body (no base-class/inheritance walk) for `self.attr = ...` / `cls.attr = ...` across all methods; canonicalize identity as literal string `self.<attr>` (`cls.<attr>` maps to the same `self.<attr>` token, per design decision — not bare `<attr>`, to avoid colliding with a same-named local). Files: `internal/callgraph/python_parser.go`. Re-run 3.1 and 3.2 green.
- [ ] 3.4 REFACTOR: verify no new invalidation/rebinding logic was added (rebinding correctness comes free from the existing positional `lifecycleSelector.selectDescendants`, per design) — confirm `internal/scan/supporting_calls.go` still shows zero diff (`git diff --stat internal/scan/supporting_calls.go`).

## Phase 4: Row 12 — Synthetic module/class-body entry points (T4)

- [ ] 4.1 GREEN (mechanical, not TDD): rename `javaFunctionTypeClassInit` → shared `functionTypeClassInit` in `internal/callgraph/types.go`; add `moduleInitMethodName = "<module>"` and `functionTypeModuleInit` constants. Update 2 references in `internal/callgraph/java_parser.go`.
- [ ] 4.2 Update EXISTING test `internal/callgraph/java_parser_clinit_test.go`: replace its 2 references to `javaFunctionTypeClassInit` with `functionTypeClassInit`. Intended expectation: unchanged runtime behavior/value — compile-only rename, no assertion changes. Run `go test ./internal/callgraph/ -run TestJava -count=1` (or the file's exact test names) to confirm still green. Depends on: 4.1.
- [ ] 4.3 RED: add `TestPythonParser_SyntheticEntryPoint_ModuleLevel` (assert `ID.Name=="<module>"`, `ID.Type==""`, `ID.Package == "<pkg>.<stem>"` per spec-reconciliation item 1 — module dotted path, not bare package path, to avoid sibling-file key collisions), `_ClassBody` (`ID.Name=="<clinit>"`, `ID.Type==<class>`), `_EmptyBodyOmitted` (no decl when body has no direct calls) to `python_parser_test.go`. Run `go test ./internal/callgraph/ -run TestPythonParser_SyntheticEntryPoint -count=1`; observe fail. Depends on: 4.2, 3.4.
- [ ] 4.4 RED: add `TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver` to `internal/scan/supporting_calls_test.go` (module-level `cipher = Cipher(); cipher.set_key(k); cipher.encrypt(data)`). Run `go test ./internal/scan/ -run TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver -count=1`; observe fail.
- [ ] 4.5 GREEN: emit `<module>` decl (Package = module's own dotted path: `packagePath + "." + stem`, or bare `packagePath` for `__init__.py`) for direct-child calls of `module`, and `<clinit>` decl (Type = class name, reusing `functionTypeClassInit`) for direct-child calls of a class `block`; prune subtree walk at `function_definition`, `class_definition`, `decorated_definition`, `lambda`; emit no decl when the pruned call list is empty. Files: `internal/callgraph/python_parser.go`. Re-run 4.3 and 4.4 green; re-run `go test ./internal/scan/ -run TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis -count=1` to confirm the empty-body guard holds.

## Phase 5: Row 4 — Import resolution robustness (T5)

- [ ] 5.1 RED: add `TestPythonParser_Import_TryExcept` (fixture: `try: import fastcrypto as crypto / except ImportError: import crypto`; expected `Imports["crypto"]=="fastcrypto"` — first binding in document order wins, per spec-reconciliation item 2), `_TypeChecking`, `_FunctionLocal`, `_RelativeSingleDot` (`pkg/mod.py`, `from . import helper` → `pkg`), `_RelativeDoubleDot` (`pkg/sub/mod.py`, `from ..other import Bar` → `pkg.other`) to `python_parser_test.go`. Run `go test ./internal/callgraph/ -run TestPythonParser_Import_ -count=1`; observe fail. Depends on: 4.5.
- [ ] 5.2 GREEN: make `extractImports` recurse into the whole tree (no pruning; `try`/`except`, `if`, function bodies all in scope) without overwriting an existing `Imports[name]` key (first-wins); implement `pythonRelativeModulePath(packagePath, prefix, dotted)` reading `import_from_statement`'s `module_name` field via `Node.FieldNameForChild` (not a scan for the first `dotted_name` child, which mis-binds `from .foo import Bar` per T0 finding 3). Files: `internal/callgraph/python_parser.go`. Re-run 5.1 green.
- [ ] 5.3 REFACTOR: confirm `internal/callgraph/python_parser_from_import_test.go` (import-map shape) still passes unchanged — recursive walk only adds keys.

## Phase 6: Row 15 — `__init__.py` re-export propagation (T6)

- [ ] 6.1 RED: create `internal/callgraph/python_parser_reexport_test.go` with `TestBuilder_InitPyReexport_SiblingResolution` (package layout `pkg/__init__.py` re-exporting `Cipher` from `pkg/mod.py`, `pkg/user.py` calling `Cipher().encrypt(data)` via `from pkg import Cipher`; expect callee FQN `pkg.mod.Cipher`) and `_NoInferredType` (internal alias `Cipher = SomeOtherThing` inside `mod.py` must NOT be followed). Run `go test ./internal/callgraph/ -run TestBuilder_InitPyReexport -count=1`; observe fail. Depends on: 5.3.
- [ ] 6.2 GREEN: add `FileAnalysis.PythonReExports map[string]string` (types.go); parser records it only when file basename is `__init__.py`, only from explicit relative `from .mod import Sym [as Alias]` (wildcard/absolute imports ignored). Files: `internal/callgraph/python_parser.go`, `internal/callgraph/types.go`.
- [ ] 6.3 GREEN: builder accumulates `PythonReExports` per package in `addAnalyses`; add `applyPythonReExports(graph, table)` run once at end of Phase 1, Python-only. Stitching gate (explicit): rewrite `Callee.Package` for a re-exported symbol ONLY WHEN the rewritten FQN exists as a declaration in the graph AND the original does not — never unconditionally, since KB YAMLs key on public re-export paths (`Crypto.Cipher.AES.new`) that an unconditional rewrite would destroy. File: `internal/callgraph/builder.go`. Re-run 6.1 green; re-run full `internal/scan` Python fixture suite to confirm no KB-path regression.

## Phase 7: Performance guard (T7)

- [ ] 7.1 Create `internal/callgraph/testdata/python_perf/generate_fixture.go`: generator emitting N synthetic Python modules exercising every binder form from T1-T3 (generated corpus itself not committed). Depends on: 6.3.
- [ ] 7.2 Create `internal/callgraph/python_perf_test.go` with `BenchmarkPythonParseDirectory_Bindings`, `t.Skip`ing when the generated fixture directory is absent, mirroring `testdata/inference_perf`/`TestPerformance_InferenceOverhead` convention.
- [ ] 7.3 Run `go generate`/the fixture generator locally, then `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -run ^$ -count=1` before and after this change's commits; confirm ≤10% added parse time. Record the before/after numbers in the PR description (not committed to the repo).

## Phase 8: Regression guard — existing Python test inventory (apply must not guess)

- [ ] 8.1 `TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis` (`internal/scan`) — expected: pass unchanged; that fixture has no direct calls at module/class-body level, so no `<module>`/`<clinit>` decl is added.
- [ ] 8.2 `TestPythonParser_ModuleCall_NoReceiverVar` — expected: pass unchanged; import check stays ahead of the locals check so a parameter never masks an import-name receiver.
- [ ] 8.3 `TestPythonParser_ParseFile`, `TestPythonParser_DunderMethodSkip` — expected: pass unchanged; both fixtures have zero module-level and zero class-body calls, so no synthetic decls appear in `analysis.Functions`.
- [ ] 8.4 `TestPythonParser_FunctionCallCarriesNonZeroColumns` — expected: pass, with wider coverage (now also iterates synthetic decls' calls through the same `parseCallExpr` column path).
- [ ] 8.5 `python_chain_integration_test.go` (4 tests) — expected: pass unchanged; chain walker untouched, parameters only add new identities, never remove existing ones.
- [ ] 8.6 `internal/scan/python_golden_fixtures_test.go`, `python_multilib_smoke_test.go`, `python_fidelity_deployed_rules_test.go` — expected: pass; entry-point/supporting-call counts may rise (intended precision gain from `<module>`/`<clinit>`) since none of these assert exact counts (`>= 1` or `t.Logf` only) — a rising count is NOT a regression here.
- [ ] 8.7 `internal/callgraph/python_parser_from_import_test.go`, `python_mro_dispatch_test.go`, `python_type_resolver_test.go` — expected: pass unchanged; recursive import walk only adds keys (first-wins), MRO/type resolver untouched. Run `go test ./internal/callgraph/ -run Python -count=1` and `go test ./internal/scan/ -count=1` to confirm the full inventory (6 callgraph files: 9+5+4+3+5+1 tests; 4 scan files: 12+8/1+1+N tests, per design baseline note) matches every row above; record real pass counts (baseline re-run was not possible during design — apply must run it for real).

## Phase 9: Final gates

- [ ] 9.1 `go test -race ./...` — full suite green.
- [ ] 9.2 `make lint` (golangci-lint v2.10.1) — clean.
- [ ] 9.3 `make coverage-check` — total coverage ≥ 80%.
- [ ] 9.4 `git diff --check` — no whitespace errors.
- [ ] 9.5 Confirm zero diff: `git diff --stat pkg/graphfrag/ internal/scan/supporting_calls.go internal/callgraph/contracts/` must be empty.
- [ ] 9.6 Add `CHANGELOG.md` `[Unreleased]` → `Fixed` entry: Python reachability/supporting-call precision now matches Java (parameters, non-assignment bindings, `self`/`cls` attributes, module/class-body synthetic entry points, robust/relative imports, `__init__.py` re-export resolution).
- [ ] 9.7 If any user-visible wording in `docs/user-guide/user-guide.html` describes Python reachability coverage, update it per `docs/user-guide/AGENTS.md`; otherwise mark N/A (this change is structural precision, not a new flag/command).
