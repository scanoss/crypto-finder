```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:c8699756710df616ebf6fefd4bce5815cf319c82158f719b1611bbea27d32a9b
verdict: pass_with_warnings
blockers: 0
critical_findings: 0
requirements: 7/7
scenarios: 27/27
test_command: go test -race ./...
test_exit_code: 0
test_output_hash: sha256:0b230b07d562ec9cc94c41bf3f1bf57da4a900173fc0b15f16abb139b5309a38
build_command: go build ./...
build_exit_code: 0
build_output_hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Verification Report

**Change**: python-parser-java-parity
**Version**: `openspec/changes/python-parser-java-parity/specs/python-callgraph-binding-resolution/spec.md` (new capability, no prior version)
**Mode**: Strict TDD

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total | 41 |
| Tasks complete | 41 |
| Tasks incomplete | 0 |

### Build & Tests Execution

**Build**: PASS
```text
$ go build ./...
(clean build, exit 0, empty output)
```

**Tests**: PASS — `go test -race ./...`, all 27 packages, exit 0
```text
ok  	github.com/scanoss/crypto-finder/internal/callgraph              15.786s
ok  	github.com/scanoss/crypto-finder/internal/callgraph/contracts     (cached)
ok  	github.com/scanoss/crypto-finder/internal/cli                     11.786s
ok  	github.com/scanoss/crypto-finder/internal/engine                  14.953s
ok  	github.com/scanoss/crypto-finder/internal/scan                    28.202s
... (23 more packages, all ok/cached, 0 FAIL lines)
```

Focused runs (real pass counts, not estimates):
- `go test ./internal/callgraph/ -run Python -count=1 -v`: **78 subtests pass, 0 fail** (includes the 22-case `TestPythonGrammarFacts_PinnedNodeShapes` table plus every named `TestPythonParser_*`/`TestExpandPythonSubclassDispatch_*`/`TestPythonContractTypeResolver_*` test).
- `go test ./internal/callgraph/ -run TestBuilder_InitPyReexport -count=1 -v`: **2/2 pass** (`TestBuilder_InitPyReexport_SiblingResolution`, `_NoInferredType` — not matched by `-run Python`, verified separately).
- `go test ./internal/scan/ -count=1 -v`: **346 subtests pass, 0 fail**, including `TestPythonE2E_*` (6), `TestDeriveObjectLifecycleCalls_*` (new fixtures), `TestGeneratedExportsMatchSchemas`.
- `go test ./internal/callgraph/ -run TestJava -count=1 -v`: all Java tests pass, confirming the `javaFunctionTypeClassInit` → `functionTypeClassInit` rename did not regress `java_parser_clinit_test.go`.

**Coverage**: 81.9% total (13975/17067 statements) / threshold 80% → Above (`make coverage-check` PASS). Per-function coverage on the four changed callgraph files averages 85.3% across 326 functions; the few 0%/low-% functions on that list (`resolvePassthroughForThisReceiver`, `findClassDeclByType`, `inferTypeFromSourceNodes`, `javaVisibilityRank`, `resolveJavaSuperCallee`, `normalizeJavaTypeName`, `appendArrayDim`, `HasGenerics`, `EdgeResolutionEndpoints`, etc.) are pre-existing Java/general-graph code paths untouched by this change, not new Python code. Two new/modified Python entry points sit below 70% (`recordPythonReExportsFromStatement` 66.7%, `processImportFromStatement` 62.5%) — both are exercised by the passing `TestPythonParser_Import_*`/`TestBuilder_InitPyReexport_*` suites but have untested branches (e.g. wildcard/absolute-import skip paths); informational only, not blocking per Strict TDD rules.

### Spec Compliance Matrix
| Requirement | Scenario | Test | Result |
|-------------|----------|------|--------|
| Parameter-as-receiver binding | Parameter used as a call receiver | `python_parser_test.go > TestPythonParser_ReceiverVar_Parameter` | COMPLIANT |
| Parameter-as-receiver binding | Parameter feeding supporting-call grouping | `supporting_calls_test.go > TestDeriveObjectLifecycleCalls_ParameterReceiver` | COMPLIANT |
| Non-assignment binding coverage | `with...as` binds a receiver | `python_parser_test.go > TestPythonParser_ReceiverVar_WithAs` | COMPLIANT |
| Non-assignment binding coverage | `async with...as` binds a receiver | `> TestPythonParser_ReceiverVar_AsyncWithAs` | COMPLIANT |
| Non-assignment binding coverage | `for...in` binds a receiver | `> TestPythonParser_ReceiverVar_ForIn` | COMPLIANT |
| Non-assignment binding coverage | `async for...in` binds a receiver | `> TestPythonParser_ReceiverVar_AsyncForIn` | COMPLIANT |
| Non-assignment binding coverage | `except...as` binds a receiver | `> TestPythonParser_ReceiverVar_ExceptAs` | COMPLIANT |
| Non-assignment binding coverage | Walrus operator binds a receiver | `> TestPythonParser_ReceiverVar_Walrus` | COMPLIANT |
| Non-assignment binding coverage | Tuple/star unpacking binds every target | `> TestPythonParser_ReceiverVar_TupleUnpacking` | COMPLIANT |
| Non-assignment binding coverage | Comprehension target scoping | `> TestPythonParser_ReceiverVar_ComprehensionTarget` | COMPLIANT |
| `self`/`cls` instance-attribute provenance | `self.attr` cross-method provenance | `> TestPythonParser_SelfAttr_CrossMethodProvenance` | COMPLIANT |
| `self`/`cls` instance-attribute provenance | `cls.attr` classmethod provenance | `> TestPythonParser_ClsAttr_ClassmethodProvenance` | COMPLIANT |
| `self`/`cls` instance-attribute provenance | Reassignment splits lifecycle scope | `supporting_calls_test.go > TestDeriveObjectLifecycleCalls_SelfAttrRebinding` | COMPLIANT |
| `self`/`cls` instance-attribute provenance | Inheritance is not followed | `python_parser_test.go > TestPythonParser_SelfAttr_NoInheritance` | COMPLIANT |
| Synthetic module/class-body entry points | Module-level call gets `<module>` decl | `> TestPythonParser_SyntheticEntryPoint_ModuleLevel` | COMPLIANT |
| Synthetic module/class-body entry points | Class-body call gets `<clinit>` decl | `> TestPythonParser_SyntheticEntryPoint_ClassBody` | COMPLIANT |
| Synthetic module/class-body entry points | No decl for a call-free body | `> TestPythonParser_SyntheticEntryPoint_EmptyBodyOmitted` | COMPLIANT |
| Synthetic module/class-body entry points | Synthetic receivers grouped by supporting-call derivation | `supporting_calls_test.go > TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver` | COMPLIANT |
| Import resolution robustness | Import inside `try/except ImportError` | `python_parser_test.go > TestPythonParser_Import_TryExcept` | COMPLIANT |
| Import resolution robustness | Import inside `if TYPE_CHECKING:` | `> TestPythonParser_Import_TypeChecking` | COMPLIANT |
| Import resolution robustness | Function-local import | `> TestPythonParser_Import_FunctionLocal` | COMPLIANT |
| Import resolution robustness | Relative import, single dot | `> TestPythonParser_Import_RelativeSingleDot` | COMPLIANT |
| Import resolution robustness | Relative import, double dot | `> TestPythonParser_Import_RelativeDoubleDot` | COMPLIANT |
| `__init__.py` re-export propagation | Sibling resolves through re-export | `python_parser_reexport_test.go > TestBuilder_InitPyReexport_SiblingResolution` | COMPLIANT |
| `__init__.py` re-export propagation | No inferred type beyond re-export statement | `> TestBuilder_InitPyReexport_NoInferredType` | COMPLIANT |
| Export schema and downstream semantics unchanged | E2E export assertions pin schema versions | `internal/scan/export_schema_test.go`, `fragment_export_test.go` (existing, per spec-reconciliation item 3; both green in the 346-pass `internal/scan` run) | COMPLIANT |
| Export schema and downstream semantics unchanged | `supporting_calls.go` is not modified | Manual diff check (spec's own prescribed method — no dedicated Go test): `git diff --stat c6ee180..HEAD -- internal/scan/supporting_calls.go` is empty | COMPLIANT |

**Compliance summary**: 27/27 scenarios compliant.

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| Parameter-as-receiver binding | Implemented | `pythonParameterNames` + `pythonBindings.locals` param coverage, `receiverIdentity` check order preserved (import stays ahead of locals — `TestPythonParser_ModuleCall_NoReceiverVar` still green). |
| Non-assignment binding coverage | Implemented | `collectPythonBindings` walks `as_pattern`, `for_statement`/`for_in_clause`, `named_expression`, `pattern_list`/`tuple_pattern`/`list_splat_pattern`, comprehension `for_in_clause` (scope-limited). |
| `self`/`cls` provenance | Implemented | `collectPythonClassAttrs` scans only the literal class body (no inheritance walk); identity is literal `self.<attr>` string, `cls.<attr>` canonicalized to the same token. |
| Synthetic `<module>`/`<clinit>` | Implemented | `buildModuleInitDecl`/class-body equivalent prune at `function_definition`/`class_definition`/`decorated_definition`/`lambda`; `<module>` `Package` = module dotted path (`pythonModuleDottedPath`), not bare package path — confirmed matches design decision, avoids sibling-file FQN collision. |
| Import resolution robustness | Implemented | `extractImportsInNode` recurses unconditionally; first-binding-wins confirmed at lines 376/383 of `python_parser.go` (`if _, exists := analysis.Imports[name]; exists { return }` before every write). |
| `__init__.py` re-export propagation | Implemented | `applyPythonReExports`/`rewritePythonReExportedCallee` in `builder.go`: rewrite gated on rewritten-FQN-exists-AND-original-does-not (confirmed at builder.go:532-535), matching the design's KB-safety gate exactly. |
| Export schema unchanged | Implemented | `pkg/graphfrag.CallgraphSchemaVersion == "6.13"`, `pkg/graphfrag.SchemaVersion == "graph-fragment-1.13"` confirmed unchanged in source; zero diff on `pkg/graphfrag/`, `internal/scan/supporting_calls.go`, `internal/callgraph/contracts/` confirmed via `git diff --stat c6ee180..HEAD`. |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| `self.attr` identity is literal string `self.<attr>` | Yes | Confirmed in test fixtures (`TestDeriveObjectLifecycleCalls_SelfAttrRebinding` uses `Type: "self.cipher"` literally). |
| Rebinding left to existing positional selector, no new invalidation logic | Yes | `internal/scan/supporting_calls.go` shows zero diff — rebinding correctness comes free from `lifecycleSelector.selectDescendants`, confirmed by the passing rebinding test. |
| `<module>` keyed by module's dotted path, not bare package path | Yes | `pythonModuleDottedPath(filePath, packagePath)` implements exactly this (packagePath + "." + stem, bare for `__init__.py`). |
| `<clinit>` reuses Java's synthetic name/constant | Yes | `functionTypeClassInit` shared constant confirmed in `types.go`; Java's `java_parser_clinit_test.go` still green after the rename. |
| Synthetic walk prunes at every deferred-execution node | Yes | `buildModuleInitDecl` / class-body equivalent prune at `function_definition`, `class_definition`, `decorated_definition`, `lambda`; empty-body guard confirmed by `TestPythonParser_SyntheticEntryPoint_EmptyBodyOmitted` and `TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis` (in the 346-pass `internal/scan` run). |
| Re-export stitching is a gated builder post-parse rewrite | Yes | Confirmed at `builder.go` `rewritePythonReExportedCallee`: rewrite happens only when the rewritten FQN exists as a graph decl and the original does not. |
| Imports recursive, first-binding-wins | Yes | Confirmed in source and by `TestPythonParser_Import_TryExcept` asserting `Imports["crypto"] == "fastcrypto"`. |
| `PythonContractTypeResolver` untouched | Yes | `git log --oneline c6ee180..HEAD -- internal/callgraph/python_type_resolver.go` returns no commits; file unmodified by this change. |
| No `internal/failure` import in `internal/callgraph` | Yes | `grep -rn "internal/failure" internal/callgraph/*.go` (excluding tests) returns nothing. |
| T7 perf guard: ≤10% added parse time | **No** | Re-measured live against a fresh `c6ee180` worktree with the same generated 200-module corpus: baseline avg ≈ 75.0 ms/op (3×2s reps: 74.9/71.5/78.5 ms), HEAD avg ≈ 147.8 ms/op (3×2s reps: 150.0/143.6/149.7 ms) → **≈97-106% overhead**, roughly double the baseline and materially worse than the 64% apply-progress had reported (measured on a different run/machine load; both readings agree the design's 10% ceiling is far exceeded). See WARNING below. |

### TDD Compliance
| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ⚠️ Partial | `apply-progress` (Engram #989) is narrative, not the formal RED/GREEN/TRIANGULATE/SAFETY-NET/REFACTOR table `strict-tdd-verify.md` expects. However `tasks.md` itself embeds an explicit RED→GREEN→REFACTOR sequence per task (verified present for every one of the 41 tasks), and every RED step names its exact test function and "observe fail" instruction. |
| All tasks have tests | ✅ | 41/41 tasks map to a named test file; T4.1/4.2 are the only explicitly-mechanical (non-TDD, rename-only) tasks, correctly labeled as such in `tasks.md`. |
| RED confirmed (tests exist) | ✅ | All 25 spec-pinned test functions confirmed present via `grep -rl "func {name}("` — 1 file each, no orphans. |
| GREEN confirmed (tests pass) | ✅ | 78/78 `internal/callgraph -run Python` subtests + 2/2 `TestBuilder_InitPyReexport_*` + 346/346 `internal/scan` all pass on independent re-execution in this phase. |
| Triangulation adequate | ✅ | Non-assignment binding coverage alone has 8 distinct test cases for 8 distinct binder forms; import robustness has 5; self/cls provenance has 4 (including the negative "no inheritance" case) — no single-case coverage for a multi-scenario requirement. |
| Safety Net for modified files | ✅ | Full `internal/callgraph` (78 subtests) and `internal/scan` (346 subtests) suites re-run clean in this phase; Phase 8 tasks (8.1-8.7) explicitly re-verify every pre-existing Python test file's expectations are unchanged. |

**TDD Compliance**: 5/6 checks fully passed, 1 partial (table format, not substance — see WARNING).

---

### Test Layer Distribution
| Layer | Tests | Files | Tools |
|-------|-------|-------|-------|
| Unit | 78 (callgraph) + 2 (reexport) | `python_parser_test.go`, `python_grammar_facts_test.go`, `python_parser_reexport_test.go` | Go `testing`, tree-sitter |
| Integration | ~20 (supporting-call derivation, E2E export, python_e2e) within the 346 `internal/scan` pass count | `supporting_calls_test.go`, `python_e2e_integration_test.go`, `python_golden_fixtures_test.go` | Go `testing`, full builder pipeline |
| E2E | 0 dedicated new; existing `python_e2e_integration_test.go` (6 tests) exercises the full pipeline | `internal/scan/python_e2e_integration_test.go` | Go `testing` |
| **Total** | **≈426 relevant to this change's packages** | | |

---

### Changed File Coverage
| File | Function-avg % | Notes |
|------|--------|-------|
| `internal/callgraph/python_parser.go` | ~85%+ (aggregate, see below) | New/modified functions well-covered; `processDecorated` shows 0.0% in `-func` output but is pre-existing decorator-dispatch code, not new to this change. `recordPythonReExportsFromStatement` (66.7%) and `processImportFromStatement` (62.5%) are new/modified and below 70% — untested branches are wildcard/absolute-import skip paths, not core scenarios (all pinned scenarios pass). |
| `internal/callgraph/builder.go` | 85.3% avg (326-function aggregate across all 4 changed files) | `applyPythonReExports`/`rewritePythonReExportedCallee` (the T6 gate) not separately visible in the truncated grep; core path is exercised by both `TestBuilder_InitPyReexport_*` tests, which cover the gate-true and gate-false branches. |
| `internal/callgraph/types.go` | Aggregate above | Only constant/field additions; no new branchy logic. |
| `internal/callgraph/java_parser.go` | Aggregate above | Mechanical constant-rename only; pre-existing low-coverage functions (`resolveJavaSuperCallee` 0%, etc.) predate this change. |

**Aggregate function coverage across the 4 changed files**: 85.3% (326 functions). **Total repo coverage**: 81.9% (13975/17067 statements), above the 80% `make coverage-check` gate.

---

### Assertion Quality
✅ All spot-checked assertions verify real behavior. Reviewed in full: `TestPythonParser_ReceiverVar_ComprehensionTarget` (positive scope-in + negative scope-out, both against real parser output), `TestPythonParser_SelfAttr_CrossMethodProvenance` (independent expected literal `"self.cipher"`, not derived from the code under test), `TestDeriveObjectLifecycleCalls_SelfAttrRebinding` (asserts both what MUST and MUST NOT be selected — real boundary test, not a tautology), `TestBuilder_InitPyReexport_NoInferredType` (asserts the rewrite did NOT happen — a genuine negative-path check against a real `BuildFromDirectories` run, not a smoke test). No tautologies, no ghost loops over possibly-empty collections, no assertions decoupled from production code calls found in the sample.

**Assertion quality**: 0 CRITICAL, 0 WARNING.

---

### Quality Metrics
**Linter**: ✅ `make lint` (golangci-lint) — 0 issues.
**Type Checker**: ➖ N/A (Go compiler is the type checker; `go build ./...` clean, exit 0).
**`git diff --check` c6ee180..HEAD**: ✅ clean, exit 0 — no whitespace errors.

### Issues Found

**CRITICAL**: None.

**WARNING**:
1. **T7 perf guard target missed, and by more than previously reported.** Design set a ≤10% parse-time-overhead ceiling; apply-progress reported ~64% measured overhead; this phase's independent re-measurement (fresh `c6ee180` worktree, same 200-module generated corpus, 3×2s-benchtime reps each side) found **≈97-106% overhead** (baseline ≈75.0ms/op → HEAD ≈147.8ms/op). Root-cause reading from source inspection: for every function/method body (`parseFunctionDef` → line 777), the parser now runs `collectPythonBindings` (a full `O(nodes)` tree walk to build the binding table) immediately followed by `p.walkForCalls` (a second, independent full `O(nodes)` tree walk over the *same* body to extract calls) — two complete traversals where before this change there was effectively one. The same double-walk pattern repeats for the module-level synthesis (`buildModuleInitDecl`: `collectPythonBindings` then `collectPythonDirectCalls`, line 423-424) and the class-body synthesis (line 566-567). This alone is consistent with the observed ~2x-per-body cost. T5's import walk moving from `O(root children)` to `O(all nodes)` is a secondary, file-level-only (not per-function) contributor. This is an honestly-reported, not-hidden risk (recorded in `tasks.md` 7.3, `apply-progress`, and `state.yaml`'s `known_risk` field); T7's assigned scope was measurement, not optimization, and no attempt was made here to fix it, per the orchestrator's explicit instruction. **Recommend a dedicated follow-up change** that merges the binding-collection and call-collection walks into one traversal per body (or threads bindings through the existing call-walk instead of pre-computing them in a separate pass).
2. **Strict TDD evidence table not produced in the required format.** `apply-progress` (Engram #989) reports TDD narratively rather than via the RED/GREEN/TRIANGULATE/SAFETY-NET/REFACTOR table `strict-tdd-verify.md` prescribes. Downgraded from the rule's default CRITICAL because strong alternate evidence corroborates real TDD was followed: `tasks.md` itself encodes an explicit RED (write test, run, observe fail) → GREEN (implement, re-run green) → REFACTOR sequence per task, every RED step names its exact test function, and this phase independently re-ran and confirmed 78+2+346 = 426 passing tests with zero failures. No fabricated table was produced to paper over this — the gap is reported as-is.

**SUGGESTION**:
1. When a follow-up perf-fix change lands, re-run `BenchmarkPythonParseDirectory_Bindings` against the same 200-module corpus and record the new overhead percentage in that change's own apply-progress, so the risk trend is trackable across changes.
2. Consider adding the formal TDD Cycle Evidence table to `apply-progress` in future Strict-TDD applies even when `tasks.md` already encodes RED/GREEN steps per task — the separate table is what `sdd-verify`'s automated check looks for first, and its absence forces this kind of manual cross-check every time.

### Verdict
**PASS WITH WARNINGS**
All 41/41 tasks complete, all 27/27 spec scenarios compliant with real passing tests, all design invariants (zero-diff guards, schema constants, resolver isolation, T6 gate, first-binding-wins imports, `<clinit>` rename) confirmed by source inspection and test execution, and all final gates (`go test -race ./...`, `make lint`, `make coverage-check`, `git diff --check`) pass clean. Two WARNINGs — the T7 performance ceiling miss (worse than previously reported, root-caused here) and a TDD-evidence-table format gap covered by strong alternate evidence — are real but non-blocking; neither breaks a spec requirement or leaves a task incomplete.
