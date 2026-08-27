# Tasks: Python parser parity round 2 — throughput, deferred rows, KDF key length

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~3500–5500 (perf rewrite ~500-700; rows 6/18/20/8/9/7/11/13 ~600-900; row C KB+code ~500-700; row 14 new resolver+cache+wiring ~500-700; tests ~2000-2800; CHANGELOG/user-guide ~60) |
| 400-line budget risk | High |
| Chained PRs recommended | No |
| Suggested split | Single PR (`#310`, `matiasdaloia/parser-parity-multi-language`) — `size:exception` already accepted |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

### Suggested Work Units

All units land on the SAME PR #310 branch (no chaining — `size:exception` accepted).

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | T0 pinning + A perf rewrite (single descent, CI guard) | PR #310 | `go test ./internal/callgraph/ -run 'TestPythonGrammarFacts|TestPythonSymbolTable|TestPythonParser_NodeVisitBudget|TestPythonParser_ReturnTypeFromFieldNode|TestPythonParser_CallOrderIsDocumentOrder' -v` | `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -count=8` vs `c6ee180` worktree | `git revert` the A commit range; every later row depends on it, so this unit is the true rollback floor |
| 2 | Small rows 6, 18, 9 | PR #310 | `go test ./internal/callgraph/... ./internal/scanner/... -run 'TestOpengrep_PythonEndColConventionPinning|TestPythonParser_Visibility|TestPythonParser_Super' -v` | N/A — pure parser-unit scope, no external scan needed | independent revert per row's commit |
| 3 | Medium rows 20, 8, 7, 11, 13 | PR #310 | `go test ./internal/callgraph/ -run 'TestPythonParser_ArgProvenance|TestPythonParser_Decorator|TestPythonParser_Super|TestPythonParser_DynamicDispatch|TestPythonParser_Partial|TestPythonParser_Call_DunderCall|TestPythonParser_TypeHint' -v` | `go run ./cmd/crypto-finder scan --export-callgraph /tmp/py-cg.json internal/callgraph/testdata/python_stubs/` | independent revert per row's commit; row 13 resolver half reverts with `python_type_resolver.go` diff |
| 4 | Row C — KDF key length (contracts.go + key_length.go + 6 KB YAMLs) | PR #310 | `go test ./internal/callgraph/contracts/... ./internal/scan/... -run 'TestLoadEmbeddedPython_KDFKeySizeRoles|TestResolvedKeyLength_Python|TestResolvedKeyLength_JavaUnchangedByKeywordPath' -v` | `go run ./cmd/crypto-finder scan -o /tmp/py-kdf-findings.json <python fixture repo with PBKDF2/scrypt/HKDF calls>` | reverting C leaves A–B green (design §8) |
| 5 | Row 14 — dependency type resolver (last, abandonable) | PR #310 | `go test ./internal/callgraph/ -run TestPythonDepTypeResolver -v` | `go run ./cmd/crypto-finder scan --scan-dependencies -o /tmp/py-dep-findings.json <repo with a real pip-resolved dependency>` or explicit skip if no such tree is available | reverting 14 leaves A–C intact and green (design §8, D7) |
| 6 | Regression guard + final gates + docs | PR #310 | `go test -race ./...` | `make lint`, `make coverage-check` | N/A — verification-only unit, nothing to roll back |

## Phase 0: T0 — Grammar and perf pinning tests (foundation)

- [x] **0.1** RED T0.1: extend `TestPythonGrammarFacts_PinnedNodeShapes` (`internal/callgraph/python_grammar_facts_test.go`) with the section-10 appendix rows (decorators, `superclasses`, `super()`, `getattr`, `importlib`, params/annotations, `return_type`, annotated assignment, `keyword_argument`, module constants, nested call args, lambda, `await`).
  Evidence: `go test ./internal/callgraph/ -run TestPythonGrammarFacts_PinnedNodeShapes -v`; if real parser output disagrees, fix the test expectations, never the parser.
  Deps: none.
- [x] **0.2** RED T0.2: add `TestPythonGrammarFacts_ReturnTypeField` asserting `function_definition` field `return_type` exists with child `type`.
  Files: `internal/callgraph/python_grammar_facts_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonGrammarFacts_ReturnTypeField -v`. Deps: 0.1.
- [x] **0.3** RED T0.3: add `TestPythonSymbolTable_AllSymbolsResolved` — every entry added to `resolvePythonSymbols` (design §3.3 list) resolves to a non-zero `sitter.Symbol`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonSymbolTable_AllSymbolsResolved -v`. Deps: none.
- [x] **0.4** RED T0.4/A3: add `TestPythonParser_NodeVisitBudget` using the instance visit-counter hook (D4: `visits *int` field on `PythonParser`, nil in production) over a committed ≤40-file corpus at `internal/callgraph/testdata/python_visit_budget/` (one file per idiom: comprehensions, `with/as`, decorators, `super()`, nested classes, keyword args, annotations, module constants). Asserts `visits >= nodeCount` and `visits <= nodeCount + 8*callCount`.
  Files: `internal/callgraph/python_parser_test.go`, `internal/callgraph/testdata/python_visit_budget/*.py`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_NodeVisitBudget -v`. Deps: none.
- [x] **0.5** RED T0.5: add `TestPythonParser_ReturnTypeFromFieldNode` — 500+-line function body, `ReturnType` correct without materializing the body (`testing.AllocsPerRun` or an equivalent non-`Content()` proof).
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_ReturnTypeFromFieldNode -v`. Deps: none.
- [x] **0.6** RED T0.6: add `TestPythonParser_CallOrderIsDocumentOrder` proving `decl.Calls` order equals source order across comprehensions, nested defs, and chains under deferred resolution (D3, load-bearing for `internal/scan/supporting_calls.go` positional splitting).
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_CallOrderIsDocumentOrder -v`. Deps: none.
- [x] **0.7** T0.8 baseline measurement: `git worktree add /tmp/.../c6ee180-wt c6ee180` under the scratchpad dir; copy `BenchmarkPythonParseDirectory_Bindings` harness + corpus generator into the worktree; run `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -run ^$ -count=8` (≥8 reps, one continuous run); record combined mean AND min/max range in apply-progress notes; remove the worktree afterward.
  Files: none in-repo (temporary worktree only) + apply-progress note. Evidence: recorded mean+range text. Deps: none.

## Phase 1: A1/A2/A3 — Single-descent rewrite and CI guard

- [x] **1.1** GREEN: implement `pythonBindingLayer`, `pythonPendingCall`, `pythonScope`, `pythonFileWalk` (design §3.2–3.3); one `pythonWalk(root)` descent emitting pending calls per scope; delete `walkForCalls`, `walkPrunedForCalls`, `withComprehensionTargets`; extend `pythonSymbolTable`/`resolvePythonSymbols` with the full §3.3 symbol list.
  Files: `internal/callgraph/python_parser.go`. Evidence: `go test ./internal/callgraph/ -run 'TestPythonGrammarFacts|TestPythonSymbolTable_AllSymbolsResolved|TestPythonParser_NodeVisitBudget|TestPythonParser_CallOrderIsDocumentOrder' -v` all green. Deps: 0.1–0.6.
- [x] **1.2** GREEN: `ReturnType` from `return_type` field node only (delete the `node.Content(src)` call site on `function_definition`); `Parameters` from `typed_parameter`/`typed_default_parameter` `type` field nodes, populating `FunctionParameter.Name`.
  Files: `internal/callgraph/python_parser.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_ReturnTypeFromFieldNode -v`. Deps: 1.1.
- [x] **1.3** REFACTOR: cache `ChildCount()` everywhere on hot paths; ensure `pending` slices allocate lazily (nil until a scope's first call).
  Files: `internal/callgraph/python_parser.go`. Evidence: `go test ./internal/callgraph/... -run Python -v` green, no behavior change. Deps: 1.1–1.2.
- [x] **1.4** Run full existing Python suite to confirm no regression from the descent rewrite, especially D3's document-order invariant.
  Evidence: `go test ./internal/callgraph/... -v` and `go test ./internal/scan/... -run Python -v`. Deps: 1.1–1.3.
- [x] **1.5** Perf guard re-run: `go test ./internal/callgraph/ -run TestPythonParser_NodeVisitBudget -v` AND `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -run ^$ -count=8`; compare mean to the 0.7 baseline — must be ≤1.10x mean, ≤1.15x `B/op`. A breach is optimized here before any later row lands; never accepted.
  Deps: 0.7, 1.1–1.4.

## Phase 2: A4 — Mining-scale measurement

- [x] **2.1** Run `--scan-dependencies` before/after the A1–A3 rewrite on a real large pip-resolved dependency tree; record wall-clock in apply-progress. If no suitably large tree exists in this environment, record that gap explicitly rather than fabricating a number.
  Evidence: apply-progress note with before/after numbers or an explicit "no large tree available" note. Deps: 1.5.

## Phase 3: Row 6 — Opengrep column pinning (also satisfies T0.7)

- [x] **3.1** RED: `TestOpengrep_PythonEndColConventionPinning`, mirroring `TestOpengrep_EndColConventionPinning` (`internal/scanner/semgrep/transformer_test.go`), against a Python fixture with one crypto call.
  Files: `internal/scanner/semgrep/transformer_test.go` (or sibling Python test file), fixture under `internal/scanner/semgrep/testdata/`. Evidence: `go test ./internal/scanner/semgrep/... -run TestOpengrep_PythonEndColConventionPinning -v`. Deps: 1.5.
- [x] **3.2** GREEN: reuse the existing opengrep invocation helper; compare match columns to `StartCol`/`EndCol` (1-based, start inclusive, end exclusive); absent binary → `t.Skip` with an explicit `t.Logf` skip reason, never a silent pass.
  Deps: 3.1.
- [x] **3.3** Perf guard re-run (test-only row; expect zero parse-cost delta) — commands per 1.5.
  Deps: 3.2.

## Phase 4: Row 18 — Visibility

- [x] **4.1** RED: `TestPythonParser_Visibility_Underscore`, `_DoubleUnderscore`, `_Dunder`, `_OwnerVisibility`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_Visibility -v`. Deps: 1.5.
- [x] **4.2** GREEN: `pythonVisibilityForName(name)` (`__dunder__`→public, `__x` non-dunder→private, `_x`→protected, else public); set `FunctionDecl.Visibility` in `parseFunctionDef` using the source name (before `__init__`→`<init>`); set `OwnerVisibility` from the class name in `processClass`/`extractClassMethods` (empty for module-level functions).
  Files: `internal/callgraph/python_parser.go`. Deps: 4.1.
- [x] **4.3** Perf guard re-run — commands per 1.5.
  Deps: 4.2.

## Phase 5: Row 20 — Argument provenance recursion

- [x] **5.1** RED: `TestPythonParser_ArgProvenance_NestedConstructorCalls`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_ArgProvenance_NestedConstructorCalls -v`. Deps: 4.3.
- [x] **5.2** GREEN: populate `FunctionCall.ArgumentSources` for the three bounded shapes (nested `call` → `CALL_RESULT` recursive, depth ≤4; bare identifier bound to a module-level int constant → `VARIABLE`→`VALUE`; literal → `VALUE`); populate `pythonFileWalk.moduleConsts` in the same descent.
  Files: `internal/callgraph/python_parser.go`. Deps: 5.1.
- [x] **5.3** Perf guard re-run — commands per 1.5.
  Deps: 5.2.

## Phase 6: Row 8 — Decorator semantics

- [x] **6.1** RED: `TestPythonParser_Decorator_StaticMethodNoReceiver`, `_ClassMethodCls`, `_PropertyReceiver`, `_CustomKeepsIdentity`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_Decorator -v`. Deps: 5.3.
- [x] **6.2** GREEN: classify each `decorator` child in `extractDecoratedMethod`/`processDecorated` against `staticmethod`/`classmethod`/`property`; `@staticmethod` → parameter 0 is an ordinary local, `receiverIdentity` no longer special-cases it; `@classmethod` → parameter-0 marking so a renamed `cls` still canonicalises; `@property` → record the property name in the class scope's `attrs`; any other decorator leaves `FunctionID` unchanged.
  Files: `internal/callgraph/python_parser.go`. Deps: 6.1.
- [x] **6.3** Regression re-verify (design §6): `TestPythonParser_SelfNamedReceiver_FreeFunction`, `_ReceiverVar_ParameterShadowsImport` still pass unchanged.
  Evidence: `go test ./internal/callgraph/ -run 'TestPythonParser_SelfNamedReceiver_FreeFunction|TestPythonParser_ReceiverVar_ParameterShadowsImport' -v`. Deps: 6.2.
- [x] **6.4** Perf guard re-run — commands per 1.5.
  Deps: 6.3.

## Phase 7: Row 9 — `super()`

- [x] **7.1** RED: `TestPythonParser_Super_InitResolvesBase`, `_MethodResolvesBase`, `_NeverLocalSuper`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_Super -v`. Deps: 6.4.
- [x] **7.2** GREEN: add `bases []string` to `pythonScope` (populated in `processClass`); in `parseAttributeCall`, resolve `super()`/`super(B, self)` object nodes to `FunctionID{Package: packagePath, Type: OwnerBases[0], Name: method}`; empty `OwnerBases` → leave unresolved; `__init__`→`<init>` for the callee name.
  Files: `internal/callgraph/python_parser.go`. Deps: 7.1.
- [x] **7.3** Perf guard re-run — commands per 1.5.
  Deps: 7.2.

## Phase 8: Row 7 — Bounded dynamic dispatch

- [x] **8.1** RED: `TestPythonParser_DynamicDispatch_GetattrLiteral`, `_ImportlibLiteral`, `_NonLiteralNoIdentity`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_DynamicDispatch -v`. Deps: 7.3.
- [x] **8.2** GREEN: `getattr(obj, "encrypt")(data)` with a single-`string_content` literal argument 1 rewrites the outer call through the `obj.encrypt` receiver/callee path (non-literal → nothing new); `importlib.import_module("hashlib")`/`__import__("hashlib")` with a literal argument register the import via `recordPythonImportOnce` (first-binding-wins).
  Files: `internal/callgraph/python_parser.go`. Deps: 8.1.
- [x] **8.3** Perf guard re-run — commands per 1.5.
  Deps: 8.2.

## Phase 9: Row 11 — `functools.partial` / `__call__`

- [ ] **9.1** RED: `TestPythonParser_Partial_ResolvesTarget`, `TestPythonParser_Call_DunderCall`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run 'TestPythonParser_Partial_ResolvesTarget|TestPythonParser_Call_DunderCall' -v`. Deps: 8.3.
- [ ] **9.2** GREEN: `partials map[string]FunctionID` and `callables map[string]string` on `pythonScope`, both populated during deferred resolution; `classesWithDunderCall map[string]bool` collected in the same descent from `pythonFileWalk.classScopes`.
  Files: `internal/callgraph/python_parser.go`. Deps: 9.1.
- [ ] **9.3** Perf guard re-run — commands per 1.5.
  Deps: 9.2.

## Phase 10: Row 13 — Type hints

- [ ] **10.1** RED: `TestPythonParser_TypeHint_ParamAnnotation`, `_ReturnAnnotation`, `_OptionalUnionNormalization`, `_StringForwardRef`, `_AnnotatedAssignment`, `_TypeCheckingImport`, `_UnresolvableNoType`.
  Files: `internal/callgraph/python_parser_test.go`. Evidence: `go test ./internal/callgraph/ -run TestPythonParser_TypeHint -v`. Deps: 9.3.
- [ ] **10.2** GREEN parser half: `pythonNormalizeAnnotation(typeNode, src)` per the pinned shapes (`type>identifier`, `Optional[...]`/`Union[...]`, `X | None`, string forward-ref); populate `pythonScope.varTypes` from typed parameters, annotated assignment, and `FunctionDecl.ReturnType`; consult `varTypes[object]` in `parseAttributeCall` after the import check, before the local-name fallback.
  Files: `internal/callgraph/python_parser.go`. Deps: 10.1.
- [ ] **10.3** GREEN resolver half: `propagatePythonAssignedVarTypes(graph)` as the last step of the new `PythonTypeResolverChain.ResolveTypes`; per-decl ordered pass over `Calls` maintaining `var → type`, never crossing decls.
  Files: `internal/callgraph/python_type_resolver.go`. Deps: 10.2.
- [ ] **10.4** Regression re-verify (design §6): `TestPythonParser_ReceiverVar_ComprehensionTarget` still holds, both positive and negative sub-assertions (D2 layer-stack change).
  Evidence: `go test ./internal/callgraph/ -run TestPythonParser_ReceiverVar_ComprehensionTarget -v`. Deps: 10.3.
- [ ] **10.5** Perf guard re-run — commands per 1.5.
  Deps: 10.4.

## Phase 11: Row C — KDF key length

- [ ] **11.1** RED: add `DerivationArgumentByteLength` to `validDerivation` whitelist + error string; add (failing) `TestLoadEmbeddedPython_KDFKeySizeRoles`.
  Files: `internal/callgraph/contracts/contracts.go` (`:404`, `:547`), `internal/callgraph/contracts/contracts_test.go` (or Python-specific test file). Evidence: `go test ./internal/callgraph/contracts/... -run TestLoadEmbeddedPython_KDFKeySizeRoles -v`. Deps: 10.5.
- [ ] **11.2** GREEN: implement the `argument_byte_length` case in `resolveContractKeyBits` (`internal/scan/key_length.go:227`) — `bits = bytes*8`, reject `<=0` or `> maxKeyMaterialBytes`.
  Deps: 11.1.
- [ ] **11.3** RED: `TestResolvedKeyLength_Python_KeywordDklen`, `_ModuleConstant`, `_NonConstantStaysUnknown`.
  Files: `internal/scan/resolved_key_length_test.go`. Evidence: `go test ./internal/scan/... -run TestResolvedKeyLength_Python -v`. Deps: 11.2.
- [ ] **11.4** GREEN step 3a: keyword-name matching in `resolvedKeyLengthFromContract` (`internal/scan/key_length.go`, **not** `mergeCallParameters`) — parse the leading `identifier=` from `Arguments[i]` via `^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`, match group 1 against the contract role's `Name`, derive bits from `ResolvedValue` or group 2, bypass `contractParameterTypesMatch` for this step only.
  Files: `internal/scan/key_length.go`. Deps: 11.3.
- [ ] **11.5** RED: `TestResolvedKeyLength_Python_PositionalLength` (spec §"Positional call without call-site type evidence still resolves").
  Evidence: `go test ./internal/scan/... -run TestResolvedKeyLength_Python_PositionalLength -v`. Deps: 11.4.
- [ ] **11.6** GREEN step 3b: positional/type-evidence-absent path — contract declares `parameter_types`, no `SourceNode.DeclaredType`/empty `parameterTypes[index]`, value resolves to a constant → emit `constant` only; unresolved value → nil.
  Files: `internal/scan/key_length.go`. Deps: 11.5.
- [ ] **11.7** RED+GREEN: `TestResolvedKeyLength_JavaUnchangedByKeywordPath` (T0.10) plus re-run the full existing `internal/scan/resolved_key_length_test.go` incl. the `wantAbsent` case — must stay byte-identical.
  Evidence: `go test ./internal/scan/... -run 'TestResolvedKeyLength_JavaUnchangedByKeywordPath|TestResolvedKeyLength' -v`. Deps: 11.6.
- [ ] **11.8** Verify module-constant resolution end-to-end: `KEY_LEN = 32` feeds `moduleConsts` (5.2) → `ArgumentSources` VARIABLE→VALUE → existing `resolveSimpleExportParameterValue` with zero export-schema change.
  Evidence: covered by `TestResolvedKeyLength_Python_ModuleConstant` (11.3). Deps: 11.4, 5.2.
- [ ] **11.9** KB: `pyca-cryptography.yaml` — verify `PBKDF2HMAC`/`Scrypt`/`HKDF`/`HKDFExpand`/`ConcatKDFHash`/`X963KDF` `<init>` arity and the `length` parameter's declared index against the `cryptography` library's own source/docs before authoring; add `parameters[].contributes: keySize` (`argument_byte_length`) with both `index` and `name`, plus `parameter_types`.
  Files: `internal/callgraph/contracts/python/pyca-cryptography.yaml`. Evidence: `go test ./internal/callgraph/contracts/... -v`. Deps: 11.1.
- [ ] **11.10** KB (new file): `python/hashlib.yaml` — verify `hashlib.pbkdf2_hmac`/`hashlib.scrypt` signatures against CPython stdlib docs before authoring; schema-v2 header, `dklen` keySize entries, hierarchy edges to a root.
  Files: `internal/callgraph/contracts/python/hashlib.yaml`. Evidence: `go test ./internal/callgraph/contracts/... -v`. Deps: 11.1.
- [ ] **11.11** KB: `argon2-cffi.yaml` — verify `argon2.PasswordHasher.<init>` signature (`hash_len` position) against argon2-cffi docs before authoring; add keySize entry.
  Files: `internal/callgraph/contracts/python/argon2-cffi.yaml`. Evidence: `go test ./internal/callgraph/contracts/... -v`. Deps: 11.1.
- [ ] **11.12** KB: `bcrypt.yaml` — verify `bcrypt.kdf` signature (`desired_key_bytes` position) against py-bcrypt docs before authoring; add keySize entry.
  Files: `internal/callgraph/contracts/python/bcrypt.yaml`. Evidence: `go test ./internal/callgraph/contracts/... -v`. Deps: 11.1.
- [ ] **11.13** KB: `pycryptodome.yaml` + `pycryptodomex.yaml` — verify `Crypto.Protocol.KDF.PBKDF2`/`scrypt`/`HKDF` signatures against PyCryptodome docs before authoring; mirror keySize entries under both `Crypto.*` and `Cryptodome.*` namespaces.
  Files: `internal/callgraph/contracts/python/pycryptodome.yaml`, `internal/callgraph/contracts/python/pycryptodomex.yaml`. Evidence: `go test ./internal/callgraph/contracts/... -v`. Deps: 11.1.
- [ ] **11.14** RED+GREEN: `TestResolvedKeyLength_Python_EveryListedAPI` — table over the full design §5.3 API list, positional and keyword forms.
  Files: `internal/scan/resolved_key_length_test.go`. Evidence: `go test ./internal/scan/... -run TestResolvedKeyLength_Python_EveryListedAPI -v`. Deps: 11.9–11.13.
- [ ] **11.15** Verify export schema unchanged: `pkg/graphfrag.CallgraphSchemaVersion == "6.13"`, `SchemaVersion == "graph-fragment-1.13"`.
  Evidence: `go test ./internal/scan/... -run 'TestExportSchema|TestFragmentExport' -v`. Deps: 11.14.
- [ ] **11.16** Perf guard re-run — commands per 1.5.
  Deps: 11.15.

## Phase 12: Row 14 — `PythonDependencyTypeResolver` (lands last, abandonable)

- [ ] **12.1** RED: `TestPythonDepTypeResolver_StubReturnAnnotation`, `_SourceAnnotation`, `_ClassBases`, `_CachePerDistribution`, `_NoAnnotationsDegrades`, `_ProjectLocalUnaffected` against committed `.pyi`/`.py` fixtures.
  Files: `internal/callgraph/python_dependency_type_resolver_test.go`, `internal/callgraph/testdata/python_stubs/`. Evidence: `go test ./internal/callgraph/ -run TestPythonDepTypeResolver -v`. Deps: 11.16.
- [ ] **12.2** GREEN: new `PythonDependencyTypeResolver` — `pythonSignature`, worker pool `min(max(NumCPU/2,1), maxPythonDistributionWorkers=8)`, pruned tree-sitter descent reading only `return_type`/`superclasses` field nodes (`.pyi` preferred over same-stem `.py`), reusing `pythonNormalizeAnnotation` (10.2).
  Files: `internal/callgraph/python_dependency_type_resolver.go` (new). Deps: 12.1.
- [ ] **12.3** GREEN: new `PythonSignatureIndexCache` disk implementation mirroring `BytecodeIndexCache`; cache key `sanitize(ImportPath) + "@" + Version + pythonSignatureCacheSchemaVersion`.
  Files: `internal/callgraph/python_signature_cache.go` (new). Deps: 12.2.
- [ ] **12.4** GREEN: `PythonTypeResolverChain{contract, dependency}`; `ResolveTypes` order contract KB → dependency signatures → `propagatePythonAssignedVarTypes` (10.3); merge into `graph.TypeHierarchy`/`graph.ExternalMethodSignatures`; fill `FunctionDecl.ReturnType` only when currently empty; `sourceRoots` filtered to `Version != ""` (D8).
  Files: `internal/callgraph/python_dependency_type_resolver.go`. Deps: 12.2–12.3.
- [ ] **12.5** Wiring: `NewTypeResolverForEcosystem("python")` returns `NewPythonTypeResolverChain()`; add the Python branch mirroring the Java one, injecting `NewDiskPythonSignatureIndexCache()`.
  Files: `internal/callgraph/parser_registry.go`, `internal/cli/scan.go:331-340`. Evidence: `go test ./internal/callgraph/... ./internal/cli/... -v`. Deps: 12.4.
- [ ] **12.6** Confirm degradation rules: unreadable dir, absent `.pyi`, absent annotation, cache read/write error, unresolvable annotation name → debug log, resolve nothing, `nil` error; `StrictFailure()` not implemented (matches `PythonContractTypeResolver`).
  Evidence: covered by `_NoAnnotationsDegrades`/`_ProjectLocalUnaffected` (12.1). Deps: 12.5.
- [ ] **12.7** Integration task: if a real pip-resolved package is available in this environment, run `--scan-dependencies` against it and assert dependency-typed receivers appear; otherwise `t.Skip` with an explicit `t.Logf` reason (graceful skip, never a fabricated pass).
  Files: `internal/callgraph/python_dependency_type_resolver_test.go` (integration case, `testing.Short()`-skippable). Evidence: `go test ./internal/callgraph/... -run TestPythonDepTypeResolver_Integration -v` (skip logged if unavailable). Deps: 12.5.
- [ ] **12.8** Perf guard re-run (row 14's in-process parse cost must not regress; dependency indexing is a separate measurement, not part of `BenchmarkPythonParseDirectory_Bindings`) — commands per 1.5.
  Deps: 12.7.

## Phase 13: Regression guard (design §6)

- [ ] **13.1** `internal/callgraph/python_grammar_facts_test.go` `TestPythonGrammarFacts_PinnedNodeShapes` — confirm the extended table (0.1) matches real parser output.
  Evidence: `go test ./internal/callgraph/ -run TestPythonGrammarFacts_PinnedNodeShapes -v`.
- [ ] **13.2** `internal/callgraph/python_parser_test.go` `TestPythonParser_ParseFile` and any `FunctionDecl`-equality/`Parameters` assertions — update expectations to include `Visibility`/`OwnerVisibility`/`Parameters[].Name` now populated by rows 18 and A2.
  Evidence: `go test ./internal/callgraph/ -run TestPythonParser_ParseFile -v`.
- [ ] **13.3** `TestPythonParser_SelfNamedReceiver_FreeFunction`, `_ReceiverVar_ParameterShadowsImport` — re-verify unchanged (already covered by 6.3).
- [ ] **13.4** `TestPythonParser_ReceiverVar_ComprehensionTarget` — re-verify unchanged, positive and negative sub-assertions both hold (already covered by 10.4).
- [ ] **13.5** `internal/scan` `TestPythonE2E_*`, `TestPythonGolden_*`, `python_multilib_smoke_test.go`, `python_fidelity_deployed_rules_test.go` — re-run; counts may rise (all assertions `>=1`/`t.Logf`); confirm `crypto_entry_points` now carry `visibility`/`owner_visibility`.
  Evidence: `go test ./internal/scan/... -run 'TestPythonE2E|TestPythonGolden' -v` plus `go test ./internal/scan/... -v`.
- [ ] **13.6** `internal/scan/resolved_key_length_test.go` incl. the `wantAbsent` non-int-overload case — must stay green unchanged (already covered by 11.7).
- [ ] **13.7** `internal/callgraph/python_perf_test.go` — update doc comment only; benchmark body unchanged.
  Files: `internal/callgraph/python_perf_test.go`.
- [ ] **13.8** `internal/callgraph/contracts` loader tests — add `argument_byte_length` to any exhaustive-derivation assertion; update expected error-message text.
  Evidence: `go test ./internal/callgraph/contracts/... -v`.

## Phase 14: Final gates, docs, delivery

- [ ] **14.1** `go test -race ./...` — exit 0.
- [ ] **14.2** `make lint` — 0 issues.
- [ ] **14.3** `make coverage-check` — ≥80%.
- [ ] **14.4** `git diff --check` — clean.
- [ ] **14.5** Verify zero diff: `git diff --stat -- pkg/graphfrag/ internal/scan/supporting_calls.go` — must be empty.
- [ ] **14.6** Verify schema constants unchanged: `pkg/graphfrag.CallgraphSchemaVersion == "6.13"`, `SchemaVersion == "graph-fragment-1.13"` (existing schema tests green, per 11.15).
- [ ] **14.7** `CHANGELOG.md` — add `[Unreleased]` bullets: `Added` (Python KDF `resolved_key_length` coverage, dependency-mode Python type resolution), `Changed` (Python parser throughput rewrite, `visibility`/`owner_visibility` now populated on Python entries), consumer-facing wording only.
- [ ] **14.8** `docs/user-guide/user-guide.html` — update per `docs/user-guide/AGENTS.md` for user-visible behavior (Python `visibility`/`owner_visibility`, KDF `resolved_key_length` coverage, dependency-mode type resolution); verify with an HTML parser, prohibited-term grep, `git diff --check`, and a local HTTP server/browser check.
- [ ] **14.9** Commit each phase incrementally with conventional commit messages, no AI attribution (matches the existing `T0`–`T4` commit series style already on this branch).
- [ ] **14.10** Push to `origin matiasdaloia/parser-parity-multi-language`.
- [ ] **14.11** Hand-off summary for the PR #310 comment (orchestrator posts it): phase 2 delivered A(perf) + rows 6/7/8/9/11/13/14/18/20 + C(KDF); overhead vs `c6ee180` baseline measured at the value recorded in 0.7/1.5; test count added; KB coverage table (design §5.3); links to `CHANGELOG.md`/user-guide diffs.
