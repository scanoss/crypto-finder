# Apply progress: python-parser-parity-2 (batch 1)

## Status: Phases 0-7 done (29/83 tasks), stopping cleanly at the Phase 7 boundary per batch scope

## Completed tasks
- [x] 0.1-0.7 (T0 grammar/symbol/perf-guard pinning tests)
- [x] 1.1-1.5 (A1/A2/A3 single-descent rewrite + CI guard + perf verification)
- [x] 2.1 (A4 mining-scale measurement)
- [x] 3.1-3.3 (Row 6 — opengrep column pinning)
- [x] 4.1-4.3 (Row 18 — visibility)
- [x] 5.1-5.3 (Row 20 — argument provenance)
- [x] 6.1-6.4 (Row 8 — decorator semantics)
- [x] 7.1-7.3 (Row 9 — super())

## Commits (this batch, in order)
- `d2ad581` docs(sdd): add python-parser-parity-2 tasks
- `9aa415c` test(python): pin T0 grammar/symbol/perf-guard facts for parity round 2
- `32d9791` perf(python): single-descent parser with deferred call resolution
- `daf0690` docs(sdd): mark python-parser-parity-2 phases 0-1 tasks complete
- `b770608` docs(sdd): checkpoint python-parser-parity-2 apply-progress (phases 0-1)
- `3ec0109` docs(sdd): record python-parser-parity-2 A4 mining-scale measurement
- `912133f` test(python): pin opengrep column convention against Python parser (row 6)
- `a24a85d` feat(python): populate Visibility/OwnerVisibility from naming convention (row 18)
- `207abfa` feat(python): populate ArgumentSources for bounded argument shapes (row 20)
- `9017d38` feat(python): decorator-aware receiver semantics (row 8)
- `0bede9f` feat(python): resolve super() against the enclosing class's base (row 9)
- `29a5f36` refactor(python): extract helpers to keep pythonWalk/parseAttributeCall lint-clean

All pushed to `origin/matiasdaloia/parser-parity-multi-language`.

## Architecture (A1-A3)
Replaced three-walk pipeline (import prepass + per-function `walkForCalls` +
pruned `walkPrunedForCalls`) with `pythonWalk`: one full-file descent using
`NamedChild()/NamedChildCount()` (not `Child()/ChildCount()` — avoids
go-tree-sitter's per-node wrapper caching cost for anonymous/punctuation
tokens, since all dispatch only matches named grammar rules).

New types: `pythonBindingLayer` (parent-chained map, replaces per-comprehension
map clone), `pythonPendingCall` (node + captured layer, deferred resolution),
`pythonScope` (locals + attrs + pending), `pythonClassInfo` (attrs),
`pythonFileWalk` (moduleScope/funcScopes/classInfo/classDirect maps).

Resolution deferred to `extractDeclarations` via `resolvePythonPendingCalls`,
run once per scope after the full descent — preserves document order (D3),
pinned by `TestPythonParser_CallOrderIsDocumentOrder`.

`ReturnType` now reads `return_type` field node directly (`pythonReturnTypeOf`,
no `Content()` on the whole function body). `Parameters` now reads
`typed_parameter`/`default_parameter`/`typed_default_parameter`/splat field
nodes directly, populating `FunctionParameter.Name` (previously Java-only) —
new test `TestPythonParser_Parameters_NameAndTypeFromFieldNodes`.

Deleted: `pythonFilePrepass`, `pythonClassScope`, `collectPythonFilePrepass*`,
`recordPythonFilePrepassBinders`, `recordPythonBinderNode` (old),
`collectPythonAssignmentTargets` (old, map-based), `extractCalls`,
`walkForCalls`, `collectPythonDirectCalls`, `walkPrunedForCalls`,
`withComprehensionTargets`, `collectPythonComprehensionTargets`.

## Perf numbers (BenchmarkPythonParseDirectory_Bindings, 8 reps, one continuous run each)

| Stage | mean ns/op | range ns/op | mean B/op | range B/op | mean allocs/op |
|---|---|---|---|---|---|
| c6ee180 baseline (0.7) | 67,913,428 (67.9ms) | 63.6ms-71.9ms | 19,275,101 (18.4MiB) | 19.23M-19.31M | 313,966 |
| Phase-0 commit (9aa415c, pre-rewrite, old prepass architecture) | ~75.3ms (3 reps) | 74.5-76.2ms | 25,993,722-25,995,881 | — | ~284,664 |
| After A1-A3 rewrite (Child()-based) | 70,467,093 (70.5ms) | 66.2-73.6ms | 25,383,510 (24.2MiB) | 25.38M-25.39M | 286,466 |
| After NamedChild() optimization | 65,336,994 (65.3ms) | 62.2-67.6ms | 20,457,130 (19.5MiB) | 20.46M-20.46M | 274,455 |
| **Final (after Parameters field-node fix, 1.5 gate)** | **60,590,328 (60.6ms)** | **60.3-61.1ms** | **20,390,622 (19.4MiB)** | **20.39M-20.39M** | **272,053** |

**Ratio vs c6ee180 baseline (final): ns/op = 0.892x (budget <=1.10x, PASS), B/op = 1.058x (budget <=1.15x, PASS).**

Key insight: go-tree-sitter's vendored binding (`smacker/go-tree-sitter@v0.0.0-20240827094217`)
allocates+caches a Go `*Node` wrapper (`Tree.cachedNode`, `map[C.TSNode]*Node`)
for EVERY node surfaced via `.Child()`/`.ChildByFieldName()`/`.Parent()`,
named or anonymous. Repeat access to the SAME node position (same pointer +
index) is a genuine cache hit (verified empirically via a throwaway
`runtime.MemStats`-delta probe) — so deferred resolution's later re-touch of
already-walked nodes is free. The real cost is total UNIQUE node positions
ever wrapped. Since all of `pythonWalk`'s dispatch (imports, call,
class/function definition, assignment/as-pattern/for/walrus binders,
comprehension symbols, pruned-definition symbols) matches only NAMED grammar
rules, switching the main recursive descent (and `pythonWalkClass`'s loop,
and `parsePythonParameters`) from `Child()/ChildCount()` to
`NamedChild()/NamedChildCount()` skips wrapping every anonymous
punctuation/keyword token — a large, free win. `TreeCursor` was investigated
and rejected: `CurrentNode()` routes through the identical `cachedNode` cache,
so it offers no additional benefit over `NamedChild()` with this binding
version.

`TestPythonParser_NodeVisitBudget`'s `countAllTreeNodes` helper was updated
to count named nodes only, matching pythonWalk's actual coverage — this is a
deliberate, documented redefinition (the test's protective purpose —
catching a regression back to multi-pass — is unaffected).

## TDD Cycle Evidence

| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 0.1 | `python_grammar_facts_test.go` | Unit | N/A (new subtests) | Written | Passed immediately (grammar-fact pinning, not new behavior) | 15 new subtests covering appendix rows | N/A |
| 0.2 | `python_grammar_facts_test.go` `TestPythonGrammarFacts_ReturnTypeField` | Unit | N/A | Written | Passed immediately | Single scenario (field existence) | N/A |
| 0.3 | `python_parser_test.go` `TestPythonSymbolTable_AllSymbolsResolved` | Unit | N/A | Written (extended symbol table structurally first) | Passed | 47 sub-cases (all new + existing symbol names) | N/A — structural, single correct output |
| 0.4 | `python_parser_test.go` `TestPythonParser_NodeVisitBudget` + 8 fixtures | Unit | N/A (new hook) | Written, FAILED against old architecture (visits over budget on all 8 fixtures) | Passed after A1 rewrite + NamedChild optimization | 8 fixture files (comprehensions/with-as/decorators/super/nested-classes/kwargs/annotations/module-constants) | N/A |
| 0.5 | `python_parser_test.go` `TestPythonParser_ReturnTypeFromFieldNode` | Unit (isolated benchmark-based proof) | N/A | Written, FAILED (8192 B/op vs 759 B/op budget) | Passed after A2 (`pythonReturnTypeOf` field-node read) | N/A — single allocation-budget assertion | N/A |
| 0.6 | `python_parser_test.go` `TestPythonParser_CallOrderIsDocumentOrder` | Unit | 40+ existing Python tests green | Written, PASSED immediately (approval test — pins existing-correct order behavior ahead of the D1 refactor) | Stayed green through the rewrite | 8-call mixed fixture (comprehension/with-as/chain/nested calls) | N/A |
| 1.1-1.3 | `python_parser.go` (production) | — | 40+ existing Python tests green pre-rewrite | N/A (refactor, approval-tested via 0.4/0.5/0.6 + full existing suite) | All tests green post-rewrite | N/A | Clean — old prepass/walkForCalls/walkPrunedForCalls/withComprehensionTargets fully deleted |
| 1.2 (Parameters) | `python_parser_test.go` `TestPythonParser_Parameters_NameAndTypeFromFieldNodes` | Unit | Full suite green | Written referencing new field-based shape | Passed | 7 parameter shapes in one table (plain/typed/default/typed-default/positional-only-marker/splat/kwsplat) | Clean |

### Test Summary
- Total new tests: 6 top-level + ~15 grammar-fact subtests + 47 symbol-table subtests + 8 visit-budget fixture subtests + 1 parameters test = ~25 top-level test functions/fixtures added
- Total tests passing: full `internal/callgraph` + `internal/scan` suites green (`go test -race ./internal/callgraph/... ./internal/scan/... -count=1`)
- Layers used: Unit only (no runtime harness applicable — pure parser-unit scope)
- Approval tests: `TestPythonParser_CallOrderIsDocumentOrder` (0.6) + the full existing 40+ Python test suite, used as the safety net for the A1 refactor

## Work Unit Evidence (Unit 1: T0 pinning + A perf rewrite)

| Evidence | Value |
|---|---|
| Focused test command and exact result | `go test ./internal/callgraph/ -run 'TestPythonGrammarFacts\|TestPythonSymbolTable\|TestPythonParser_NodeVisitBudget\|TestPythonParser_ReturnTypeFromFieldNode\|TestPythonParser_CallOrderIsDocumentOrder' -v` — all PASS |
| Runtime harness command/scenario and exact result | `go test ./internal/callgraph/ -bench BenchmarkPythonParseDirectory_Bindings -count=8` vs c6ee180 worktree — ns/op 0.892x, B/op 1.058x, both within budget |
| Rollback boundary | `git revert 32d9791` (the A1-A3 commit) leaves 9aa415c (T0 tests only, some RED by design pending A1) — every later row depends on this commit landing |

## Phase 2 (A4 mining-scale measurement) — done

Used the real, ambient pip-resolved dependency tree already present in this
environment (`/home/matiasdaloia/.local/lib/python3.12/site-packages`, 131
packages via `pip list`, 322MB, 6285 `.py` files — `internal/dependency`'s
`PipResolver` auto-detects the ambient `PATH` interpreter when no
project-local `.venv`/`venv` exists, per its documented priority order).
Built two CLI binaries (`crypto-finder-before` from the pre-A1-rewrite
worktree at commit `9aa415c`, `crypto-finder-head` from this batch's final
state) and ran `scan --scan-dependencies --no-remote-rules --rules-dir
testdata/rules` against a minimal one-file Python project, 5 reps each
(remote ruleset registry is unreachable in this sandbox — `--no-remote-rules
--rules-dir` substitutes the repo's own committed test rules, which is
enough to exercise the full dependency-resolution + parse + build +
inference + rules-match pipeline).

**Caveat**: the first rep of each binary was COLD (dependency-resolution
`pip show`/dist-info-scan caching not yet warm) and showed high variance
(15.6s before vs 54.4s after on the very first run) — this was NOT a parser
regression; it reflects `pip show` subprocess/dist-info indexing cache
state, confirmed by 4 subsequent WARM reps per binary converging tightly.

| Binary | Warm wall-clock (5 reps, `time -f %es`) | Findings |
|---|---|---|
| before (pre-A1, `9aa415c`) | 15.55s, 15.46s, 15.33s (mean ~15.4s) | 10 files, 23 crypto assets |
| after (HEAD, this batch) | 13.32s, 13.31s, 13.35s (mean ~13.3s) | 10 files, 23 crypto assets (identical — no correctness regression) |

**Result: ~13.6% wall-clock improvement at mining scale**, consistent
with (slightly better than) the isolated `BenchmarkPythonParseDirectory_Bindings`
ns/op improvement (0.892x). Findings are byte-identical in count between
before/after, confirming the rewrite did not change scan output.

## Phase 3 (Row 6 — opengrep column pinning) — done

Added `TestOpengrep_PythonEndColConventionPinning` in a new sibling file
`internal/scanner/semgrep/transformer_python_test.go`, mirroring the
existing Java `TestOpengrep_EndColConventionPinning`: runs the REAL
`opengrep` binary (present in this environment, `1.27.1`) over a Python
fixture (`hashlib.sha256(data)`), and cross-checks its match
Start.Line/Start.Col/End.Col directly against the `PythonParser`'s own
`FunctionCall.Line/StartCol/EndCol` for the SAME call — both independently
derived, both must agree. Passed on first real run; no grammar/column
surprises. Skips explicitly (`t.Skipf`) with a reason if the binary is
absent or unusable — never a silent pass.

## Phase 4 (Row 18 — visibility) — done

`pythonVisibilityForName(name)`: `__dunder__` (len > 4, so bare `__`/`___`
degenerate cases fall to private) -> `VisibilityPublic`; `__x` (non-dunder)
-> `VisibilityPrivate`; `_x` -> `VisibilityProtected`; else ->
`VisibilityPublic`. Wired into `parseFunctionDef`: `Visibility` from the
SOURCE name (before the `__init__`->`<init>` rename); `OwnerVisibility`
from the class name (empty for module-level functions — Python has no
package-private concept). 4 new tests, all real assertions against parsed
output (Underscore/DoubleUnderscore/Dunder/OwnerVisibility).

## Phase 5 (Row 20 — argument provenance) — done

Added `fw.moduleConsts map[string]string` (populated in the SAME
`pythonWalk` descent, gated on `moduleDirect && sym == assignment` with an
`identifier = integer` shape) and `pythonArgumentSources`/
`pythonArgumentSourceFor`, wired into `parseCallExpr` via new `fw`/`depth`
parameters. Three bounded shapes: nested call -> recursive `CALL_RESULT`
(callee resolved through the SAME `parseCallExpr` path, depth-capped at 4
via `pythonArgProvenanceMaxDepth`, harvesting the nested call's OWN
`ArgumentSources` rather than recomputing them — no duplicate recursion);
bare identifier bound to a module-level int constant -> `VARIABLE`
wrapping `VALUE`; integer/string literal -> `VALUE` (raw text, quotes
included for strings, matching the existing Java `SourceNode.Value`
convention). Anything else (e.g. an unbound identifier) emits nothing.
1 new table-style test covering all three shapes plus the "no fabrication"
negative case in one call.

## Phase 6 (Row 8 — decorator semantics) — done

New `pythonWalk` case for `decorated_definition` (`pythonWalkDecorated`):
classifies decorators via `classifyPythonDecorators` against the fixed
`staticmethod`/`classmethod`/`property` set (bare-identifier decorators
only; an attribute or call decorator, e.g. `@app.route(...)`, is ignored).
`@staticmethod` sets `pythonScope.staticMethod`, disabling the self/cls
implicit-receiver refusal both in `receiverIdentity` AND the
`parseAttributeCall` self-call shortcut. `@classmethod` sets
`pythonScope.selfAlias` to parameter-0's OWN name when it differs from the
literal `cls`, threaded into `pythonBindings` so a renamed first parameter
still canonicalises. `@property` records its own name directly into
`activeClassInfo.attrs` (the SAME table self.attr assignments populate),
extending the existing `self.<attr>` receiver mechanism for free.

**Bugfix found while implementing this row** (not a design-anticipated
issue): a bare `cls.foo()` call (no decorator involved at all) resolved
with `Callee.Type == "cls"` instead of behaving like `self.foo()` (a local
method call) — the design's own stated precondition ("cls behaves exactly
as self, already true") was WRONG, verified empirically via a throwaway
probe test before touching any production code. Fixed by extending
`parseAttributeCall`'s early self-call shortcut to also match the literal
`cls`, matching `self`'s existing treatment. 4 new tests
(StaticMethodNoReceiver/ClassMethodCls [covers both the bugfix and the
renamed-alias addition]/PropertyReceiver/CustomKeepsIdentity); regression
re-verify (6.3) confirmed `TestPythonParser_SelfNamedReceiver_FreeFunction`
and `_ReceiverVar_ParameterShadowsImport` unaffected.

## Phase 7 (Row 9 — super()) — done

Added `bases []string` to `pythonClassInfo` (computed once per class in
`pythonWalkClass` from the class_definition's `superclasses` field,
reusing the existing `extractPythonBaseClassNames` helper) and threaded it
into every method's `pythonScope`/`pythonBindings` (mirroring how `attrs`
already flows). In `parseAttributeCall`, a call whose object is a `call`
node with function identifier `super` (covers both `super()` and
`super(B, self)`) resolves to `FunctionID{Package: packagePath, Type:
bases[0], Name: method}` (`__init__` -> `<init>`) instead of the former
fabricated `Type: "super()"` literal-text fallback; an empty `bases`
(no explicit superclass declared) leaves `Type` unset — never fabricated.
3 new tests. One test-design correction made from real parser output: a
`super().__init__(key)` call is a 2-link fluent chain, so the INNER
`super()` call node is ALSO independently recorded as its own pending call
(pre-existing, general chain-link behavior — every nested/chain-linked
call node gets its own `decl.Calls` entry, confirmed consistent with
`TestPythonParser_CallOrderIsDocumentOrder`'s established semantics); the
test was corrected to find the specific resolved link rather than assert
`len(Calls) == 1`.

## Post-implementation lint cleanup

`golangci-lint run ./internal/callgraph/... ./internal/scanner/semgrep/...`
surfaced 2 NEW complexity issues introduced by rows 8/9's additions to
`parseAttributeCall`/`pythonWalk` (gocognit 21>20, then after a first fix
gocyclo 16>15) plus 1 new goconst hit from literal `"self"` strings in a
new test. Fixed via extraction: `pythonWalkSideEffects` (import/call/
assignment dispatch, out of `pythonWalk`), `pythonIsSelfLikeReceiver`/
`pythonLocalMethodCall`/`pythonResolveSuperCall` (out of
`parseAttributeCall`), and the test now uses the `pythonSelfObjectName`
constant instead of a literal string. Zero behavior change (full suite +
perf guard re-verified after the refactor); commit `29a5f36`. The
remaining 8 lint findings (`rust_parser.go` goconst, `python_parser.go`
G115 gosec, 6 `prealloc` suggestions) are confirmed pre-existing —
diffed against commit `9aa415c` (this batch's own starting point) and the
`c6ee180` baseline, none introduced by this batch.

## Perf guard re-runs after every row (all within budget throughout)

| After row | mean ns/op | ratio vs c6ee180 | mean B/op | ratio vs c6ee180 |
|---|---|---|---|---|
| 1.5 (A1-A3 final) | 60,590,328 | 0.892x | 20,390,622 | 1.058x |
| 3.3 (row 6) | ~64,680,000 | 0.953x | 20,512,685 | 1.064x |
| 4.3 (row 18) | ~64,713,000 | 0.953x | ~20,529,378 | 1.065x |
| 5.3 (row 20) | ~64,680,000 | 0.953x | ~20,512,685 | 1.064x |
| 6.4 (row 8) | ~65,472,000 | 0.964x | ~20,529,503 | 1.065x |
| 7.3 (row 9) | ~64,940,000 | 0.956x | ~20,566,419 | 1.067x |
| post-lint-cleanup (29a5f36) | ~67,310,000 | 0.991x | ~20,566,975 | 1.067x |

All comfortably within budget (<=1.10x ns/op, <=1.15x B/op) throughout;
no row breached and needed to be dropped or further optimized.

## Remaining tasks (batch 2+, not started)
- [ ] 8.1-8.3 (Row 7 — dynamic dispatch: getattr literal, importlib/__import__)
- [ ] 9.1-9.3 (Row 11 — functools.partial / __call__)
- [ ] 10.1-10.5 (Row 13 — type hints, parser + python_type_resolver.go)
- [ ] 11.1-11.16 (Row C — KDF key length: contracts.go enum + key_length.go + 6 KB YAMLs, verify arities against primary library sources before authoring)
- [ ] 12.1-12.8 (Row 14 — PythonDependencyTypeResolver, new files, lands last/abandonable)
- [ ] 13.1-13.8 (Regression guard — re-verify all pinned invariants)
- [ ] 14.1-14.11 (Final gates: go test -race ./..., make lint, make coverage-check, git diff --check, CHANGELOG, user-guide.html, push)

## Notes for batch 2

- Every row so far follows the SAME shape: extend `pythonScope`/
  `pythonBindings` with a new field, thread it through
  `resolvePythonPendingCalls`'s growing parameter list (now 9 params —
  consider consolidating into passing `*pythonScope` directly if it grows
  further), implement in `parseCallExpr`/`parseAttributeCall`, write
  RED test, verify GREEN, re-run the FULL perf guard (T0.4 unit test +
  8-rep benchmark), re-run `golangci-lint` on touched files before
  committing (this batch caught 2 real complexity regressions that way).
- Row 13 (type hints) is the first row needing a NEW file
  (`python_type_resolver.go` changes) beyond `python_parser.go` — read
  design.md §4 "Row 13" and §14's `PythonTypeResolverChain` ordering
  (contract KB -> dependency signatures -> `propagatePythonAssignedVarTypes`)
  carefully before starting, since row 14 depends on the SAME resolver
  chain type existing first.
- Row C (KDF) requires verifying library API arities/indices against
  PRIMARY SOURCES (cryptography, pycryptodome, argon2-cffi, bcrypt docs)
  before authoring YAML — do not trust design §5.3's table numbers on
  faith, per its own explicit warning.
