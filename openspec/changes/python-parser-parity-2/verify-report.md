# Verification Report: python-parser-parity-2

**Mode**: full artifacts (proposal, specs, design, tasks, apply-progress all present)
**Verdict**: PASS WITH WARNINGS
**Verified**: 2026-08-27, HEAD `29ceef5` (branch `matiasdaloia/parser-parity-multi-language`, PR #310), 25 commits `73c9d28..HEAD`

## Completeness

83/83 tasks in tasks.md are checked. Working tree is clean at HEAD; `git diff --stat` empty.

## Build / Test / Coverage evidence (commands run for real, exit codes recorded)

| Command | Exit | Result |
|---|---|---|
| `go build ./...` | 0 | clean |
| `go test ./internal/callgraph/... -run 'Python\|Opengrep_Python' -count=1 -v` | 0 | 127 PASS, 0 FAIL, 0 SKIP |
| `go test ./internal/scan/ -count=1 -v` | 0 | 185 PASS, 0 FAIL, 12 SKIP (all pre-existing fidelity/wall-clock fixtures unavailable in sandbox, matches apply-progress) |
| `go test ./internal/callgraph/contracts/ -count=1 -v` | 0 | 123 PASS, 0 FAIL |
| `go test ./internal/scanner/semgrep/... -run TestOpengrep_PythonEndColConventionPinning -v` | 0 | PASS (opengrep binary present, real run, not skipped) |
| `go test -race ./...` | 0 | 31 packages ok, 0 FAIL |
| `go test -v -race -coverprofile=coverage.out ./...` | 0 | 0 FAIL (strict-TDD-mandated runner) |
| `make coverage-check` | 0 | PASS — 82.0% (14529/17725) >= 80% threshold |
| `make lint` | 2 | 2 issues (see Issues) |
| `git diff --check` (working tree, and `73c9d28..HEAD`) | 0 | clean both ways |

## Spec compliance matrix

### python-callgraph-parse-performance (4 requirements, 5 scenarios)

| Requirement/Scenario | Status | Evidence |
|---|---|---|
| Parse-time budget ≤1.10x mean, ≥8 reps one continuous run, mean+range reported | PASS | Independently re-measured (not just trusted from apply-progress): HEAD 8-rep run (regenerated 200-module corpus) mean **65.13ms** (range 64.31–65.91ms); `c6ee180` baseline 8-rep run in a temporary worktree, mean **68.78ms** (range 65.40–70.92ms). **Ratio = 0.947x** (budget ≤1.10x, PASS) |
| CI-enforceable non-skipping guard | PASS | `TestPythonParser_NodeVisitBudget` ran (not skipped) over 8 committed fixtures, all PASS |
| Allocation budget ≤1.15x B/op | PASS | HEAD mean B/op **20,799,741** vs baseline mean **19,266,783**. **Ratio = 1.080x** (budget ≤1.15x, PASS) — matches apply-progress's own final measurement (1.080x) almost exactly |
| Header-only return-type extraction | PASS | `pythonReturnTypeOf` reads only the `return_type` field node via `ChildByFieldName`; `parsePythonReturnType` (the old whole-body `Content(src)` call site) no longer exists anywhere in the package (grep confirms zero references) |
| Every row re-runs the guard | PASS | apply-progress's per-row perf table (11 re-runs across 3 batches) plus this independent final re-measurement |

### python-kdf-key-length-resolution (6 requirements, 9 scenarios)

| Requirement/Scenario | Status | Evidence |
|---|---|---|
| Keyword-argument-aware parameter-index mapping (3 scenarios incl. step 3b) | PASS | `TestResolvedKeyLength_Python_KeywordDklen`, `_PositionalLength`, `_PositionalNonConstantStaysAbsent` all read and confirmed as real behavioral assertions (independent expected values, not tautologies), all PASS |
| `argument_byte_length` derivation | PASS | `contracts.go` `validDerivation` whitelist + `resolveContractKeyBits`; `TestLoadEmbeddedPython_KDFKeySizeRoles` PASS |
| Integer literal / module-constant resolution | PASS | `TestResolvedKeyLength_Python_ModuleConstant`, `_NonConstantStaysUnknown` PASS |
| KB coverage for 19 listed APIs | PASS | `TestResolvedKeyLength_Python_EveryListedAPI` (19 subtests) PASS; independently verified all 19 keySize-bearing contracts across 6 changed YAML files have `parameter_types` length == `arity` (zero mismatches, python3/yaml cross-check) |
| Export schema unchanged | PASS | `CallgraphSchemaVersion == "6.13"`, `SchemaVersion == "graph-fragment-1.13"` confirmed via grep; zero diff on `pkg/graphfrag/` vs `c6ee180` |
| Java neutrality | PASS | `TestResolvedKeyLength_JavaUnchangedByKeywordPath` read and confirmed: asserts `nil` result for a Java call site under the new steps 3a/3b, independent of the code under test |

### python-callgraph-binding-resolution (9 requirements, ~20 scenarios)

| Requirement | Status | Evidence |
|---|---|---|
| Opengrep column pinning (row 6) | PASS | `TestOpengrep_PythonEndColConventionPinning` ran for real (binary present), PASS |
| Bounded dynamic dispatch (row 7) | PASS | `TestPythonParser_DynamicDispatch_GetattrLiteral/_ImportlibLiteral/_NonLiteralNoIdentity` all PASS; negative test read and confirmed: asserts exactly 1 call (`getattr` itself) and no fabricated identity |
| Decorator-aware receiver semantics (row 8) | PASS | 4 tests PASS incl. regression re-verify of pre-existing self-named-receiver tests |
| `super()` (row 9) | PASS | 3 tests PASS |
| `functools.partial`/`__call__` (row 11) | PASS | 2 tests PASS |
| Type-hint-fed resolution (row 13) | PASS | 7 tests PASS incl. `_UnresolvableNoType` (read and confirmed: asserts unchanged `Callee`/empty `ResolvedReceiverType` for an unresolvable annotation) |
| Dependency-mode stub/source resolution (row 14) | PASS | 6 unit tests + 1 real-package integration test (against installed `cryptography` 50.1, not skipped) all PASS; `_NoAnnotationsDegrades`/`_ProjectLocalUnaffected` read and confirmed as real negative-path assertions |
| Leading-underscore visibility (row 18) | PASS | 4 tests PASS |
| Argument provenance recursion (row 20) | PASS | 1 table test PASS |

## Invariants (all independently re-checked, not trusted from apply-progress)

| Invariant | Status | Evidence |
|---|---|---|
| Zero diff `pkg/graphfrag/` vs `c6ee180` | PASS | `git diff --stat c6ee180 HEAD -- pkg/graphfrag/` empty |
| Zero diff `internal/scan/supporting_calls.go` vs `c6ee180` | PASS | `git diff --stat c6ee180 HEAD -- internal/scan/supporting_calls.go` empty |
| `CallgraphSchemaVersion == "6.13"` | PASS | confirmed via grep |
| `SchemaVersion == "graph-fragment-1.13"` | PASS | confirmed via grep |
| No `internal/failure` import in `internal/callgraph` | PASS | `grep -rl "internal/failure" internal/callgraph/*.go` empty |
| `contracts.LoadEmbedded("python")` loads/merges without conflict | PASS | full `internal/callgraph/contracts/` suite green (123 PASS, 0 FAIL), including the pre-existing two-arity `argon2.PasswordHasher.<init>` entries (arity 0 and arity 4) — no HARD ERROR, confirmed a precedented pattern (Rust `Argon2Factory.create#0/#1`) |
| Each changed KB YAML has `schema_version: "2"` | PASS | all 6 changed files (`argon2-cffi`, `bcrypt`, `hashlib`, `pyca-cryptography`, `pycryptodome`, `pycryptodomex`) confirmed |
| `parameter_types` length == `arity` for every keySize contract | PASS | 19/19 contracts checked programmatically, 0 mismatches |

## Documented deviations — assessed

| Deviation | Verdict | Reasoning |
|---|---|---|
| Row 13: `FunctionDecl.ReturnType` NOT normalized through `pythonNormalizeAnnotation` | **Acceptable, correctly reasoned** | Read the design's own §11 argument and the implementation. Normalizing `ReturnType` in place would export `""` for e.g. `List[int]` — a real downstream export regression outside this row's bound. `propagatePythonAssignedVarTypes` reads the raw string instead, matching its own written contract. Spec's scenario ("Return annotation propagates to `AssignedVar`") only requires a bare-identifier case (`-> Cipher`), which is what the test (`TestPythonParser_TypeHint_ReturnAnnotation`) actually pins — no spec violation. |
| Row C: keyword→parameter mapping lands in `internal/scan/key_length.go`, not `mergeCallParameters` as the original spec text said | **Resolved, not outstanding** | design.md §11 requested 3 exact spec edits; the delivered `python-kdf-key-length-resolution/spec.md` **already reflects the edited text** (line 19: "`internal/scan/key_length.go` MUST parse...") and state.yaml records `reconciled_with_design: true`. No drift between design and the spec artifact actually on disk. |
| Row 14: `.pyi` preferred over same-stem `.py`, opposite of `builder.go`'s `keepExistingDecl` | **Acceptable, sound, well-scoped** | Confirmed via source read (`selectPythonDistFiles`): the precedence flip is local to this one dependency-signature-stub indexer and never touches `builder.go`'s own merge logic. The two code paths serve genuinely different purposes (a hand-authored stub's annotations are the more reliable *type* source; a real `.py` implementation is richer for the *main graph*). No cross-contamination risk — each path is invoked in a disjoint context. |
| Row 11 (11.11–11.13): batch-2 deferred argon2-cffi/bcrypt/pycryptodome(x) KB entries for "no network access" | **Resolved, not outstanding** | Batch 3 completed all 4 libraries with real primary-source verification (GitHub). Two real pre-existing arity bugs (`pycryptodome`/`pycryptodomex` `scrypt` and `HKDF.<init>`) were found and fixed as a side effect — a net-positive outcome, not a shortcut. |
| Two-arity `argon2.PasswordHasher.<init>` (arity 0 pre-existing + new arity 4) | **Acceptable, verified** | Confirmed via source read of `contracts.go`'s merge rules (same method+different arity is not a conflict class) and via the full contracts test suite passing with 0 failures (a HARD ERROR would have failed the suite, not silently passed). |

## TDD Compliance

| Check | Result |
|---|---|
| TDD Evidence reported | Present — apply-progress.md's "TDD Cycle Evidence" table (batch 1) plus per-row RED/GREEN narrative for batches 2–3 |
| RED confirmed (test files exist) | All named test files exist and were spot-verified by direct read |
| GREEN confirmed (tests pass now) | All test suites re-run in this verify pass, 0 failures |
| Triangulation | Adequate — most rows have 3–7 distinct test cases per behavior (e.g. row 13's 7 tests, row C's 19-entry table) |
| Assertion quality | ✅ No tautologies found (targeted grep across all changed `*_test.go` files, plus direct read of 6 negative-path tests spanning rows 7/13/14/C — every one asserts an independently-derived expected value, not a self-referential one) |

## Issues

### CRITICAL
None.

### WARNING

1. **`make lint`'s "0 new issues" claim is imprecise for one of the two findings.** apply-progress (task 14.2) states both lint findings are "confirmed pre-existing and unchanged since `e49e921`." That is true for the `goconst` finding (`builder.go:557`, `__init__` string — `builder.go` has zero diff in this entire change's range, confirmed present verbatim at true baseline `c6ee180`). It is **not** true for the `prealloc` finding (`python_parser_test.go:2251`, `var order []string`) — that line belongs to `TestPythonParser_CallOrderIsDocumentOrder`, a test this change **introduced** in its very first commit (`9aa415c`, task 0.6/T0.6). It does not exist at `c6ee180`. The comparison baseline `e49e921` apply-progress used is itself an intermediate commit *inside* this same change (end of batch 1), well after `9aa415c` — so "unchanged since `e49e921`" is true but doesn't mean "pre-existing relative to this change." Impact: cosmetic only (a `prealloc` suggestion on a test-only local slice, non-blocking, does not affect correctness or the lint gate's exit behavior differently than reported — `make lint` still exits 2 with 2 issues either way). Recommend correcting the characterization in apply-progress/PR notes rather than reopening the row.
2. **User-guide "Structure exports" panel states stale schema version numbers.** The exact paragraph this change edited (task 14.8, to add the Python KDF/dependency-mode sentence) still reads "schema `6.12`" and "`graph-fragment-1.12`", while the actual current constants (confirmed via grep) are `6.13` and `graph-fragment-1.13`. This drift predates this change (confirmed via `git log -p` — the "6.12"/"1.12" text was already present before `73c9d28`), so it is not something this change introduced or was scoped to fix, and it does not fail any of the three documented verification checks (HTML parser, prohibited-term grep, `git diff --check` — none of which check numeric accuracy). However, this change directly edited the same sentence and left the adjacent stale numbers untouched, so it's a missed opportunity to fix nearby drift rather than a regression. Recommend a follow-up doc-only fix.

### SUGGESTION
None beyond the two WARNINGs above.

## Final Verdict: **PASS WITH WARNINGS**

All 83 tasks complete, all spec requirements/scenarios have passing, non-trivial covering tests (independently re-run and spot-read, not merely trusted from the apply artifacts), all 5 invariants hold with zero diff, all 19 KDF KB contracts are internally consistent, the performance budget is independently re-measured and comfortably within budget (0.947x ns/op, 1.080x B/op — the B/op figure matches apply-progress's own final measurement almost exactly, cross-validating both independent measurements), all final gates pass for real (`go test -race ./...`, `make coverage-check`, `git diff --check`), commit hygiene is clean (25/25 conventional, 0 AI attribution), and CHANGELOG/user-guide are updated and pass their documented checks. The two WARNINGs are non-blocking: one is a mischaracterization in apply-progress's own lint accounting (the underlying lint finding itself is cosmetic and was already correctly reported as present), the other is pre-existing documentation drift this change did not introduce.

**Recommendation: proceed to `sdd-archive`.**

---

## Re-verification (phase-2 remediation batch, PR #310)

**Verified**: 2026-08-27, HEAD `4f4f72c` (branch `matiasdaloia/parser-parity-multi-language`, PR #310), 12 commits `ac06f87..4f4f72c` on top of the previously-verified `33361ee`.

**Trigger**: a second fresh-context review on PR #310 (`73c9d28..29ceef5`) found 13 new findings (G1–G13); this pass independently re-verifies each fix plus every gate this change owns.

**Verdict**: PASS WITH WARNINGS (both prior WARNINGs are now resolved; one new non-blocking WARNING on the G1 deviation's residual scope, carried at the same severity as the prior verify's accepted-scope finding — not a regression).

### G1–G13 fix verification (source read + named test, independently re-run)

| # | Fix | Named test | Result |
|---|---|---|---|
| G1 | `pythonSplitAssignedType` splits a dotted `ReturnType` into Package/Type at the last separator; a bare name resolves `Package` from the **declaring** decl (`callee.ID.Package`), never the caller's | `TestBuilder_PythonAssignedVarType_UsesDeclaringPackage`, `TestContractMatchesForCall_PythonAssignedVarType_DottedReturnSplits` | PASS — read `internal/callgraph/python_type_resolver.go`; confirmed the diff no longer writes `fn.ID.Package` (the calling decl) into `Callee.Package` |
| G2/G7 | KDF step 3b now gated to `ctx.kb.Ecosystem == "python"`; skips a keyword-shaped expression (`pythonKeywordArgumentPattern`) at the keySize position | `TestResolvedKeyLength_Python_KeywordAtDifferentPositionNeverReadPositionally`; `TestResolvedKeyLength_JavaUnchangedByKeywordPath` extended with 2 new `t.Run` subtests (declared-type mismatch, no-type-evidence) | PASS — read `internal/scan/key_length.go`; both the ecosystem gate and the keyword-shape skip are real code, not test-only |
| G3 | `pythonKeptDunderMethods` whitelists `__call__`/`__enter__`/`__exit__` in `parseFunctionDef`'s dunder-skip | `TestBuilder_PythonCallReachesIntoDunderCall` | PASS — non-tautological: builds a real graph, asserts `sha256Call.Callee.Package == "hashlib"` and that `wantID` appears in `graph.Callers[...]`, i.e. an edge that would dangle before the fix |
| G4 | Inner `super()`/`getattr(...)` call node suppressed when it composes an enclosing attribute/call expression | Extended `TestPythonParser_Super_NeverLocalSuper` and `TestPythonParser_DynamicDispatch_GetattrLiteral` with a loop asserting no `Name == "super"` / `pythonGetattrBuiltinName` call exists | PASS |
| G5 | Dynamic-import registration moved from deferred call-resolution time into `pythonWalkSideEffects`'s call case (single descent); relative literals (leading `.`) skipped | `TestPythonParser_DynamicDispatch_ImportlibLiteral_ModuleLevelVisibleInFunction`, `_SkipsRelativeLiteral` | PASS |
| G6 | `pythonArgumentSourceFor` skips the module-constant lookup when the identifier is bound in a non-module layer (param/local/comprehension); `recordPythonModuleConst` deletes a stale entry on a later non-integer rebind | `TestPythonParser_ArgProvenance_ModuleConstant_LocalShadowNotUsed`, `_ClearedOnNonIntegerRebind` | PASS |
| G8 | `make lint` findings fixed: `prealloc` (test slice preallocated), pre-existing `goconst` (`__init__` literal → shared `pythonInitMethodName`) | N/A (lint gate) | PASS — `make lint` 0 issues, re-verified with `golangci-lint cache clean` per apply-progress's documented gotcha |
| G9 | `resolvePythonSymbols` extracted into `pythonResolveSymbolTable`, filtered to `SymbolTypeRegular` | `TestPythonResolveSymbolTable_PrefersRegularOverAnonymous` | PASS |
| G10 | `typing.Optional[...]`/`typing.Union[...]` (a `subscript` node) normalized via `pythonNormalizeTypingSubscriptAnnotation`; `recordPythonAnnotatedAssignmentVarType` clears a stale annotation on later un-annotated reassignment | `TestPythonParser_TypeHint_TypingPrefixNormalization`, `_ClearedOnUnannotatedReassignment` | PASS |
| G11/G12 | CHANGELOG `[Unreleased]` merged to exactly one `### Added`/`### Fixed`; user guide schema numbers corrected to `6.13`/`graph-fragment-1.13` | N/A (doc gates) | PASS — verified directly (see below) |
| G13 | Stale `collectPythonFilePrepass` doc comment fixed; signature-cache directory now created lazily in `Put` with a `callgraph:`-prefixed error; CI-opengrep sub-finding investigated and found to be a false premise (`Dockerfile.test` already installs opengrep `v1.12.1` on PATH before `go test` runs in `test.yml`) | N/A (doc/infra) | PASS — confirmed `Dockerfile.test`/`test.yml` wiring independently; no workflow edit was needed |

All 14 named regression tests re-run individually and confirmed PASS in this pass (`internal/callgraph` and `internal/scan` full-package runs below already include them).

### G1 deviation — assessed

The review's literal ask ("never rewrite when the result does not exist as a declaration or KB type") was **not** implemented as a full existence gate; apply-progress documents this explicitly as deliberate, to avoid breaking the existing accepted approval test `TestPythonParser_TypeHint_ReturnAnnotation` (which intentionally resolves a bare return-type annotation with no class ever declared for it, matching design.md's row-13 bounded-inference scope).

Read `pythonSplitAssignedType` directly to construct the adversarial case: a factory function `def factory() -> Cipher: ...` declared in package `mypkg/utils`, where no class/type named `Cipher` is declared anywhere in the codebase and no KB contract exists for `mypkg/utils.Cipher`. After G1's fix, `x = factory(); x.encrypt()` still resolves `Callee.Package = "mypkg/utils"`, `Callee.Type = "Cipher"` — an FQN backed by neither a declaration nor a KB entry. This is a real gap relative to the review's literal wording, but it is **not new behavior introduced by G1**: it is the same bounded-inference behavior the previously-accepted `TestPythonParser_TypeHint_ReturnAnnotation` already pins for the direct-annotation case, now merely reachable one hop further through assigned-var propagation. It is inert downstream — an FQN matching no KB contract produces no finding, so it cannot fabricate a crypto detection, only a dangling/no-op resolved type. G1's actual, narrower fix correctly closes both literal fabrication patterns the review named (wrong-package attribution, un-split dotted text); the broader existence-gate question is a pre-existing, documented scope boundary, not a regression.

**Recommendation**: a follow-up test pinning this exact propagated (not direct-annotation) no-declaration/no-KB case would tighten the boundary further, but it is not required to unblock this change — flagged as WARNING, not CRITICAL.

### Full suite re-run (real counts, this pass)

| Command | Exit | Result |
|---|---|---|
| `go build ./...` | 0 | clean |
| `go test -v -race -coverprofile=coverage.out ./...` | 0 | 31 packages ok, 0 FAIL (strict-TDD runner) |
| `go test ./internal/callgraph/... -count=1 -v` | 0 | 504 PASS, 0 FAIL |
| `go test ./internal/scan/ -count=1 -v` | 0 | 187 PASS, 0 FAIL |
| `make lint` (after `golangci-lint cache clean`) | 0 | 0 issues |
| `make coverage-check` | 0 | PASS — 82.2% (14619/17791) >= 80% |
| `git diff --check` | 0 | clean |

### Perf re-measurement (independent, this pass)

8 reps, one continuous run, `BenchmarkPythonParseDirectory_Bindings`, 200-module corpus already present on disk:

| Stage | ns/op | B/op |
|---|---|---|
| HEAD `4f4f72c` (this pass) | 65,765,877 (65.77ms) | 20,816,001 (19.85 MiB) |
| `c6ee180` baseline (re-measured this pass, fresh temporary worktree, harness+corpus copied in, removed after) | 69,711,171 (69.71ms) | 19,276,976 (18.38 MiB) |
| Ratio | **0.943x** (budget ≤1.10x, PASS) | **1.080x** (budget ≤1.15x, PASS) |

The freshly re-measured `c6ee180` baseline (19,276,976 B/op) closely matches the recorded baseline (19.28 MB / ~19,280,000 bytes decimal) and apply-progress's own remediation-batch figure (66.7ms / 20.8MB, ratio 0.982x/1.080x) — cross-validating both this independent measurement and the apply-progress self-report. Both budgets hold comfortably.

### Gates independently re-verified

| Gate | Result |
|---|---|
| `go test -race ./...` | PASS |
| `make lint` | 0 issues |
| `make coverage-check` | PASS (82.2%) |
| `git diff --check` | clean |
| Zero diff `pkg/graphfrag/` vs `c6ee180` | PASS — `git diff c6ee180 HEAD --stat -- pkg/graphfrag/` empty |
| Zero diff `internal/scan/supporting_calls.go` vs `c6ee180` | PASS — empty diff |
| `CallgraphSchemaVersion == "6.13"` | PASS (`pkg/graphfrag/callgraph_export.go:33`) |
| `SchemaVersion == "graph-fragment-1.13"` | PASS (`pkg/graphfrag/export.go:46`) |
| No `internal/failure` import in `internal/callgraph` | PASS — grep empty |
| CHANGELOG `[Unreleased]` has exactly one `### Added`/`### Fixed` | PASS — confirmed by direct read; resolves the prior verify's WARNING #1 (the lint mischaracterization it described is also moot now that G8 brought `make lint` to 0 issues) |
| User guide states `6.13`/`graph-fragment-1.13` | PASS — resolves the prior verify's WARNING #2 (stale `6.12`/`1.12`) |
| `docs/user-guide/AGENTS.md` verification script (HTML parse, prohibited-term grep, `git diff --check`) | PASS — all three ran clean |
| Commit hygiene `33361ee..HEAD` (12 commits) | PASS — all conventional (`fix(python):`, `fix(scan):`, `chore(python):`, `docs:`, `docs(sdd):`), zero AI attribution (`git log --format=%B | grep -iE "co-authored-by|generated with|claude|anthropic"` → no matches) |

### Task completeness

83/84 task lines checked in `tasks.md`; the sole unchecked item, **14.11** ("Hand-off summary for the PR #310 comment (orchestrator posts it)"), is an orchestrator-owned, non-implementation cleanup task — carried unchanged from the first verify pass (no diff to `tasks.md` in `33361ee..HEAD`), not a regression. Its substance is already satisfied in practice: the PR itself carries two matiasdaloia comments (one per review round) documenting the exact fixes, commits, and gates. WARNING, not CRITICAL, per the decision-gate rule for cleanup tasks.

### Issues (this pass)

**CRITICAL**: None.

**WARNING**:
1. G1's fix narrows two literal fabrication patterns but does not add a full existence gate; a propagated (non-direct-annotation) bare return-type with no backing declaration or KB entry can still produce an inert, non-matching FQN. Documented, deliberate, inert downstream, consistent with the already-accepted `TestPythonParser_TypeHint_ReturnAnnotation` scope boundary — not a regression. Recommend a follow-up pinning test in a later batch.
2. Task 14.11 (orchestrator hand-off summary) remains unchecked; substance already covered by the PR's own review-response comments. Carried from the first verify pass, not new.

**SUGGESTION**: None.

### Final Verdict (re-verification): **PASS WITH WARNINGS**

All 13 G1–G13 findings are fixed with real code changes and real, non-tautological, independently-re-run passing tests. Both WARNINGs from the first verify pass (lint mischaracterization, stale user-guide schema numbers) are resolved. Perf is independently re-measured within budget (0.943x ns/op, 1.080x B/op). All final gates re-run for real and pass. Commit hygiene is clean. The two WARNINGs raised in this pass are non-blocking and do not represent regressions.

**Recommendation: proceed to `sdd-archive`.**
