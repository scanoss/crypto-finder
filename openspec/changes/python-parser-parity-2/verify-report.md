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
