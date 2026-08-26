# Apply progress: python-parser-java-parity

Status: **all 41/41 tasks complete** (Phases 0-9). Change ready for `sdd-verify`.

## TDD Cycle Evidence (this batch — BATCH 2, resume)

| Task | RED | GREEN | REFACTOR |
|---|---|---|---|
| 5.1-5.3 | Confirmed pre-existing on resume: all 5 `TestPythonParser_Import_*` present, previously RED against the interrupted batch's uncommitted GREEN work | Confirmed green | 5.3 confirmed `python_parser_from_import_test.go` unchanged and passing |
| 6.1-6.3 | `_SiblingResolution` RED confirmed; `_NoInferredType` green-by-construction (no rewrite exists pre-implementation) | `applyPythonReExports`/`collectPythonReExports` implemented; both tests green | Full `internal/callgraph` + `internal/scan -run Python` suites green, zero KB-path regression |
| 7.1-7.3 | N/A — benchmark/generator, not a RED/GREEN unit | Generator + benchmark created, skip-when-absent confirmed | Real before/after measurement recorded (guard not met, reported as risk) |
| 9.2 | N/A — lint fix, not new behavior | `pythonNodeRelativeImport` const + `addAnalyses` split into `applyEcosystemAnalysisHooks`/`mergeAnalysisFunctions` | Re-ran full callgraph+scan suites green after refactor |

## Completed tasks (all phases, cumulative)

- Phase 0 (T0): 0.1-0.2 — grammar-facts pin — commit `a8d5365`
- Phase 1 (T1): 1.1-1.4 — parameter receivers — commit `22096df`
- Phase 2 (T2): 2.1-2.3 — non-assignment binders — commit `5723424`
- Phase 3 (T3): 3.1-3.4 — self/cls attribute provenance — commit `d2d70b9`
- Phase 4 (T4): 4.1-4.5 — synthetic `<module>`/`<clinit>` entry points (incl. out-of-scope `ast_anchor.go` fix, reported) — commit `6e0a9d4`
- Phase 5 (T5): 5.1-5.3 — nested/relative import resolution — commit `ffb9df2`
- Phase 6 (T6): 6.1-6.3 — `__init__.py` re-export stitching — commit `292b494`
- Phase 7 (T7): 7.1-7.3 — performance guard fixture + real measurement — commit `6a87776`
- Phase 8: 8.1-8.7 — regression guard, real pass counts recorded — commit `94f79e0`
- Phase 9: 9.1-9.7 — final gates (lint fixes, CHANGELOG, coverage) — commit `27eb966`

## Final gate results (all re-verified on final HEAD `27eb966`)

- `go test -v -race -coverprofile=coverage.out ./...` — exit 0, 0 `--- FAIL` lines, all packages `ok`.
- `make lint` (golangci-lint v2.10.1) — `0 issues.` (fixed 1 `gocognit` + 1 `goconst` finding introduced by this batch).
- `make coverage-check` — `Total coverage threshold (80%) satisfied: PASS` — `81.9% (13975/17067)`.
- `git diff --check` — clean.
- Zero-diff guard (`pkg/graphfrag/`, `internal/scan/supporting_calls.go`, `internal/callgraph/contracts/` vs merge-base `c6ee180`) — empty, confirmed.
- `CHANGELOG.md` `[Unreleased]` → `Fixed` entry added.
- `docs/user-guide/user-guide.html` — N/A, reviewed, no contradicted claims, file unchanged.

## Known risk (not blocking, reported honestly per instructions)

T7 (7.3): measured real parse-time overhead of this change is **~64%**, far above the design's 10% guard. Methodology: identical `BenchmarkPythonParseDirectory_Bindings` run against a second `git worktree` at `c6ee180` (pre-change baseline, this branch's merge-base with `main`) vs current HEAD, `-benchtime=5x -count=5` each. BEFORE avg ≈ 92.6ms/op, AFTER avg ≈ 151.7ms/op. Root cause (not fixed — outside T7's assigned scope of "measure and record"): T2's binding-table walk, T4's synthesis pruning walk, and T5's import walk (now O(all nodes) instead of O(root children)) each add a near-full-tree traversal per file/body; design underestimated the constant-factor growth. Corpus not committed (only generator + benchmark test are).

## Total change size

`git diff --shortstat c6ee180 HEAD` (full change, all phases): 21 files changed, 3336 insertions(+), 127 deletions(-). Exceeds the acquired attempt's 3000-line budget; authorized under `delivery_strategy=exception-ok` / `size:exception` per the orchestrator's explicit instruction for this run.

## Last commit SHA

`27eb966` — chore(python): fix lint findings and land final gates for parity change
