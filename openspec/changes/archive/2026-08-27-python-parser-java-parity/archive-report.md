# Archive Report: python-parser-java-parity

**Change**: Python parser parity with Java (callgraph binding resolution)
**Status**: ARCHIVED — Complete and ready for delivery
**Archived Date**: 2026-08-27
**Branch**: `matiasdaloia/parser-parity-multi-language`
**Base**: `main` (merge-base `c6ee180`)

## Executive Summary

The `python-parser-java-parity` change has been successfully completed, verified, and archived. All 7 structural requirements for Python callgraph binding resolution (parameter receivers, non-assignment bindings, `self`/`cls` attribute provenance, synthetic module/class entry points, robust import resolution, and `__init__.py` re-export propagation) are implemented with comprehensive test coverage. The change reaches structural parity with Java's reachability precision while maintaining backward compatibility in export schemas, supporting-call semantics, and KB paths. All tasks (41/41) are complete; all verifications pass with no critical findings. A documented performance overhead (~20% parse-time, vs design target of 10%) is carried forward as a follow-up optimization, not a blocker.

## Final-State Authority & Change Completion

### Commit History
- **Batch 1 (T0–T7 implementation)**: `a8d5365..022b94c` — 7 commits implementing Phases 0–7 (grammar pin, receiver binding, non-assignment bindings, attribute provenance, synthetic entry points, import robustness, re-export stitching, perf benchmarking).
- **Batch 2 (review remediation F1–F9 + goconst fix)**: `022b94c..236dfdd` — 9 commits addressing review findings (complexity refactors, test fixture improvements, complexity/linting fixes).
- **Total in branch**: 24 commits from base merge-base `c6ee180`.

### Native Review Authority
**PR #310**: https://github.com/scanoss/crypto-finder/pull/310 (OPEN, awaiting human review)
- Status: Branch ready for merge; no `reviewGate` gate applied yet (review authority does not gate archive).
- 2 HIGH / 3 MEDIUM / 4 LOW findings from fresh-context review → ALL FIXED on branch with test-first negative-path tests (documented in PR comments).
- Re-verification: pass-with-warnings, 7/7 requirements, 29/29 scenarios green.

### Task Completion Gate
**Status**: PASS ✓
All 41 implementation tasks in `tasks.md` marked complete [x]:
- Phases 0–7 (grammar pin, receivers, bindings, attribute provenance, synthetic entry points, imports, re-exports, perf guard): all TDD cycles (RED/GREEN/REFACTOR) completed.
- Phase 8 (regression guard on existing Python inventory): all 26 sub-tasks verified; no breakage.
- Phase 9 (final gates): all 7 gates (full test suite, linting, coverage, whitespace, schema freeze, changelog, user-guide review) confirmed green.

### Verification & Reverification
**Initial Verify** (state.yaml:verify):
- Verdict: `pass_with_warnings`
- Requirements: 7/7 compliant
- Scenarios: 27/27 green
- Critical findings: 0
- Warnings: 2
- Test exit code: 0 (full suite green)
- Coverage: 81.9% (≥80% threshold)

**Reverify** (state.yaml:verify.reverify, after remediation batch):
- Verdict: `pass_with_warnings`
- Requirements: 7/7 compliant
- Scenarios: 29/29 green (2 additional scenarios added during F5 remediation)
- Critical findings: 0
- Warnings: 3 (documented as non-blocking improvements)
- Head commit: 6d7ba35
- Verified on: 2026-08-27

### Engram Artifacts Persisted (Hybrid Mode)
All observations recorded in Engram for traceability (topic_key prefix `sdd/python-parser-java-parity/`):
- **Proposal** (#983): Python parser parity intent, requirements overview.
- **Spec** (#984, revised): 7 requirements, 29 scenarios, all ADDED (Python binding resolution is a new capability).
- **Design** (#985): Implementation strategy, cross-file coordination (builder stitching), design decisions, known deviations.
- **Tasks** (#988): Phase breakdown (T0–T7), phase gates, workload forecast (1800–2400 changed lines, high risk, exception-ok strategy).
- **Verify-Report** (#990): Initial verification audit with pass-with-warnings verdict.
- **Apply-Progress** (#989): Batch apply + remediation progress, commit history, known risks.
- **Archive-Report** (this document): Final-state summary for archive closure.

### Explicit Final-State Facts (Launch Prompt)
These override stale claims in intermediate snapshots:

1. **PR Review**: https://github.com/scanoss/crypto-finder/pull/310 OPEN, not merged. Branch `matiasdaloia/parser-parity-multi-language` → `main`.

2. **Commits**: `a8d5365..236dfdd` (24 commits) — T0–T9 tasks (12) + remediation batch F1–F9 + goconst fix (10) + SDD artifacts + .gitignore (2).

3. **Fresh-Context Review Findings**: 2 HIGH / 3 MEDIUM / 4 LOW → ALL FIXED on branch with test-first negative-path tests.

4. **Re-Verification**: pass-with-warnings, 7/7 requirements, **29/29 scenarios green** (Engram spec artifact was resynced from disk after F5).

5. **Final Gates at HEAD**:
   - `go test -race ./...` ✓ ok
   - `make lint` ✓ 0 issues
   - Coverage ✓ 82.0% (≥80%)
   - `git diff --check` ✓ clean
   - Zero diff: `pkg/graphfrag/`, `internal/scan/supporting_calls.go`, `internal/callgraph/contracts/` ✓ unchanged
   - Export schema 6.13 / graph-fragment-1.13 ✓ unchanged

6. **Performance**: Python parse overhead on 200-module synthetic corpus ≈14–20% over merge-base `c6ee180` (was ~100% before remediation). Above design target (10%), within hard cap (20%). Recorded as follow-up candidate `python-parser-perf`, not a blocker.

7. **Ledger**: Attempt 1 (apply) passed at 3481 changed lines > 3000 budget; maintainer reset approved by user 2026-08-27; attempt 2 (PR #310 review-fix) settled `complete`.

## Specification Status

### Main Spec Created
**File**: `openspec/specs/python-callgraph-binding-resolution/spec.md`
**Action**: Mechanically copied from delta spec (shell `cp`, verified by `diff -r`)
**Structure**: 7 Requirements × 29 Scenarios, all ADDED (new capability)

**Requirements Archived**:
1. Parameter-as-receiver binding (2 scenarios)
2. Non-assignment binding coverage (8 scenarios: with/async-with/for/async-for/except/walrus/tuple/comprehension)
3. `self`/`cls` instance-attribute provenance (4 scenarios: cross-method, classmethod, reassignment, no-inheritance)
4. Synthetic module-level and class-body entry points (4 scenarios: module-level call, class-body call, empty-body omitted, supporting-call grouping)
5. Import resolution robustness (5 scenarios: try/except, if TYPE_CHECKING, function-local, relative single-dot, relative double-dot)
6. `__init__.py` re-export propagation (4 scenarios: sub-package resolution, flat-layout already-resolved, no-inferred-type, no-rewrite-for-KB-keyed-dependency)
7. Export schema and downstream semantics unchanged (1 scenario: schema versions pinned, supporting_calls.go unchanged)

**Conformance**: All 7 requirements met per verify-report matrix (COMPLIANT status on all 29 scenarios).

## Implementation Artifact Checklist

- [x] Proposal artifact (openspec/changes/{name}/proposal.md + Engram #983)
- [x] Specification artifact (openspec/changes/{name}/specs/python-callgraph-binding-resolution/spec.md + Engram #984)
- [x] Design artifact (openspec/changes/{name}/design.md + Engram #985)
- [x] Tasks artifact (openspec/changes/{name}/tasks.md + Engram #988)
- [x] Apply-progress artifact (openspec/changes/{name}/apply-progress.md + Engram #989)
- [x] Verify-report artifact (openspec/changes/{name}/verify-report.md + Engram #990)
- [x] Implementation changes (24 commits across callgraph, builder, types, tests)
- [x] Main spec synced to source of truth (openspec/specs/python-callgraph-binding-resolution/spec.md)

## Known Risks & Caveats

### Performance Overhead (Accepted, Follow-Up Candidate)
**Finding**: Phase 7 (perf guard) measured ~64% parse-time overhead pre-remediation, reduced to ~14–20% post-remediation.
- **Design Target**: ≤10% overhead.
- **Measured (current HEAD)**: ~19.9% combined 10-rep, within ≤20% hard cap.
- **Root Cause**: T1 added full binding table walk; T2 added second per-function-body walk; T4 added third pruned walk per module/class; T5 changed imports from O(root-children) to full O(all-nodes) recursive walk. These 3–4 constant-factor traversals per file exceed the 10% design assumption.
- **Status**: Recorded as follow-up candidate `python-parser-perf` for optimization in a future batch, not a blocker for archive.
- **Gate Passed**: Hard cap (≤20%) met; no verification critical finding; all scenarios green.

### Scope Deviation (Fixed, Not Silent)
**Finding (Phase 4, ast_anchor.go)**: Python's new `<module>`/`<clinit>` synthetic entry points revealed missing `isFunctionContainer` entries in `ast_anchor.go` (used by `namedASTPath` to bound call AST anchor paths). This caused occurrence keys to be silently dropped for Python module-level/class-body findings.
- **Fix**: Added 2-token symmetric entry (`module`, `class_definition`) to existing switch, alongside Java's existing `static_initializer`/`field_declaration`.
- **Authority**: Outside the originally authorized task file list, but leaving it unfixed would ship a net-negative regression for occurrence-key stability.
- **Verification**: Full `go test $(go list ./... | grep -v internal/engine)` confirms zero cross-ecosystem regressions; full `internal/callgraph` + `internal/scan` suites green.
- **Gate Passed**: No critical findings; all tests pass; the fix is minimal, symmetric, and proven safe.

### Deferred Exploration Rows (Logged, Out of Scope)
The design document logged 10 deferred rows for future changes (rows 6–9, 11, 13, 14, 17, 18, 20):
- Row 6: Opengrep column-pinning test for Python
- Row 7: Dynamic getattr/importlib dispatch
- Rows 8–9: Decorators, super()
- Row 11: functools.partial/__call__
- Row 13: Type hints
- Row 14: Stub-based dependency type resolver
- Row 17: Async grammar (verified fine)
- Row 18: Visibility
- Row 20: Constructor-arg provenance

These remain on the exploration roadmap for future parity work. None are required for this change's completion.

### Engram Spec Artifact Resync (Administrative)
**Finding**: After F5 scenario additions (27 → 29 scenarios), the Engram spec artifact (id #984) was stale vs the on-disk spec.md file. Resynced per state.yaml:verify.reverify note.
- **Status**: Resolved; both Engram and disk now in sync at 29 scenarios.

## Delivery Strategy & Review Authority

- **Delivery Strategy**: `exception-ok` (accepted by user 2026-08-27).
- **Review Budget**: Unlimited (per config.yaml).
- **Strict TDD**: Enabled.
- **Review Authority**: Native PR #310 governs merge readiness; archive does not gate on review (no `reviewGate` result yet; when present, a `result: allow` will be required for delivery).

## Changelog & User-Guide Status

- **Changelog** (`CHANGELOG.md`): Entry added to `[Unreleased] → Fixed` section documenting Python reachability/supporting-call precision parity with Java.
- **User-Guide** (`docs/user-guide/user-guide.html`): Reviewed; no updates required (guide makes no contradicted claims about Python dynamic-dispatch limitations).

## Next Steps

1. **Human Review & Merge** (post-archive):
   - PR #310 awaits human review and approval.
   - Branch `matiasdaloia/parser-parity-multi-language` targets `main`.
   - All tests and gates pass; archive does not gate on review result.

2. **Follow-Up Change: Python Parser Performance Optimization** (out of scope):
   - Candidate: `python-parser-perf`.
   - Goal: Reduce parse-time overhead from current ~20% to ≤10% design target.
   - Scope: Potential optimizations in binding-table walk, synthetic-entry-point pruning, or import recursion.

3. **Parity Series Continuation** (design roadmap):
   - Go, Rust, Node parity changes using this change as template.
   - Deferred rows (dynamic dispatch, decorators, type hints, etc.) as future enhancements.

## Completeness Affirmation

All SDD artifacts (proposal, spec, design, tasks, apply-progress, verify-report, archive-report) are complete and archived. All implementation tasks (41/41) are marked done. All verification gates pass with no critical findings. The change is ready for human review, merge, and delivery.

---

**Archive Report Generated**: 2026-08-27
**Artifact Store**: Hybrid (filesystem + Engram)
**Archive Location**: `openspec/changes/archive/2026-08-27-python-parser-java-parity/`
