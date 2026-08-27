# python-callgraph-parse-performance Specification

## Purpose

Bounds Python callgraph parse throughput, at scan and mining scale, to a
CI-enforced budget relative to merge-base `c6ee180`, so every deferred
capability row (B6-B20) and the KDF key-length row (C) in this change lands
without silently re-inflating parse cost. New capability.

## Requirements

### Requirement: Parse-time budget vs merge-base baseline

The parser MUST NOT regress mean parse time beyond 10% over merge-base
`c6ee180`, measured by `BenchmarkPythonParseDirectory_Bindings` with **≥8
reps in one continuous run**, reporting the combined mean AND the range
across reps (never a single round).

#### Scenario: Benchmark reports overhead within budget

- GIVEN `BenchmarkPythonParseDirectory_Bindings` run with ≥8 reps against
  the same corpus used at merge-base `c6ee180`
- WHEN the combined mean is computed
- THEN it MUST be ≤1.10x the `c6ee180` mean, and the report MUST include the
  min/max range across reps

### Requirement: CI-enforceable non-skipping guard

A CI-runnable guard MUST fail on a parse-cost regression without a manual
corpus-generation step, and MUST NOT `t.Skip()` in CI.

#### Scenario: Committed-corpus or node-visit-count guard runs in CI

- GIVEN a committed deterministic fixture corpus (state size bound, ≤40
  files) or `TestPythonParser_NodeVisitBudget` asserting tree-sitter node
  visits per node ≤ a fixed constant
- WHEN the guard runs in a normal `go test ./...` CI invocation
- THEN it MUST execute (never skip) and MUST fail on a regression past the
  fixed constant/corpus budget

### Requirement: Allocation budget and header-only return-type extraction

`B/op` MUST NOT exceed 1.15x the `c6ee180` baseline. `parsePythonReturnType`
MUST NOT materialize the full function body as a Go string per declaration.

#### Scenario: Benchmark allocations within budget

- GIVEN the same benchmark run as the parse-time requirement
- WHEN `B/op` is compared to the `c6ee180` baseline
- THEN it MUST be ≤1.15x that baseline

#### Scenario: Return-type extraction reads only the header

- GIVEN a function declaration whose body is large (e.g. 500+ lines)
- WHEN the parser extracts its `ReturnType`
- THEN it MUST use the `return_type` field node (or an equivalent
  header-scoped slice of `src`), never `node.Content(src)` on the whole
  `function_definition` node
- Pinned by: a targeted allocation/behavior assertion in
  `internal/callgraph/python_parser_test.go`

### Requirement: Every later row re-runs the performance guard

Every implementation row in this change (6, 7, 8, 9, 11, 13, 14, 18, 20, C)
MUST re-run `BenchmarkPythonParseDirectory_Bindings` and the CI guard before
being considered complete. A row that breaches the budget MUST be optimized
or dropped within this change, never accepted as a documented deviation.

#### Scenario: Guard re-runs after each row lands

- GIVEN a row's implementation and tests are complete
- WHEN the performance guard from the two requirements above runs
- THEN it MUST still pass; a failing guard blocks that row from being
  considered done
