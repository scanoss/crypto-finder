# rust-callgraph-parse-performance Specification

## Purpose

Throughput, memory and concurrency bounds for the Rust parser. The crate-wide
declaration index in `rust_manifest.go` and the scoped traversal in
`rust_type_semantics.go` both add work per file, and two classes of defect have
already reached this branch and been fixed: a tree-sitter parser reused while
another tree was open, and a mutex held across a recursive call that re-took it.
Both are failure modes a correctness test does not catch, so they are pinned
here.

## Requirements

### Requirement: The crate index is built once per crate

The declaration index MUST be memoised on the crate source root and shared
across cloned workers for a whole scan, not rebuilt per file or per worker.

#### Scenario: Three workers share one build

- GIVEN a crate parsed by three cloned parser workers
- WHEN the scan completes
- THEN the index build count MUST be exactly 1
- Pinned by: `TestRustParser_CrateIndexIsBuiltOncePerCrate`

### Requirement: Indexing uses its own tree-sitter parser

Any code that parses a file while a caller's tree is still open MUST use a
dedicated `sitter.NewParser()`. Reusing the parser instance is not reentrant and
manifests as a parse that never finishes rather than as an error.

#### Scenario: A large crate completes within budget

- GIVEN a crate of the size of rustls 0.23.20
- WHEN it is parsed
- THEN it MUST complete within the test's time budget and MUST NOT hang
- Pinned by: `TestRustParser_ParsesALargeCrateWithinBudget`

### Requirement: No lock is held across a call that re-takes it

A function that holds the index mutex MUST NOT call a function that acquires
it. Where a helper must run under the caller's lock, its name MUST say so and
its contract MUST be documented at the definition.

### Requirement: Per-file work is bounded and does no repeated filesystem I/O

Resolution helpers called once per file MUST NOT re-read or re-parse a
directory's `lib.rs`/`mod.rs`, and MUST NOT walk the filesystem, on each call.
An unmemoised directory-level parse called per file is quadratic in the number
of module declarations at a crate root.

#### Scenario: Wall clock stays within budget of the pre-index baseline

- GIVEN the published-crate corpus used for this capability
- THEN total wall clock MUST stay within 1.3x of the baseline before the crate
  index was introduced, and no crate may hang

### Requirement: Other languages pay nothing

The Rust fields on `FileAnalysis` are unexported and MUST be assigned only
inside the Rust parse path. Every read MUST be nil-guarded or a nil-tolerant
method, so no other language allocates per file and none can nil-panic.

#### Scenario: The export schema is unchanged

- GIVEN the Rust fields added to `FileAnalysis`
- THEN they MUST NOT appear in any exported payload, and the callgraph export
  and graph-fragment schema versions MUST be unchanged

### Requirement: A bounded index is abandoned, never partial

The crate index is capped so a pathological tree cannot make indexing
unbounded. Above the cap the index MUST be abandoned rather than built from the
files that fit. A partial index detects conflicts only among the files it read,
so a name two files declare differently looks unambiguous when the second
declaration falls past the cap — a wrong identity produced by a size threshold.
Callers MUST be able to tell "no index" from "an index that found nothing",
because an empty index answers "declared nowhere" for every name and would let
a glob claim a name the crate declares itself.
