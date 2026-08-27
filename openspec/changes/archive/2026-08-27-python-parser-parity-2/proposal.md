# Proposal: Python parser parity round 2 — throughput, deferred rows, KDF key length

## Intent

`python-parser-java-parity` (archived 2026-08-27, PR #310) closed the Critical/High
binding-resolution rows but left two debts: **parse throughput** (~14–20% over
merge-base `c6ee180`, design target was ≤10%, hard cap 20% — measured noisy, and the
guard benchmark cannot run in CI because its corpus is not committed) and **10 deferred
capability rows** from the exploration matrix. Mining throughput is now a first-class
requirement: crypto-mining-service scans large pip dependency trees where a constant
per-file factor multiplies across every distribution. This change pays both debts in one
branch and adds `resolved_key_length` evidence for Python KDFs, leaving Python at or
above Java's level on every row that has a Java analogue.

## Scope

### In Scope

| ID | Deliverable | Java analogue | Layer | Path | L/M |
|----|-------------|---------------|-------|------|-----|
| A1 | TreeCursor walking + symbol-id dispatch everywhere; fold the per-body call walk into the file prepass; stop re-deriving per-call context | — (Python-only debt) | parser | L,M | M |
| A2 | Allocation reduction: `parsePythonReturnType(node.Content(src))` (python_parser.go:784) materializes the whole function body as a Go string per decl; slice `src` / use the `return_type` field node instead. Same for other `Content(src)`/`Type()` string calls on hot paths | — | parser | L,M | S |
| A3 | CI-enforceable guard: commit a small deterministic corpus + a node-visit-counter test that fails on regression; keep `BenchmarkPythonParseDirectory_Bindings` for absolute numbers | `TestOpengrep_EndColConventionPinning` precedent (pin, don't trust) | test | — | S |
| A4 | Mining-scale measurement on a real large pip tree via `--scan-dependencies`, recorded in apply-progress | `maxJavaJARWorkers` parallel indexing | measurement | L | S |
| B6 | Opengrep column-convention pinning test for Python against a real opengrep run | `TestOpengrep_EndColConventionPinning` | test | L,M | S |
| B7 | Bounded dynamic dispatch: `getattr(obj,"name")(...)`, `importlib.import_module("x")`, `__import__("x")` — **literal-string arguments only**, no inference | `7ee21ca` reflection dispatch | parser | L,M | M |
| B8 | Decorator semantics: `@staticmethod`/`@classmethod`/`@property` receiver + `cls` handling; custom decorators preserve the wrapped function identity | Java annotations (partial) | parser | L,M | M |
| B9 | `super().__init__(...)` / `super().method()` resolved to the base class via `OwnerBases` | `2287a76` | parser | L,M | S |
| B11 | `functools.partial(f, ...)` and `obj(...)` implicit `__call__` when `obj` is bound to a class instance in scope | functional interfaces (loose) | parser | L | M |
| B13 | Type hints feed receiver/return resolution: parameter/return annotations, `Optional[...]`/`Union[...]`/`X \| None` normalization, `TYPE_CHECKING` imports, `x: Cipher = ...`. **Bounded to names resolvable via imports/KB — no inference engine** | bytecode generic signatures | parser + type resolver | L,M | M |
| B14 | Dependency-mode external type resolver: `.pyi`/source-signature reader for pip-resolved distributions — declared return annotations + class hierarchies, cached per distribution, parallelized like `maxJavaJARWorkers` | `JavaBytecodeTypeResolver` (`java_type_resolver.go`) | new type resolver | L (`--scan-dependencies`) | L |
| B18 | Visibility: leading-underscore → private/protected, dunder → public; populate `Visibility`/`OwnerVisibility` | `827fe39`, `java_parser.go:915-1020` | parser | L,M | S |
| B20 | Recurse into constructor/call arguments so a nested crypto call in an argument list contributes its origin | `2959b64` | parser | L,M | M |
| C | `resolved_key_length` for Python KDFs (`hashlib.pbkdf2_hmac dklen=`, `hashlib.scrypt dklen=`, `PBKDF2HMAC/Scrypt/HKDF/ConcatKDF length=`, argon2 `hash_len`, bcrypt-kdf `desired_key_bytes`, PyCryptodome `PBKDF2 dkLen=`/`scrypt key_len=`/`HKDF key_len=`) from integer literals and module-level constants | `internal/scan/key_length.go` (schema 6.12→6.13, JCA) | KB YAML + contracts loader + parser + scan | L,M | M |

### Out of Scope (non-goals)

- Export schema change. `pkg/graphfrag.CallgraphSchemaVersion` stays `6.13`,
  `SchemaVersion` stays `graph-fragment-1.13`. Verified: `resolved_key_length` is
  already a language-agnostic field on the supporting-call declaration, driven entirely
  by KB `parameters[].contributes` — **no bump needed for C**.
- Detection-rule changes (separate rules repo).
- `internal/scan/supporting_calls.go` semantics (zero-diff guard, as in round 1).
- Go / Rust / Node parsers — later changes in the parity series.
- Unbounded type inference, dataflow across files, or a general Python type checker.

## Capabilities

### New Capabilities

- `python-callgraph-parse-performance`: bounded, CI-enforced parse-throughput budget for
  the Python parser at scan and mining scale.
- `python-kdf-key-length-resolution`: Python KDF key-length evidence populating the
  existing `resolved_key_length` field without a schema bump.

### Modified Capabilities

- `python-callgraph-binding-resolution`: extended with dynamic dispatch (bounded),
  decorator semantics, `super()` resolution, `functools.partial`/`__call__`, type-hint-fed
  resolution, visibility, argument-provenance recursion, dependency-mode stub type
  resolution, and the opengrep column-convention pinning scenario.

## Approach

**A — performance first, and it gates everything else.** Round 1's remediation already
folded binding collection into `collectPythonFilePrepass` (one full-file walk keyed by
`StartByte`), so the residual cost is: (1) a second full traversal per body in
`walkForCalls`, (2) a third pruned traversal for each `<module>`/`<clinit>` body, (3) cgo
`Node.Child/Type/ChildCount` per visited node in `parseFunctionDef`,
`collectPythonAssignmentTargets`, `pythonParameterNames` and `parseCallExpr`, and (4) KB
inference over ~25% more declarations from synthetic entry points (PR #310 F2 analysis).
A1/A2 attack (1)–(3): a single `TreeCursor` descent per file that emits calls while the
binding table is live, `Symbol()` dispatch instead of `Type()` string compares, and no
whole-body `Content(src)` allocation. Target: **≤10% over `c6ee180`, ideally at or below
baseline.** Every later row is measured against that budget, not against today's HEAD.

**B — deferred rows, each in its own layer.** B6/B18/B9 are small and land first as
low-risk confidence builders. B7/B8/B11/B20 are parser-local resolution rules with hard
bounds (literal strings only; no speculative dispatch). B13 lives half in the parser
(annotation extraction/normalization) and half in `python_type_resolver.go` (consuming a
normalized type for KB lookup) — it must not become an inference engine. B14 is a genuinely
new component (`python_type_resolver.go` sibling, role-analogous to
`JavaBytecodeTypeResolver`) and is the largest and riskiest row: it lands **last**, so A–C
are already green and independently shippable if B14 slips.

**C — layer decision, stated explicitly per AGENTS.md.** `internal/scan/key_length.go` is
already fully generic: it reads KB `parameters[].contributes.property: keySize` and applies
`contracts.Derivation`. So C is **primarily KB YAML work**, plus three small enabling
changes: (i) a new `argument_byte_length` derivation in the contracts loader whitelist
(`contracts.go:404`) and one case in `resolveContractKeyBits` — Python KDFs express length
in **bytes**, while `argument_value` is JCA raw **bits**; (ii) keyword-argument support,
because Python KDFs are called as `dklen=32`/`length=32` and nothing in
`internal/callgraph` records an argument's keyword name today (`keySizeParameterRole`
ignores name-only roles), so the parser must map keyword arguments onto declared parameter
indices; (iii) module-level integer-constant resolution for `KEY_LEN = 32`. No
`internal/failure` import in `internal/callgraph` (two-layer error model).

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/callgraph/python_parser.go` | Modified | A1/A2 traversal rewrite; B7–B9, B11, B18, B20; keyword-argument capture for C |
| `internal/callgraph/python_type_resolver.go` | Modified | B13 normalized-annotation consumption |
| `internal/callgraph/python_stub_type_resolver.go` | New | B14 `.pyi`/source signature resolver, per-distribution cache, worker pool |
| `internal/callgraph/builder.go` | Modified | B14 wiring; B13 resolution ordering |
| `internal/callgraph/contracts/contracts.go` | Modified | C: `argument_byte_length` derivation enum + validation |
| `internal/callgraph/contracts/python/*.yaml` | Modified | C: `parameters[].contributes: keySize` on KDF contracts |
| `internal/scan/key_length.go` | Modified | C: byte-length derivation case; keyword-named role matching |
| `internal/callgraph/python_perf_test.go`, `testdata/python_perf/` | Modified | A3: committed corpus + node-visit-counter guard |
| `internal/scan/supporting_calls.go`, `pkg/graphfrag/` | Unchanged | Zero-diff guard, asserted in verify |
| `CHANGELOG.md`, `docs/user-guide/user-guide.html` | Modified | Hard requirement per AGENTS.md |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| B rows re-inflate parse cost and eat A's win | High | A lands first and pins a CI guard; every B row re-runs the benchmark; a row that breaches the budget is optimized or dropped, not accepted |
| Benchmark noise on a shared dev machine (round 1 saw 12.5%–27.5% across rounds) | High | ≥8 reps in one continuous run; report the combined mean plus the range, never a single round |
| B14 is large, network/venv-dependent, and hard to test hermetically | Med | Last apply phase; committed `.pyi` fixtures, no network in tests; abandonable without touching A–C |
| C's keyword-argument capture changes shared argument plumbing and could shift Java/Go/Rust behavior | Med | Keyword mapping stays Python-parser-local; full `-race` suite plus Java/Rust regression tests as the gate |
| B7/B8/B13 over-reach into speculative inference and cause false reachability | Med | Hard bounds written into the spec: literal-string arguments only; annotations resolvable via imports/KB only; no cross-file dataflow |
| More resolved receivers change supporting-call grouping volume for mining consumers | Low | Existing `internal/scan` E2E export tests; schema and `supporting_calls.go` zero-diff |
| Committed perf corpus inflates repo size / becomes stale | Low | Small deterministic corpus sized for CI; generator stays committed alongside it |

## Rollback Plan

Same branch (`matiasdaloia/parser-parity-multi-language`, PR #310) — no new PR. Each row
(A1–A4, B6…B20, C) is its own commit series with its own tests, so any row reverts with
`git revert` of that range without touching the others. Ordering is chosen so the risky
rows are last: reverting B14 leaves A–C intact and green. Nothing in this change touches
the export schema, so no consumer-visible rollback is required.

## Dependencies

- Merge-base `c6ee180` remains the performance baseline (round 1 used it; comparability
  depends on not re-baselining).
- A real large pip-resolved dependency tree for A4's mining-scale measurement.
- Vendored `go-tree-sitter` Python grammar node/field shapes, already pinned by
  `TestPythonGrammarFacts_PinnedNodeShapes`.

## Success Criteria

- [ ] `BenchmarkPythonParseDirectory_Bindings` shows **≤10%** parse-time overhead vs
      `c6ee180`, measured with **≥8 reps in one continuous run**; combined mean and range
      both reported. At or below baseline is the stretch goal.
- [ ] `B/op` no worse than the `c6ee180` baseline (round 1 ended at +34.8%).
- [ ] A CI-runnable guard fails on a parse-cost regression without needing a manual
      corpus generation step.
- [ ] A4 mining-scale `--scan-dependencies` measurement on a real large Python tree is
      recorded with before/after numbers.
- [ ] Each of rows 6, 7, 8, 9, 11, 13, 14, 18, 20 has at least one named passing test
      pinning its scenario, plus a negative-path test for every bounded rule.
- [ ] Python KDF findings carry `resolved_key_length` with `provenance: constant` for
      integer-literal and module-level-constant lengths, and `unknown` (never fabricated)
      otherwise.
- [ ] `pkg/graphfrag.CallgraphSchemaVersion == "6.13"` and
      `SchemaVersion == "graph-fragment-1.13"` unchanged; `git diff` on
      `internal/scan/supporting_calls.go` and `pkg/graphfrag/` is empty.
- [ ] `go test -race ./...` exit 0, `make lint` 0 issues, `make coverage-check` ≥80%,
      `git diff --check` clean.
- [ ] `CHANGELOG.md` `[Unreleased]` and `docs/user-guide/user-guide.html` updated.

## Proposal question round

Execution mode is `auto` and the user's direction was explicit ("do not wait"), so the
proposal was finalized on the assumptions below rather than blocking. Correct any of
these before `sdd-spec`/`sdd-design`:

1. **Performance is a gate, not a wish.** A row that pushes the benchmark past ≤10% is
   optimized or dropped within this change — not accepted as a documented deviation the
   way round 1's F2 was. Assumed: yes.
2. **B14 is in, but last and abandonable.** If it slips or proves untestable without
   network access, A–C ship on PR #310 and B14 becomes its own change. Assumed: yes.
3. **Bounded means bounded.** B7 resolves only literal-string arguments; B13 only
   annotations resolvable via imports/KB. Dynamic or computed names stay unresolved rather
   than guessed. Assumed: yes — a false crypto edge is worse than a missing one.
4. **C introduces a new KB derivation (`argument_byte_length`) and keyword-argument
   capture in the parser.** That is a contracts-loader schema addition (internal, not the
   partner export schema) plus shared argument plumbing. Assumed acceptable; the
   alternative — encoding bytes-vs-bits per-library in scan-layer Go — was rejected as
   putting policy in the wrong layer.
5. **Visibility mapping (B18).** Assumed: single leading underscore → `protected`, double
   leading underscore (non-dunder) → `private`, dunder and everything else → `public`.
   This is convention, not enforcement; confirm the mapping is what mining consumers want.
