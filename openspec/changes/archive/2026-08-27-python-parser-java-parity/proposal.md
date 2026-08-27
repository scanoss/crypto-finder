# Proposal: Python parser parity with Java (callgraph binding resolution)

## Intent

Reachability quality must be equal across every language we mine. Java is the reference; Python is not. Python resolves `ReceiverVar` only for a call on a bare local variable assigned by a plain `x = ...` in the same function body. Crypto objects arriving as **parameters**, held on `self.attr`, bound by `with/for/except`/walrus/unpacking, initialized at module or class-body level, or re-exported through `__init__.py` lose object identity — so `deriveObjectLifecycleCalls` cannot group their lifecycle, and findings lose supporting calls and reachability precision on both paths (local scans with/without `--scan-dependencies`, and mining). First of a per-language parity series; this proposal's shape is the template for Go, Rust, and Node.

## Scope

### In Scope (exploration rows, all parser-internal)

| Row | Deliverable |
|---|---|
| 1 | Parameters usable as receivers |
| 3 | Non-assignment bindings: `with/as`, `for/in`, `except/as`, walrus, tuple/star unpacking, comprehension targets |
| 2 | `self.attr` instance-attribute provenance across methods |
| 12 | Synthetic entry points for module-level **and** class-body statements (Java `<clinit>` analogue) |
| 4 | Import robustness: nested/conditional/function-local imports; relative imports (`from . import x`, `from ..pkg import y`) |
| 15 | `__init__.py` re-export propagation to sibling files |

### Out of Scope

- Deferred rows 6, 7, 8, 9, 11, 13, 14, 17, 18, 20.
- A Python analogue of Java's `resolved_key_length` KDF field (separate product decision + schema bump).
- Detection rules, KB YAML, export schema, `supporting_calls.go` semantics.

## Capabilities

### New Capabilities

- `python-callgraph-binding-resolution`: Python object-identity resolution (receiver/assignment/chain), synthetic entry points, and import/re-export resolution feeding reachability and supporting-call derivation.

### Modified Capabilities

- None. `openspec/specs/` is empty; no shipped spec-level behavior changes.

## Approach

Change `internal/callgraph/python_parser.go` only, mirroring Java's layering:

1. **Binding table** — replace the assignment-only `collectPythonLocalVars` walk with a collector covering parameters and every non-assignment binder; receiver/assigned-var lookups consult it.
2. **Class-scoped attribute map** — port `collectClassFieldAssignments`' shape so `self.x = Cipher(...)` yields a stable identity for `self.x.encrypt()` elsewhere.
3. **Synthetic entry points** — mirror `parseClassInitDecl`/`classInitNodes` for module-root and class-body statements.
4. **Imports** — recurse into nested blocks; honor `import_prefix` levels; stitch `__init__.py` re-exports at builder level, no cross-file type inference.

`PythonContractTypeResolver` stays KB-lookup only: this improves structure, not type inference. Strict TDD — failing test per idiom first.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/callgraph/python_parser.go` | Modified | All six rows |
| `internal/callgraph/python_parser*_test.go` | New/Modified | Unit test per idiom |
| `internal/scan/supporting_calls_test.go` | New | Lifecycle grouping for new bindings |
| `internal/scan/python_e2e_integration_test.go` | Modified | Export regression; schema assertions unchanged |
| `CHANGELOG.md` | Modified | `[Unreleased]` → `Fixed`/`Changed` |
| `docs/user-guide/user-guide.html` | Conditional | Only if user-visible behavior text changes |
| `pkg/graphfrag`, `internal/scan/export.go`, contracts KB | Unchanged | No bump: `6.13` / `graph-fragment-1.13` |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Row 12 inflates entry-point volume at mining scale | Med | One synthetic decl per module/class, as Java; assert counts in e2e |
| Parse-time regression on large Python trees | Med | Single-pass binding collection; benchmark before/after |
| Existing Python e2e tests break on richer output | High | Every diff must be an intended precision gain, never a shape change |
| `__init__.py` stitching leaks cross-file assumptions | Med | Re-exports only; KB resolver untouched |
| Broad single PR (`exception-ok`) strains review | Med | `sdd-tasks` slices per row with independent tests |

## Rollback Plan

Single PR revert. Parser-internal: no schema version, persisted state, cache format, CLI flag, or rule change, so reverting restores the prior output shape exactly. Stale callgraph cache entries regenerate on next scan.

## Dependencies

- Pinned `smacker/go-tree-sitter` Python grammar must expose node types for `with`, `for`, `except`, walrus, unpacking, `import_prefix`, `async` — empirical check in design.
- Baseline green 2026-08-26: `go test ./internal/callgraph/ -run Python`, `go test ./internal/scan/`.

## Success Criteria

- [ ] One `internal/callgraph` unit test per in-scope idiom asserting `ReceiverVar`/`AssignedVar`/`ChainID`/synthetic entry point/resolved import, each red before the fix.
- [ ] `internal/scan` tests prove supporting-call grouping for parameter, `self.attr`, and non-assignment-bound objects.
- [ ] E2E tests still assert `6.13` / `graph-fragment-1.13`; no schema field added or removed.
- [ ] `make lint` (golangci-lint v2.10.1) clean; `make coverage-check` ≥ 80% total.
- [ ] `CHANGELOG.md` `[Unreleased]` entry in the same PR.
- [ ] Zero diff in `pkg/graphfrag`, `supporting_calls.go` semantics, `internal/callgraph/contracts/`.
