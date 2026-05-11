# AGENTS.md — crypto-finder

Project-specific conventions for AI agents and human contributors working in this repo.
Read this file before making non-trivial changes. It documents conventions that are
load-bearing but not enforceable by lint or compiler alone.

## Error handling

This project uses a **two-layer error model**. Mixing the layers is a defect.

### 1. Deep library code

Packages: `internal/callgraph`, `internal/scan`, `internal/converter`, `internal/cache`,
`internal/rules`, `internal/output`, parsers, loaders, helpers — anything that does not
make terminal/policy decisions.

- Return errors via `fmt.Errorf("<package-prefix>: ...: %w", err)`.
- Use `%w` so callers can `errors.Is` / `errors.As` through the chain.
- Use a stable package prefix (`contracts:`, `callgraph:`, `scan:`, ...) so error
  origins are greppable.
- **Do NOT** import `internal/failure` from these packages. Deep code stays portable
  and testable without coupling to the failure taxonomy.

### 2. Boundary code

Packages: `internal/cli`, `internal/engine`, `internal/scanner`, `internal/dependency` —
anywhere errors become terminal (CLI exit code, JSON failure payload, retry decisions).

- Wrap incoming deep-layer errors with `failure.Wrap` or `failure.WrapUnknown`.
- Assign the appropriate `failure.Code` and `failure.Stage` at the wrap site.
- Already-typed `*failure.Error` values pass through untouched (`WrapUnknown`
  preserves them; only plain errors get wrapped).

### Adding a new failure mode

When a new terminal failure mode is introduced:

1. Add a new `Code` constant in `internal/failure/error.go`.
2. Add a corresponding `Stage` if the failure belongs to a new pipeline stage.
3. **Never rename a `Code` that has shipped** — codes are stable identifiers consumed
   by external tooling and CI parsers.

### Why this layering

Deep code stays composable, unit-testable, and reusable across pipelines. The boundary
is the only place where errors become policy. Inverting this rule — sprinkling `failure`
calls deep in parsers — leaks the CLI's policy concerns into library code and makes
those packages harder to repurpose.

## Knowledge base layout (callgraph inferred-types)

The callgraph inference engine consumes language-agnostic YAML knowledge bases under
`internal/callgraph/contracts/`. The structure is:

```
internal/callgraph/contracts/
├── contracts.go           # loader, types, validation
├── java/
│   └── jdk-crypto.yaml    # JDK JCA/JCE contracts (shipped in v1)
├── go/                    # future: stdlib + x/crypto + ...
├── python/                # future: cryptography + pycryptodome + ...
└── rust/                  # future: ring + rustcrypto + ...
```

**One YAML file = one library version**. Adding a new library is a new YAML, not a code
change. The loader (`contracts.LoadEmbedded(ecosystem)`) discovers all `*.yaml` files in
the ecosystem directory, validates each, and merges them via `contracts.Merge()` with
conflict-detection rules:

- Same method+arity+condition with identical return → idempotent (no error).
- Same method+arity+condition with different return → HARD ERROR naming both libraries.
- Hierarchy `child → [A]` in both libs → idempotent.
- Hierarchy `child → [A]` vs `[B]` (no subset) → HARD ERROR naming both libraries.
- Hierarchy `child → [A]` vs `[A, B]` → UNION (subset accepted).

Each YAML carries a `library:` block with `name`, optional `coordinates`, optional
`version_range`, and optional `description`. The `library.name` propagates onto every
contract's `SourceLibrary` field for diagnostic identification across libraries.

Schema version is `"2"` — schema `"1"` is hard-rejected. The YAML schema version is
INTERNAL to the loader; the partner-facing export schema is independent (currently 5.3).

To add a library:
1. Drop a new YAML at `internal/callgraph/contracts/<ecosystem>/<library>.yaml`.
2. Set `schema_version: "2"`, `ecosystem: <name>`, and a unique `library.name`.
3. Author contracts and hierarchy edges following the same shape as `jdk-crypto.yaml`.
4. Tests run automatically — no Go code changes required.
