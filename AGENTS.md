# AGENTS.md — crypto-finder

Project-specific conventions for AI agents and human contributors working in this repo.
Read this file before making non-trivial changes. It documents conventions that are
load-bearing but not enforceable by lint or compiler alone.

## Changelog (HARD REQUIREMENT)

Every user-facing change — new flag, behavior change, schema bump, bug fix, performance
work, removal — MUST land with a matching entry under `[Unreleased]` in `CHANGELOG.md`,
in the same PR as the change. The format is [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
(`Added` / `Changed` / `Fixed` / `Removed`).

- Write entries for consumers of the tool, not for reviewers: name the flag, the schema
  version, the exported package, the observable behavior — not the internal refactor.
- Internal-only changes (test refactors, CI tweaks, comment fixes) do not need an entry.
- When cutting a release, rename `[Unreleased]` to the version + date and start a fresh
  empty `[Unreleased]` section. Do not let releases ship with the changelog behind —
  reconstructing history from merged PRs afterwards is expensive and error-prone.

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
├── c/                     # schema-v2 C callgraph contracts
├── cpp/                   # schema-v2 C++ callgraph contracts
├── java/
│   └── jdk-crypto.yaml    # JDK JCA/JCE contracts (shipped in v1)
├── go/                    # schema-v2 Go callgraph contracts
├── python/                # pyca-cryptography, pycryptodome, pycryptodomex, paramiko
└── rust/                  # schema-v2 Rust callgraph contracts
```

**One YAML file = one library version**. Adding a new library is a new YAML, not a code
change. A new ecosystem may temporarily use one empty `<ecosystem>-bootstrap` YAML because
`go:embed` requires a matching file; remove it when the first library KB lands. The loader (`contracts.LoadEmbedded(ecosystem)`) discovers all `*.yaml` files in
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
INTERNAL to the loader; the partner-facing export schema is independent (currently 6.0).

To add a library:
1. Drop a new YAML at `internal/callgraph/contracts/<ecosystem>/<library>.yaml`.
2. Set `schema_version: "2"`, `ecosystem: <name>`, and a unique `library.name`.
3. Author contracts and hierarchy edges following the same shape as `jdk-crypto.yaml`.
4. Tests run automatically — no Go code changes required.

Go contract method names use the canonical `FunctionID.String()` form:
`package/path.Function` or `package/path.(*Receiver).Method`.

## Detection vs reachability (rules, supporting calls, new languages)

There is a hard separation of concerns. Violating it is the most common mistake when
extending this tool.

- **Detection rules** (semgrep/opengrep, in the separate rules repo) detect **terminal
  crypto operations only**, and carry **standard CycloneDX metadata** (assetType,
  algorithmFamily/primitive/operation, etc.). Rules MUST NOT carry crypto-finder
  routing concerns. In particular there is no `supporting-call` assetType and no
  `supportingCall: "true"` sentinel — those are gone; do not reintroduce them.

- **Supporting calls** (setup/lifecycle/config calls around a crypto object, e.g.
  `digest.update`/`doFinal`, `Password.hash`/`addRandomSalt`/`getResult`) are **derived
  structurally from the call graph**, not tagged by rules. See
  `internal/scan/supporting_calls.go` (`deriveObjectLifecycleCalls`): a finding's
  "object" is the var its terminal call is invoked on (`ReceiverVar`) or assigned to
  (`AssignedVar`); supporting calls are the other calls on that var, the fluent-chain
  links (`ChainID`), and the producing constructor. This scales to any library without
  per-call rules.

- **Reachability MUST NOT depend on `metadata.api`.** `api` is informational CBOM
  metadata only. `matched_operation.kind` is classified from the matched **source text**
  (`inferMatchedOperationKind`), and the crypto call is located by **position** (match
  columns ∩ call-node columns) with a fluent-chain-root tie-break and a line-only
  fallback (`findCryptoCallNode`). A missing or wrong `api` must never zero out a
  finding's reachability. Do not re-add api-based selection/classification.

### Adding a new language/framework parser

For a new-language parser to get **full** reachability + supporting calls, populate these
`callgraph.FunctionCall` fields (Java does this in `internal/callgraph/java_parser.go`;
see `parseMethodInvocation` / `parseObjectCreation`):

- `ReceiverVar` — the variable a method is invoked on (`x` in `x.foo()`); empty for
  static/class receivers.
- `AssignedVar` — the variable a call's result binds to; for fluent chains, set only on
  the chain **root** (outermost call).
- `ChainID` — a stable id shared by all links of one fluent chain.
- `StartCol` / `EndCol` — **1-based, start inclusive, end exclusive** (opengrep's
  convention; tree-sitter columns are 0-based, so `+1`). Pin the tool's column
  convention with a real run, not a hand-built fixture
  (`TestOpengrep_EndColConventionPinning`).

Omitting any of these is safe — the system **degrades gracefully** to line-only
matching and a chain-root/best-resolved heuristic — but precision on multi-call lines
drops. Library-specific fluent/return-type resolution belongs in the contract KB above,
not in the parser.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in this repository's GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the canonical five-label triage vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Use the single-context domain documentation layout. See `docs/agents/domain.md`.
