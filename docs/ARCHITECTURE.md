# Architecture

How crypto-finder turns a source tree into findings, reachability data, and partner-facing exports. For the domain vocabulary used below (finding, crypto entry point, supporting call, call chain, ...), see [CONTEXT.md](../CONTEXT.md).

## Pipeline

A `scan` run executes these stages in order:

```
target source tree
   │
   ▼
1. Rules loading          remote "dca" ruleset (scanoss/crypto_rules via SCANOSS API,
   (internal/rules,        cached with TTL + stale fallback) merged with any local
    internal/cache,        --rules / --rules-dir sources
    internal/api)
   │
   ▼
2. Detection              language detection (internal/language), skip patterns
   (internal/engine,       (internal/skip), then OpenGrep/Semgrep executes the rules
    internal/scanner)      → raw matches → dedup (internal/deduplicator), dead-code
                           filtering (internal/deadcode) → interim report entities
   │
   ▼
3. Call graph             tree-sitter parsers per ecosystem build function nodes and
   construction            call edges; type inference resolves receivers/returns using
   (internal/callgraph)    the contracts KB (internal/callgraph/contracts) and, for
                           Java, bytecode/JDK platform signatures (internal/javaruntime)
   │
   ▼
4. Reachability           each finding is matched to its call graph node by POSITION
   analysis                (match columns ∩ call-node columns), then call chains from
   (internal/scan)         API entry points to the terminal crypto call are computed;
                           dependency scans (internal/dependency, internal/engine)
                           repeat 2–3 per resolved dependency with a findings cache
   │
   ▼
5. Supporting-call        lifecycle/config/factory/output calls around each finding's
   derivation              crypto object are derived STRUCTURALLY from the graph
   (internal/scan)         (ReceiverVar / AssignedVar / ChainID — see invariants below)
   │
   ▼
6. Enrichment + export    OID enrichment (internal/enricher); writers (internal/output,
   (internal/enricher,     internal/converter) emit interim JSON or CycloneDX CBOM;
    internal/scan,         --export-callgraph emits the schema-6.10 reachability export;
    pkg/graphfrag)         --export-graph-fragment emits a graph-fragment-1.9 fragment
```

The `annotate` command is a shortcut through this pipeline: it runs stage 2 only and maps the fresh findings onto a cached stage-3 fragment (`graphfrag.Fragment.ContainingFunction`), skipping the expensive graph rebuild. `convert` runs stage 6's CBOM conversion standalone.

Errors become terminal only at the CLI boundary, with a stable machine-readable code and stage — see [ERROR_CODES.md](ERROR_CODES.md).

## Package Map

### `internal/`

| Package | Responsibility |
|---------|----------------|
| `api` | HTTP client for the SCANOSS REST API (remote ruleset download). |
| `cache` | Local cache of downloaded rulesets: TTL, `--strict`, stale-fallback policy. |
| `callgraph` | Function-level call graph construction: per-ecosystem tree-sitter parsers, type inference, and the contracts knowledge base (`contracts/`). |
| `cli` | Cobra commands (`scan`, `annotate`, `convert`, `configure`, `version`), flag wiring, terminal error rendering. |
| `config` | Configuration management: env vars, config file, flag overrides. |
| `converter` | Interim JSON → CycloneDX 1.6 CBOM transformation. |
| `deadcode` | Filters findings inside C/C++ preprocessor dead-code blocks (`#if 0 ... #endif`). |
| `deduplicator` | Per-line deduplication of cryptographic assets (multiple rules on one line → one asset with a `rules[]` array). |
| `dependency` | Dependency resolvers: Go modules, Java (Maven/Gradle), Python (pip), Rust (Cargo). |
| `engine` | Scan orchestration: language detection → rules → scanner → report; the dependency scanner and its findings cache (disk/postgres); finding-ID assignment; rule-driven entry-point synthesis. |
| `enricher` | OID enrichment of findings (algorithm → Object Identifier). |
| `entities` | Scanner input structures and compatibility aliases for the public interim report contract. |
| `failure` | Compatibility aliases for the public structured terminal error contract. |
| `javaruntime` | Java JDK selection (`--java-jdk-major` / `--java-jdk-home`) for platform-signature type enrichment. |
| `language` | Automatic language detection (go-enry) honoring skip patterns. |
| `output` | Output writers: interim JSON and CycloneDX, stdout or file, streaming for large reports. |
| `rules` | Rule source management: remote source, local files/dirs, multi-source merge. |
| `scan` | Reusable scan utilities shared by CLI commands: flag validation, reachability export, graph-fragment export, supporting-call derivation, conditioned-finding materialization. |
| `scanner` | Scanner abstraction plus the `opengrep/` and `semgrep/` engine implementations. |
| `skip` | File/directory exclusion: built-in defaults, `scanoss.json` patterns, `--exclude`, gitignore-style matching. |
| `utils` | Small general-purpose helpers. |
| `version` | Build/version information for the binary. |

### `pkg/` (public, importable by downstream services)

| Package | Responsibility |
|---------|----------------|
| `graphfrag` | The graph-fragment model and wire schema (`graph-fragment-1.9`), fragment decode/encode, the tiered fail-closed **stitcher** that composes per-component fragments into transitive reachability, and the renderers (`ToCallgraphExport` — stamps callgraph schema `6.10` — and `ToFindingsEnvelope`). |
| `graphfrag/equiv` | Semantic diff asserting a stitched callgraph equals a live one (the equivalence guarantee the renderers rely on). |
| `paramcondition` | Parser for the crypto-rules `parameterCondition` grammar (`param[<selector>]<op><value>`) into structured predicates. |
| `schema` | Interim report JSON contract (format version `1.6`) and compatibility unmarshalling. |
| `failure` | Structured terminal error contract: stable `Code` and `Stage` enums plus JSON `Payload`. |

## Load-Bearing Invariants

These rules are enforced by convention (and tests), not by the compiler. Violating them is the most common way to break the tool. The agent-facing statement of the same rules lives in [AGENTS.md](../AGENTS.md).

### 1. Two-layer error model

- **Deep library code** (`internal/callgraph`, `internal/scan`, `internal/converter`, `internal/cache`, `internal/rules`, `internal/output`, parsers, loaders) returns plain wrapped errors: `fmt.Errorf("<package-prefix>: ...: %w", err)`. It must **never** import `internal/failure`.
- **Boundary code** (`internal/cli`, `internal/engine`, `internal/scanner`, `internal/dependency`) is where errors become policy: it wraps incoming errors with `failure.Wrap` / `failure.WrapUnknown`, assigning the `Code` and `Stage`. Already-typed failures pass through untouched.
- Failure `Code`s are a **stable external contract** consumed by CI parsers — never rename a shipped code. The published taxonomy is [ERROR_CODES.md](ERROR_CODES.md).

Why: deep code stays composable and testable; the boundary is the single place errors become exit codes and JSON payloads.

### 2. Contracts knowledge base (KB)

The type-inference engine consumes YAML knowledge bases under `internal/callgraph/contracts/<ecosystem>/`. **One YAML file = one library version** — adding a library is a new YAML, never a code change. The loader (`contracts.LoadEmbedded`) discovers, validates, and merges all files per ecosystem with these conflict rules:

| Situation | Outcome |
|-----------|---------|
| Same method+arity+condition, identical return | Idempotent (no error) |
| Same method+arity+condition, different return | **Hard error** naming both libraries |
| Hierarchy `child → [A]` in both libraries | Idempotent |
| Hierarchy `child → [A]` vs `[B]` (no subset) | **Hard error** naming both libraries |
| Hierarchy `child → [A]` vs `[A, B]` | Union (subset accepted) |

KB YAML schema version is `"2"` (internal to the loader). It is **independent** of the partner-facing export schemas (callgraph `6.10`, `graph-fragment-1.9`). See [AGENTS.md](../AGENTS.md#knowledge-base-layout-callgraph-inferred-types) for the authoring recipe.

### 3. Detection vs reachability

Detection rules (in [scanoss/crypto_rules](https://github.com/scanoss/crypto_rules)) detect **terminal crypto operations only** and carry standard CycloneDX metadata. They carry no crypto-finder routing concerns — there is no `supporting-call` assetType and no `supportingCall` sentinel; do not reintroduce them.

### 4. Structural supporting-call derivation

Supporting calls (setup/lifecycle/config calls around a crypto object, e.g. `digest.update`/`doFinal`) are **derived from the call graph**, not tagged by rules (`internal/scan/supporting_calls.go`, `deriveObjectLifecycleCalls`). A finding's "object" is the variable its terminal call is invoked on (`ReceiverVar`) or assigned to (`AssignedVar`); its supporting calls are the other calls on that variable, the fluent-chain links (`ChainID`), and the producing constructor. This scales to any library without per-call rules. New-language parsers should populate `ReceiverVar`, `AssignedVar`, `ChainID`, and 1-based `StartCol`/`EndCol` — omitting them degrades gracefully to line-only matching but loses precision on multi-call lines.

### 5. Reachability must never depend on `metadata.api`

`metadata.api` is informational CBOM metadata only. The matched operation's kind is classified from the matched **source text** (`inferMatchedOperationKind`), and the crypto call is located by **position** — match columns intersected with call-node columns, with a fluent-chain-root tie-break and a line-only fallback (`findCryptoCallNode`). A missing or wrong `api` must never zero out a finding's reachability. Do not re-add api-based selection or classification.

## Schema Versioning

Four independent version numbers ship in the outputs — do not conflate them:

| Version | Constant | Current | Bumps when |
|---------|----------|---------|------------|
| Interim report format | `schema.InterimFormatVersion` | `1.6` | The findings.json envelope changes |
| Callgraph export schema | `graphfrag.CallgraphSchemaVersion` | `6.10` | The partner-facing reachability contract changes |
| Graph-fragment schema | `graphfrag.SchemaVersion` | `graph-fragment-1.9` | The fragment wire format changes |
| Graph algorithm version | `graphfrag.GraphAlgoVersion` | `graph-algo-2` | Callgraph **construction** changes in a way that alters the structural graph (cache key for `annotate`) |

Every schema bump is recorded in [CHANGELOG.md](../CHANGELOG.md) (a hard repo requirement) and the format details live in [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md).
