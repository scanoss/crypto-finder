# Architecture

crypto-finder is a domain and a client built on the reachability engine
[`github.com/scanoss/reach`](https://github.com/scanoss/reach). reach builds
typed call graphs and stitches them; crypto-finder supplies the crypto
knowledge base, detects cryptography on the graph, asks the SCANOSS API about
dependencies, and writes the reports. For the vocabulary (finding, crypto
entry point, supporting call, call chain), see [CONTEXT.md](../CONTEXT.md).

## At a glance

| Layer | Lives in | Owns |
|---|---|---|
| Engine | `github.com/scanoss/reach` (MIT) | Parsers, call graph, type resolution, contracts loader, entry points, graph fragments, stitcher, callgraph renderer |
| Domain | `internal/cryptokb`, `internal/cardmatch`, `internal/scanner/cards`, `internal/scan`, `internal/oid`, `internal/pqc`, `pkg/appreach`, `pkg/conditioned`, `pkg/pqc` | Crypto KB, detection, supporting calls, OIDs, PQC, the application reachability answer |
| Client | `internal/cli`, `internal/config`, `internal/api`, `internal/cache`, `internal/rules`, `internal/ruleset`, `internal/dependency`, `internal/offline`, `internal/output`, `internal/converter` | Commands, configuration, API calls, ruleset cache, dependency resolution, offline mining, report writing |

What runs locally and what the API serves: [CLIENT_SERVER.md](CLIENT_SERVER.md).

## Pipeline

A `scan` runs these stages in order:

```
target source tree
   │
   ▼
1. Rules          remote "crypto-cards" ruleset (leased bundle from the SCANOSS API,
   │              cached encrypted) merged with --rules / --rules-dir
   ▼
2. Graph          reach/language detects languages (Java, Python; others fail
   │              with language_not_supported); reach/callgraph builds one typed
   │              graph per scanned ecosystem, typed by the crypto KB
   │              (internal/cryptokb), JDK platform signatures and, with
   │              --scan-dependencies, the closure's JARs (type-only)
   ▼
3. Detection      the cards engine (internal/cardmatch) matches the ruleset
   │              against the graph's call sites → dedup → findings
   ▼
4. Reachability   each finding is matched to its call-graph node by position;
   │              chains from entry points to it are computed. With
   │              --scan-dependencies, one request to
   │              /v3/cryptography/reachability/application (or --offline, in
   │              process) answers every dependency finding
   ▼
5. Supporting     lifecycle and configuration calls around each finding's
   calls          object, derived from the graph (see invariants)
   ▼
6. Output         OIDs, PQC; interim JSON or CycloneDX; --export-callgraph
                  (reach/graphfrag renderer); --export-graph-fragment
```

| Command | Stages |
|---|---|
| `scan` | 1-6 |
| `annotate` | 1, 3, 5, 6 on a stored fragment: re-detects without rebuilding the graph (`graphfrag.Fragment.ContainingFunction` maps findings to functions) |
| `convert` | The CycloneDX conversion of stage 6 |
| `cbom` | Asks the API per SBOM component; scans nothing locally |

Errors become terminal only at the CLI boundary, with a stable code and
stage ([ERROR_CODES.md](ERROR_CODES.md)).

## Package map

### `internal/`

| Package | Responsibility |
|---|---|
| `api` | HTTP client for the SCANOSS API (rulesets, project and component reachability) |
| `boundary` | Lists the paths the engine packages had here (`MovedEnginePackages`); its tests fail if one reappears |
| `cache` | Ruleset cache: TTL, `--strict`, stale fallback, encrypted leased bundles |
| `cardmatch` | The cards engine: compiles the ruleset into a card index and matches it against a graph's call sites |
| `cli` | Cobra commands, flag wiring, terminal error rendering |
| `config` | Configuration: flags, environment, config file |
| `converter` | Interim JSON → CycloneDX 1.7 CBOM, exact-only OIDs |
| `cryptokb` | The crypto KB: contract YAML per ecosystem, embedded and installed into reach on import |
| `deadcode` | Drops findings inside C/C++ `#if 0` blocks |
| `deduplicator` | Per-line deduplication of assets |
| `dependency` | Java (Maven, Gradle) and Python closure resolution; module-root discovery |
| `engine` | Scan orchestration; the application reachability closure, request and merge; finding ids |
| `enricher` | OID enrichment after materialization |
| `entities` | Scanner input structures; aliases of the public report contract |
| `failure` | Aliases of the public error contract |
| `graphalgoguard` | Test-only: the graph algorithm guard ([GRAPH_IDS.md](GRAPH_IDS.md)) |
| `offline` | `--offline`: mines dependencies in process and caches them ([OFFLINE.md](OFFLINE.md)) |
| `oid` | Exact, registered OIDs only |
| `output` | Writers: interim JSON, CycloneDX; stdout or file |
| `pqc` | Writes the PQC dataset's classification onto output |
| `rules` | Rule sources: remote, local files and directories, merge |
| `ruleset` | Leased ruleset bundle format and lease verification |
| `scan` | Shared scan utilities: flag validation, reachability and fragment export, supporting calls |
| `scanner` | Detector interface and its one implementation, `cards/` |
| `utils`, `version` | Helpers; build information |

### `pkg/` (public)

| Package | Responsibility |
|---|---|
| `appreach` | The application reachability answer (`/v3/cryptography/reachability/application`), run by the API and by `--offline`; the findings envelope (`ToFindingsEnvelope`) |
| `conditioned` | Specializes a generic finding by the value its selector argument resolves to |
| `pqc` | Post-quantum classification of served findings |
| `sbomcbom` | CycloneDX CBOM for an SBOM from published findings (`cbom`) |
| `schema` | Interim report JSON contract (format `1.9`) |
| `failure` | Terminal error contract: `Code`, `Stage`, JSON payload |

The graph-fragment, stitcher, walk, condition-parser and purl packages are in
reach since 1.0 ([MIGRATION_1.0.md](MIGRATION_1.0.md#go-library-users)).

## Engine boundary

| Rule | Enforced by |
|---|---|
| Engine changes land in reach, are tagged, then required in `go.mod` here (v0.14.0 today); no `replace` on a release | Review; `go.mod` |
| No engine package reappears in crypto-finder | `go test ./internal/boundary` |
| reach imports nothing from crypto-finder | reach's `internal/importguard` |
| Crypto knowledge is data, injected: `internal/cryptokb` calls `contracts.SetSource` and `contracts.SetHints` on import | Review |
| crypto-finder passes reach its cache root (`~/.scanoss/crypto-finder/cache`) for the bytecode and Python signature caches | Code (`internal/cli/scan.go`) |
| reach's contract-typed tests run here against the crypto KB | `make test-reach` (`REACH_TEST_CONTRACTS`) |

## Load-bearing invariants

These are enforced by convention and tests, not by the compiler. The
agent-facing version is in [AGENTS.md](../AGENTS.md).

| # | Invariant | Why |
|---|---|---|
| 1 | Two-layer errors: deep code (`reach/callgraph`, `internal/scan`, `internal/converter`, `internal/cache`, `internal/rules`, `internal/output`) returns `fmt.Errorf("<prefix>: ...: %w", err)` and never imports `internal/failure`; boundary code (`internal/cli`, `internal/engine`, `internal/scanner`, `internal/dependency`) wraps with `failure.Wrap` / `WrapUnknown`. Shipped codes are never renamed. | One place turns errors into exit codes and JSON |
| 2 | One KB YAML file is one library version; adding a library is a new file, never code. The loader merges per ecosystem and fails on conflicting returns or hierarchies. | KB growth without engine changes |
| 3 | Rules detect terminal crypto operations only, with standard CycloneDX metadata. No `supporting-call` asset type, no `supportingCall` sentinel. | Detection and reachability stay separate |
| 4 | Supporting calls are derived from the graph (`internal/scan/supporting_calls.go`): the other calls on the finding's `ReceiverVar` / `AssignedVar`, the fluent-chain links (`ChainID`), the producing constructor. Key sizes come from contract `contributes` markers; a disagreeing rule value is kept as `rule_declared_bits` behind `rule_conflict`. | Scales to any library without per-call rules |
| 5 | Reachability never depends on `metadata.api`. The call is located by position (match columns ∩ call-node columns, fluent-chain-root tie-break, line-only fallback). | A wrong `api` must not zero out reachability |
| 6 | `call_chains` is a capped sample: 8 routes by default, depth 32 (`--export-callgraph-max-chains`); the complete reverse index is opt-in (`--export-callgraph-entry-points`). Policy: [ADR 0002](adr/0002-call-chains-sample-size.md). | Bounded output size |

## Versioning

Graph algorithm ids, the graph-fragment and callgraph schemas, the interim
format, and the guard that keeps them honest: [GRAPH_IDS.md](GRAPH_IDS.md).
Every schema bump is recorded in [CHANGELOG.md](../CHANGELOG.md); formats are
in [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md).
