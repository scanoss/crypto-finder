# Graph algorithm and schema ids

Every graph fragment crypto-finder writes is stamped with the id of the
algorithm that built it (`scan_metadata.graph_algo_version`). Caches of
structural graphs (SCANOSS's stored dependency graphs, the `--offline`
cache, `annotate` users)
are keyed on that id, so a graph-construction change must bump it, and a
change that does not alter graphs must not. `TestGraphAlgoVersionGuard`
enforces both directions.

## Quick path: I changed graph construction

1. Run the guard:
   ```bash
   go test ./internal/graphalgoguard/ -run TestGraphAlgoVersionGuard
   ```
2. If it fails naming an ecosystem, bump that ecosystem's id in reach
   (`graphfrag.GraphAlgoVersion`, `GraphAlgoVersionPython`, `GraphAlgoVersionRust`, `GraphAlgoVersionNode`, `GraphAlgoVersionGo`, `GraphAlgoVersionC`, `GraphAlgoVersionCPP`, `GraphAlgoVersionRuby` or `GraphAlgoVersionCSharp`),
   with a comment above the constant saying what changed. Tag reach and
   require the new tag in `go.mod`.
3. Record the new hashes:
   ```bash
   go test ./internal/graphalgoguard/ -run TestGraphAlgoVersionGuard -update
   ```
4. Add a changelog fragment naming the new id: stored graphs of that
   ecosystem will be mined again.

## The ids

| Id | Constant (in `github.com/scanoss/reach/graphfrag`) | Value today | Covers |
|---|---|---|---|
| Graph algorithm, Java and default | `GraphAlgoVersion` | `graph-algo-40` | Java and every ecosystem without its own id |
| Graph algorithm, C | `GraphAlgoVersionC` | `graph-algo-c-3` | C graphs |
| Graph algorithm, C++ | `GraphAlgoVersionCPP` | `graph-algo-cpp-4` | C++ graphs |
| Graph algorithm, Python | `GraphAlgoVersionPython` | `graph-algo-py-40` | Python graphs |
| Graph algorithm, Rust | `GraphAlgoVersionRust` | `graph-algo-rs-15` | Rust graphs |
| Graph algorithm, Node | `GraphAlgoVersionNode` | `graph-algo-node-13` | JavaScript and TypeScript graphs |
| Graph algorithm, Go | `GraphAlgoVersionGo` | `graph-algo-go-15` | Go graphs |
| Graph algorithm, Ruby | `GraphAlgoVersionRuby` | `graph-algo-rb-10` | Ruby graphs |
| Graph algorithm, C# | `GraphAlgoVersionCSharp` | `graph-algo-cs-2` | C# graphs |
| Graph-fragment schema | `SchemaVersion` | `graph-fragment-1.39` | The fragment wire format |
| Callgraph schema | `CallgraphSchemaVersion` / `CallgraphInternedSchemaVersion` | `6.14` / `6.18` | The `--export-callgraph` contract (inlined / interned frames) |
| Interim report format | `schema.InterimFormatVersion` (crypto-finder `pkg/schema`) | `1.9` | The findings report |

`graphfrag.GraphAlgoVersionFor(ecosystem)` returns the graph algorithm id of
an ecosystem; a fragment without an ecosystem reads as Java. Consumers
compare a stored graph with `GraphAlgoVersionForPurl(purl)`.

The values above are those of the reach version `go.mod` requires (v0.36.0
when this was written); the constants are the source of truth.

## When to bump

| Change | Bump |
|---|---|
| The structural graph of an ecosystem changes: functions, internal edges, external calls (and for Python and Node imports, Python exports and the Python-only sections; for Rust imports, items, constant refs, declarations and public type paths) | That ecosystem's graph algorithm id only |
| The fragment JSON gains, loses or redefines a field | `SchemaVersion` |
| The callgraph export contract changes | The callgraph schema version |
| Detection changes (ruleset, cards, OIDs, annotations) | None: annotations are recomputed against the cached structure |
| A crypto-finder release with no graph change | None |

Bump only the ecosystem that changed. A Java bump re-mines every stored Java
graph; a Python change must not cost that.

## The guard

`TestGraphAlgoVersionGuard` lives in crypto-finder, in the test-only package
`internal/graphalgoguard`, because it drives crypto-finder's scan. The ids
live in reach.

| Part | Location |
|---|---|
| Corpus: one application and one dependency per ecosystem (C, C++, Go, Java, Node, Python, Ruby, Rust; C# has none yet) | `internal/graphalgoguard/testdata/graph_algo_guard/<ecosystem>/{app,dep}` |
| Golden: per ecosystem, its id, the SHA-256 of its structural graph, and counts | `internal/graphalgoguard/testdata/graph_algo_guard.golden.json` |

What it hashes: the structural part of each fragment export (functions,
internal edges, external calls; for Python also imports, exports and the
Python-only sections; for Rust also imports, items, constant refs,
declarations and public type paths). Scan metadata, crypto annotations, supporting calls
and entry points are left out. Java is built without its bytecode type
resolver, whose output depends on the host JDK and `~/.m2`.

| Guard outcome | Meaning | Action |
|---|---|---|
| Pass | Ids and graphs equal the golden | None |
| Fail: "changed without a bump" | A graph changed while its ecosystem's id did not | Bump the named constant, then `-update` |
| Fail: "ids or graphs differ" | An id was bumped (with or without a graph change) and the golden is old | `-update`; if no graph changed, revert the bump instead, unless the PR explains it |
| `-update` refused | An ecosystem whose graph changed still has its old id | Bump first |

`-update -force` rewrites the golden without a bump. Use it only for an edit
to the guard's own fixtures, or a change the PR explains does not invalidate
cached graphs.

## Checklist for a PR that changes graph construction

- [ ] The guard passes after the bump and `-update`.
- [ ] Only the changed ecosystem's id moved.
- [ ] The constant's comment says what the new id changes.
- [ ] A changelog fragment names the new id.
- [ ] `go.mod` requires the reach tag that carries the bump (no `replace`).
