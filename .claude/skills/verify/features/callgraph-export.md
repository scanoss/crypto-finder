# Call graph and graph fragment export

`scan --export-callgraph <file>` writes the crypto-scoped call graph that partners consume: one `finding_graphs[]` entry per finding with its reachability, dependency attribution and sampled call chains, plus `scan_metadata`. `--export-graph-fragment <file>` writes the reusable structural fragment (functions, edges, crypto annotations) that `annotate` and stitching consume. Both carry a `schema_version` that external tooling keys on.

## Sub-features

- `cg-schema-6.18` is the default: interned frames, with `call_chain_indexes` into `functions[]` and frames without inline identity.
- `cg-schema-6.14` comes with `--export-callgraph-interned-frames=false`: frames inline their `function_name`.
- `cg-coverage` gives every `finding_id` in the report a `finding_graphs[]` entry, and every reachable entry a chain with in-range indexes.
- `cg-chain-route` makes the transitive chain start at `example.com/transapp.main` and end in `example.com/translibb`.
- `cg-max-chains` caps the chains per finding with `--export-callgraph-max-chains N`.
- `cg-entry-points` adds `crypto_entry_points` with `--export-callgraph-entry-points`, and leaves it absent by default.
- `fragment-schema` gives the graph fragment `schema_version` `graph-fragment-1.15`, with functions, edges and crypto annotations.
- `cg-key-params` resolves `supporting_calls[].supporting_call.resolved_key_length` for a Java `KeyPairGenerator` whose size or curve is fixed in another method: a parameter every caller fills with the same constant, and a generator a helper returns to a caller that initializes it.
- `annotate-key-params` makes `annotate --import-fragment` re-derive the same key sizes from the scan's graph fragment, the returned generator included, through `functions[].returns_calls`.

## How to get to it (user POV)

- `crypto-finder scan ... --export-callgraph callgraph.json [--export-graph-fragment fragment.json] <target>`
- Flags: `--export-callgraph-interned-frames=false`, `--export-callgraph-max-chains N` (default 8), `--export-callgraph-entry-points`, `--export-callgraph-project-reachability` (see `reachability-project.md`).

## Driving it with run.sh

This feature has no drive in this version. The 0.54.0 drive (OpenGrep, non-Java fixtures) was removed. A new drive for this version is to be written against the cards engine.

## Gotchas

- `scan_metadata.function_count` counts the whole crypto-scoped graph, while `functions[]` holds only the frames the chains reference. They differ by design, so do not assert equality.
- The 6.14 export still carries `call_chain_indexes` next to the inlined `call_chains`. Tell the schemas apart by `schema_version` and frame identity, not by which key exists.
- Chains are sampled, not complete: the budget defaults to 8 per finding and depth is capped at 32. "No chain through X" with `--export-callgraph-max-chains 1` can be the budget, not a reachability bug.
- The key-size check prints `none` for a finding whose supporting calls carry no bits, or carry two different ones. It reads bits only through `supporting_call_ids`, the join consumers use.
- The partner-facing schema versions are independent of the KB YAML schema `"2"`. Do not confuse them. A version bump here is a changelog-worthy contract change.

## Code paths

- `internal/cli/scan.go`
- `internal/cli/annotate.go`
- `internal/scan/annotate*.go`
- `internal/scan/fragment_export.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `internal/scan/key_length*.go`
- `internal/scan/supporting_calls.go`
- `internal/scan/returned_object_lifecycle.go`
- `pkg/appreach/findings_envelope.go`
