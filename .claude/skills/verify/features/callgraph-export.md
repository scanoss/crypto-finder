# Call graph and graph fragment export

`scan --export-callgraph <file>` writes the crypto-scoped call graph that partners consume: one `finding_graphs[]` entry per finding with its reachability, dependency attribution and sampled call chains, plus `scan_metadata`. `--export-graph-fragment <file>` writes the reusable structural fragment (functions, edges, crypto annotations) that `annotate` and stitching consume. Both carry a `schema_version` that external tooling keys on.

## Sub-features

- `cg-schema-6.18` is the default: interned frames, with `call_chain_indexes` into `functions[]` and frames without inline identity.
- `cg-schema-6.14` comes with `--export-callgraph-interned-frames=false`: frames inline their `function_name`.
- `cg-coverage` gives every `finding_id` in the report a `finding_graphs[]` entry, and every reachable entry a chain with in-range indexes.
- `cg-chain-route` makes the transitive chain start at `example.com/transapp.main` and end in `example.com/translibb`.
- `cg-max-chains` caps the chains per finding with `--export-callgraph-max-chains N`.
- `cg-entry-points` adds `crypto_entry_points` with `--export-callgraph-entry-points`, and leaves it absent by default.
- `fragment-schema` gives the graph fragment `schema_version` `graph-fragment-1.14`, with functions, edges and crypto annotations.

## How to get to it (user POV)

- `crypto-finder scan ... --export-callgraph callgraph.json [--export-graph-fragment fragment.json] <target>`
- Flags: `--export-callgraph-interned-frames=false`, `--export-callgraph-max-chains N` (default 8), `--export-callgraph-entry-points`, `--export-callgraph-project-reachability` (see `reachability-project.md`).

## Driving it with run.sh

Preconditions:

- `doctor.sh` reports `lang go: ready`.
- Fixture `testdata/projects/transitive_reachability/go` scanned with `--scan-dependencies`, using `testdata/rules/transitive-reachability.yaml`.

- **Drive it.** Run `.claude/skills/verify/scripts/run.sh callgraph-export`. It exits 0, and `evidence/callgraph-export/verdict.txt` reads `VERDICT: PASS`.
- **Default export plus fragment.** `scan ... --export-callgraph callgraph.json --export-graph-fragment graph-fragment.json` exits 0, with these results:
  - `callgraph.json` has `schema_version: "6.18"`;
  - `scan_metadata` reads `tool_name: crypto-finder, ecosystem: go, root_module: example.com/transapp`, with non-zero `function_count`/`edge_count`;
  - frames carry no `function_name`;
  - the report's finding ids equal the graph's finding ids;
  - every reachable graph has in-range `call_chain_indexes`;
  - one libb chain runs from `example.com/transapp.main` to `example.com/translibb`;
  - there is no `crypto_entry_points`.
- **Fragment.** `graph-fragment.json` has `schema_version: "graph-fragment-1.14"`, plus non-empty `functions`, edges and `crypto_annotations`.
- **Legacy and options.** `--export-callgraph-interned-frames=false --export-callgraph-entry-points --export-callgraph-max-chains 1` exits 0, with these results in `callgraph-6.14.json`:
  - `schema_version` is `"6.14"`;
  - every frame of a reachable chain has `function_name`;
  - no finding has more than one chain;
  - `crypto_entry_points` is present.

## Gotchas

- `scan_metadata.function_count` counts the whole crypto-scoped graph, while `functions[]` holds only the frames the chains reference. They differ by design, so do not assert equality.
- The 6.14 export still carries `call_chain_indexes` next to the inlined `call_chains`. Tell the schemas apart by `schema_version` and frame identity, not by which key exists.
- Chains are sampled, not complete: the budget defaults to 8 per finding and depth is capped at 32. "No chain through X" with `--export-callgraph-max-chains 1` can be the budget, not a reachability bug.
- The partner-facing schema versions are independent of the KB YAML schema `"2"`. Do not confuse them. A version bump here is a changelog-worthy contract change.

## Code paths

- `internal/cli/scan.go`
- `internal/scan/export.go`
- `internal/scan/export_ecosystems.go`
- `pkg/graphfrag/callgraph_export.go`
- `pkg/graphfrag/export.go`
- `pkg/graphfrag/intern_functions.go`
- `pkg/graphfrag/encode.go`
- `pkg/graphfrag/model.go`
- `pkg/graphfrag/findings_envelope.go`
- `pkg/graphfrag/stitch*.go`
