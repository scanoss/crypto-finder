# Keep the 128 call_chains default; live UIs opt in to a small N

Live `--export-callgraph` and served stitch both keep a default `call_chains`
sample of 128. A live dependency scan that only needs a composed route opts in
to 8 (or 1) through the existing knob. `crypto_entry_points` stays the complete
reverse-reach set at any N.

Issue: [#335](https://github.com/scanoss/crypto-finder/issues/335).
Knob: `--export-callgraph-max-chains` / `StitchOptions.MaxChains` ([#334](https://github.com/scanoss/crypto-finder/issues/334)).

## Decision

| Surface | Default N | How a client asks for a smaller sample |
|---|---|---|
| CLI live `--export-callgraph` | **128** when `--export-callgraph-max-chains` is omitted | `--export-callgraph-max-chains 8` (recommended for a live UI that needs a composed route through dependencies). `1` is valid for a single route. |
| Served / stitched API in this repo | **128** when `StitchOptions.MaxChains` is zero or omitted | Pass `StitchOptions.MaxChains` with the same N the live scan used. |

This repo has no HTTP query parameter for the budget. If a wrapping service
exposes one, that mapping is a follow-up on [#336](https://github.com/scanoss/crypto-finder/issues/336),
not a silent change of the stitch default here.

Do not change `graphfrag.DefaultMaxChainsPerOp` until a later issue amends this
ADR. Schema 6.x clients that omit the knob must keep seeing 128-long samples.

## Non-goals

- Do not drop `call_chains` from the schema 6.x body.
- Do not change `canonical_signature` spelling.
- Do not fold `crypto_entry_points` through the chain budget. The index is who
  reaches crypto. The sample is which walks to print.

## Consequences

- Live UI scans of a tree with little or no first-party crypto can pass
  `--export-callgraph-max-chains 8` today, without a schema bump, and still join
  LIB A → LIB B → LIB C through the entry-point index.
- Mined / served clients that query `purl@version` and stitch on
  `canonical_signature` keep the 128-sample until they opt in. The join is the
  index. Traces stay a sample. `entry_point_signatures` already exists so a
  later stitch change can spend that sample on the named method.
- `#336` may wire N through stitch callers. It must not shrink the served
  default below 128.
