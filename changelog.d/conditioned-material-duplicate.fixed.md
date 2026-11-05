- `scan` with a call graph (`--export-callgraph`, `--export-callgraph-project-reachability`,
  `--scan-dependencies`) no longer reports a related-crypto-material asset twice on one call,
  once as the rule's own match (with its `parameterCondition` pattern) and once as the
  per-value asset with `conditioned_value` (for example `param[0]==RSA` on
  `KeyPairGenerator.getInstance("RSA", "BC")`). As for algorithm assets, the per-value asset
  now replaces the rule's match when both name the same material type and algorithm, also
  when the rule file sits at the rules root and the match carries the bare rule id.
