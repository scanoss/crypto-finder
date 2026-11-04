- The call graph, dependency resolution, rule prefilter, language detection and
  other engine packages now live in the `github.com/scanoss/static-engine`
  module, which crypto-finder imports. Scan output is unchanged. `pkg/failure`
  and `pkg/paramcondition` keep their import paths and now forward to the
  `github.com/scanoss/static-engine` packages of the same name; code importing
  `pkg/graphwalk` or `pkg/purl` moves to `github.com/scanoss/static-engine/graphwalk`
  and `github.com/scanoss/static-engine/purl`.
- The scan pipeline, rules loader, scanner adapters, findings writers and CBOM
  converter also move to `github.com/scanoss/static-engine`. Scan output is
  unchanged. `pkg/graphfrag` and `pkg/schema` keep their import paths and now
  forward to `github.com/scanoss/static-engine/graphfrag` and
  `github.com/scanoss/static-engine/schema`; `pkg/graphfrag/equiv` moves to
  `github.com/scanoss/static-engine/graphfrag/equiv`.
- The engine is domain-agnostic: crypto-finder runs it with the crypto domain,
  which reads each rule's `metadata.crypto` block as before. Findings JSON,
  CycloneDX, call graph and graph fragment output are unchanged.
- `scan --format raw` writes the engine's domain-agnostic RAW report
  (`raw-1.0`): one entry per finding with its file, rule, location, purl,
  reachability (`unknown` for now) and the rule's `metadata.crypto` values.
