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
  which reads each rule's `metadata.crypto` block as before. Findings JSON and
  CycloneDX output are unchanged; the call graph and graph fragment change only
  by the visibility fields described below.
- `scan --format raw` writes the engine's domain-agnostic RAW report
  (`raw-1.0`): one entry per finding with its file, rule, location, purl,
  reachability (`unknown` for now) and the rule's `metadata.crypto` values.
- Go, Rust and Node functions in the call graph export and the graph fragment
  now carry `visibility` and, for a member of a type, class or object,
  `owner_visibility`, as Java and Python functions already did. In Go an
  exported name is `public` and any other `package-private`; in Rust `pub` is
  `public`, `pub(crate)`, `pub(super)` and `pub(in path)` are
  `package-private` and no modifier is `private`; in Node a function its module
  exports is `public`. The stitcher reads them to keep a public member of a
  public owner as a consumer entry point. The graph algorithm version is now
  `graph-algo-16` (from `graph-algo-15`), so cached structural graphs are
  rebuilt; re-mine Go, Rust and Node components to get the new fields.
- The contracts knowledge base (the per-ecosystem YAML that tells the call
  graph what crypto library calls return) moves out of static-engine, which
  now ships none, into crypto-finder (`internal/contracts`). crypto-finder
  embeds it and registers it with the engine at startup. Scan output is
  unchanged.
