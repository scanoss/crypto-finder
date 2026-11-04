- The call graph, dependency resolution, rule prefilter, language detection and
  other engine packages now live in the `github.com/scanoss/static-engine`
  module, which crypto-finder imports. Scan output is unchanged. `pkg/failure`
  keeps its import path and now forwards to `github.com/scanoss/static-engine/failure`;
  code importing `pkg/graphwalk` or `pkg/purl` moves to the
  `github.com/scanoss/static-engine` packages of the same name.
