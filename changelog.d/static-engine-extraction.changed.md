- The call graph, dependency resolution, rule prefilter, language detection and
  other engine packages now live in the `github.com/scanoss/static-engine`
  module, which crypto-finder imports. Scan output is unchanged. `pkg/failure`
  and `pkg/paramcondition` keep their import paths and now forward to the
  `github.com/scanoss/static-engine` packages of the same name; code importing
  `pkg/graphwalk` or `pkg/purl` moves to `github.com/scanoss/static-engine/graphwalk`
  and `github.com/scanoss/static-engine/purl`.
