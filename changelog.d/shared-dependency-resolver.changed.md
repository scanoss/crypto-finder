- `finding_graphs[].dependency.relationship` and `.path` in the callgraph export now come from the
  dependency graph of scanoss.go's shared resolver, the one Earnie uses: the project's lockfile for
  npm, Cargo, Poetry and uv, and the `go` and `mvn` tools for Go modules and Maven projects. A Go
  module that `go.mod` marks `// indirect` is now `transitive`, with its route, instead of `direct`.
  In a multi-module Maven project each module's declared dependencies are `direct`, and findings in
  dependencies that carried no `relationship` now carry one. Where the shared resolver records no
  edges (pip without a lockfile, Gradle, npm without a lockfile) the previous graph is used.
- Building crypto-finder from source requires Go 1.26.
