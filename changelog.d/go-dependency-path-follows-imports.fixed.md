- `scan --scan-dependencies`: a Go dependency's `dependency.path` in the callgraph export now
  follows imports. Each step is the module whose packages import the next one. Before, the
  path followed the module requirement graph, where a `go.mod` lists, `// indirect`, modules
  only its dependencies import, so for app -> liba -> libb -> libc the path to libc read
  `[liba, libc]` (distance 2) instead of `[liba, libb, libc]`.
