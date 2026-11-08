- Graph fragments and call-graph exports stamp `graph_algo_version` `graph-algo-19`: Go and
  Rust function parameters now carry their names, so a Go or Rust wrapper that forwards its
  parameter to an interface or trait call can gain the pass-through dispatch edge Java and
  Python graphs already had. Structural graphs cached under `graph-algo-18` should be rebuilt.
