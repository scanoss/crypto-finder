- Graph fragments and call-graph exports stamp `graph_algo_version` `graph-algo-19`. A Rust
  function whose parameters name a lifetime (`fn f<'a>(key: &'a [u8], iv: &'a [u8])`) now has one
  parameter per declaration in `parameter_types`; the lifetime used to swallow the rest of the
  list into a single parameter. Go and Rust parameters also carry their names, so a Go wrapper
  that forwards its parameter to an interface call can gain the pass-through dispatch edge Java
  and Python graphs already had. Structural graphs cached under `graph-algo-18` should be rebuilt.
