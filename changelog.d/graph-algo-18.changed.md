- `scan_metadata.graph_algo_version` is `graph-algo-18`: Python functions
  registered as handlers by a Flask, FastAPI or Starlette call carry
  `entry_kind: framework_entry` in the structural graph and graph fragment. A
  Python structural graph cached under `graph-algo-17` lacks it.
