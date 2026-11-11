- Python scans now resolve an algorithm passed through a function parameter, a
  string local variable or a module-level string constant. A helper such as
  `def digest(data, alg): return hashlib.new(alg, data)` is reported with the
  algorithm each caller passes, also from another module and by keyword
  (`digest(alg="sha256", data=d)`), and a caller passing a dynamic value keeps
  the generic finding. Methods (`self`/`cls`) and keyword-only parameters are
  not resolved yet. Call-graph exports stamp `graph_algo_version`
  `graph-algo-20`; cached Python structural graphs from `graph-algo-19` are
  rebuilt.
