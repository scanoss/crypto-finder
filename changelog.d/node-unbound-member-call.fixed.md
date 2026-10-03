- JavaScript and TypeScript call graph: a member call on a chained or
  unresolved receiver, such as `crypto.createHash('md5').update(x).digest('hex')`
  or `param.digest()`, is no longer bound to a module function of the same name.
  That false edge made unrelated functions appear as callers of the function.
  A call on an inline `require('./x')` receiver, such as
  `require('./x').digest(v)`, now binds to the function the required module
  declares, as an import binding does, instead of to a function of the calling
  file.
  `graphfrag.GraphAlgoVersion` is now `graph-algo-7` (was `graph-algo-6`): the
  structural graph of a Node scan loses those edges, so a consumer that caches
  structural graphs under `scan_metadata.graph_algo_version` must re-mine. The
  wire schema is unchanged.
