- `--export-graph-fragment` builds the fragment's call edges (`internal_edges_compact`,
  `external_calls`) on all CPU cores instead of one, and writes them without re-encoding
  each edge's call site. The fragment is byte-for-byte the one a single-threaded export
  writes, and memory stays bounded: edges are built a few hundred caller-callee pairs at
  a time, at most a few such batches per core ahead of the writer.
