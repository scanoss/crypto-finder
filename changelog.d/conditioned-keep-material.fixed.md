- A related-crypto-material asset (for example `materialType: private-key`) reported on the
  same call as an algorithm asset specialized for its resolved argument value is no longer
  dropped when a call graph is built (`--export-callgraph`, `--export-graph-fragment`,
  `--scan-dependencies`). Scans with and without a call graph now report the same material.
