- The stitched callgraph export now carries `root_kind` on the first frame of
  each chain and `analysis.no_callers_only` on each finding, with the meaning
  they have in the live export. A root reads `main` or `framework_entry` when
  the scan that produced the fragment recognized it as an entry point, and
  `no_callers` when it did not and nothing in the stitched graph calls it.
  `no_callers_only` is `true` when every root that reaches the finding is a
  `no_callers` root. The graph-fragment export records this: the schema is now
  `graph-fragment-1.14`, with `entry_kind` on the functions a scan recognized as
  entry points and `scan_metadata.entry_kinds` saying the scan recorded them. A
  fragment from an earlier version (or one re-encoded without entry kinds)
  still loads and stitches with the same verdicts, but its roots carry no
  `root_kind` and its findings never claim `no_callers_only`, since a framework
  entry the scan could not mark would otherwise read as `no_callers`.
- `graphfrag.GraphAlgoVersion` is now `graph-algo-7` (was `graph-algo-6`): the
  structural graph now holds each function's entry kind. A consumer that caches
  structural graphs under `scan_metadata.graph_algo_version` must re-mine to get
  `root_kind` and `no_callers_only` on the stitched export.
