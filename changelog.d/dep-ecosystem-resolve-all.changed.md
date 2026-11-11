- `--scan-dependencies` with `--dep-ecosystem auto` now resolves the
  dependencies of every ecosystem the target has a manifest for, not only the
  first. A repository with a `package.json` and `package-lock.json` beside a
  `requirements.txt` reports the dependency findings of both Node and Python.
  The first ecosystem, the dominant language by file count first, stays the
  primary one that `scan_metadata.ecosystem` of the call-graph export names;
  each other resolved ecosystem gets a dependency-aware call graph, its
  dependency findings carry their `dependency` block, chains and reachability
  in the export as the primary ecosystem's do, and its entry in
  `scan_metadata.ecosystems` counts its dependencies' functions and edges.
  The export schema version is unchanged. An ecosystem whose call graph
  cannot be set up is skipped and the others are still resolved; a failed
  dependency scan of any ecosystem still fails the phase. An explicit
  `--dep-ecosystem` resolves that ecosystem alone, as before. The graph
  fragment (`--export-graph-fragment`) still covers the primary ecosystem
  only.
- The completed `dependencies` event of `--progress` sums its counters and
  outcome lists over every resolved ecosystem, and carries two new fields:
  `ecosystems`, the resolved ecosystems with the primary first, and
  `ecosystems_skipped`, the ecosystems seen but not resolved, each as
  `{"ecosystem": "node", "reason": "lockfile_absent"}`, written `[]` when
  there are none. The nested `callgraph` events repeat once per resolved
  ecosystem that has dependencies. The progress schema stays at version `1`.
