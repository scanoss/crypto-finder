- When a finding has more routes than the chain budget
  (`--export-callgraph-max-chains`), the kept `call_chains` now prefer routes
  through different sequences of libraries before further variants of a kept
  sequence. On a Java project at a budget of 4, the chains of reachable
  findings showed 213 distinct library paths where a budget of 32 showed 412;
  verdicts do not change and the output stays the same size. Routes are looked
  for within a bounded scan, so findings with a very large number of routes
  cost no more to export.
