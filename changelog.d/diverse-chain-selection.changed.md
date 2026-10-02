- When a finding has more routes than the chain budget
  (`--export-callgraph-max-chains`), the kept `call_chains` now show distinct
  routes of every evidence tier before variants: tier by tier, one route per
  chain root and one route through each library whose sequence of libraries no
  kept chain shows, then further routes. The first chain is still the
  strongest route. On a Java project with 2,674 dependency findings at a
  budget of 4, the chains of reachable findings now cross 493 distinct library
  paths (213 before; a budget of 32 showed 412) and start at 261 distinct roots
  (224 before), with the same verdicts, a 68.5 MB export (66.7 MB before) and
  no slower export. Routes through each library are built from the graph, not
  found by enumerating routes, so findings with very many routes cost no more.
