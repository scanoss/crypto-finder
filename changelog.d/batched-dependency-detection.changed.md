- `--scan-dependencies` now scans the dependencies the findings cache does not
  hold in batches: each dependency worker runs one OpenGrep process over
  several dependency source roots instead of one process per dependency, so
  the rules load once per batch instead of once per dependency. Cache lookups
  and cache writes stay per dependency, and a dependency whose scan stopped at
  a time or memory limit is still reported and left uncached on its own. Each
  dependency's findings, finding IDs and provenance are the ones a scan of
  that dependency alone produces; a batch never holds a root nested under
  another of its roots, so an npm dependency's nested `node_modules` exclusion
  never hides another dependency. Batches hold at most 16 roots, are balanced
  by source bytes so the workers finish together, give a very large dependency
  a process of its own, and get the single-scan `--timeout` once per
  ceil(roots / jobs). When a batch's process fails, times out or returns
  unreadable output, its dependencies are scanned one by one, so one faulty
  dependency fails only itself. A single dependency and the primary project
  scan are unchanged.
