- **BREAKING (default change):** `scan` and `annotate` now run OpenGrep in core
  mode by default (`--opengrep-mode core`): `opengrep-core` runs directly instead
  of the Python `opengrep` CLI. Findings are unchanged, and the scan still falls
  back to the CLI whenever core cannot run (an OpenGrep version core mode was not
  verified against, a missing `opengrep-core` binary, or a failed core run).
  Opt out with `--opengrep-mode cli` or `SCANOSS_OPENGREP_MODE=cli`. `annotate`
  gains the same `--opengrep-mode` flag, so its annotations keep matching
  `scan --export-graph-fragment`.
- Dependency findings cache keys change once: the OpenGrep mode is recorded in
  the key only when it is not `cli`, so keys written by earlier versions (CLI
  mode) no longer match. The first `--scan-dependencies` run after upgrading
  scans every dependency again with a cold cache; later runs hit the cache as
  before. Runs with `--opengrep-mode cli` keep using the existing entries.
