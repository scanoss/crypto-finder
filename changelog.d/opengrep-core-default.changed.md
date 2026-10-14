- **BREAKING (default change):** `scan` and `annotate` now run OpenGrep in core
  mode by default (`--opengrep-mode core`): `opengrep-core` runs directly instead
  of the Python `opengrep` CLI. Findings are unchanged, and the scan still falls
  back to the CLI whenever core cannot run (an OpenGrep version core mode was not
  verified against, a missing `opengrep-core` binary, or a failed core run).
  Opt out with `--opengrep-mode cli` or `SCANOSS_OPENGREP_MODE=cli`. `annotate`
  gains the same `--opengrep-mode` flag, so its annotations keep matching
  `scan --export-graph-fragment`.
- Dependency findings cache keys change once, in every OpenGrep mode: the key
  now records the engine that runs, the dependency's place in its package store
  and an allowlist of environment variables, and core-mode keys also record the
  mode. Entries written by earlier versions no longer match, including for
  `--opengrep-mode cli`, so the first `--scan-dependencies` run after upgrading
  scans every dependency again with a cold cache; later runs hit the cache as
  before.
