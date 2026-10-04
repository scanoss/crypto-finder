- `scan` and `annotate` keep the results of the `opengrep --version` and
  `opengrep scan --help` checks under `~/.scanoss/crypto-finder/cache/opengrep-probes`,
  so a later run of the same OpenGrep binary skips them (about 1.5 s per run).
  Entries are keyed by the binary's path, size, modification time and
  contents, so an updated or replaced binary is checked again, and an
  unusable entry or cache directory falls back to running the checks.
- A scan parses each rule file once while loading rules and once for the rule
  graph passes, instead of twice each, which saves about 0.5 s per run
  with the default ruleset. Output is unchanged.
