- `scan` downloads the remote ruleset filtered to the target: it reads the
  target's sources once, sends the SCANOSS API the languages they have files
  of and the ruleset libraries they use (never the project's import list or
  file names), and receives only the rules that can match. Each filtered
  ruleset is cached under `rulesets/<name>/profiles/<version>/<profile hash>/`
  with the TTL of the full ruleset, and the interim report's `rules.profile`
  names the profile. Any failure of the index or filter request falls back
  to the full ruleset with a warning. `--scan-dependencies` and
  `--rule-prefilter off` keep the full download, as does the new
  `--no-remote-filter` flag (or `SCANOSS_NO_REMOTE_FILTER=1`).
