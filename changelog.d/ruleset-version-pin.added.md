- `scan` and `annotate` accept `--ruleset-version` to fetch a specific release of the
  remote ruleset (for example `--ruleset-version v1.39.0`) instead of `latest`, so a scan
  can be rerun later with identical rules. The default stays `latest`. The version in the
  report's `rules` block is still the concrete release that was used. The flag cannot be
  combined with `--no-remote-rules`, and anything other than `latest` or a release
  version is rejected.
