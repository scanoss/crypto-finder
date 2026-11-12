- Rulesets cached as plain rule files by earlier crypto-finder versions are
  never loaded as rules, not even as stale cache. On the first run
  crypto-finder warns `Ignoring a ruleset cached by an older crypto-finder;
  downloading it again`, downloads the ruleset from `/v3/rulesets` and, only
  once that download succeeds, replaces the old cache directory. When the
  download fails, the old directory is left as it is, unused, and the scan
  fails with the download error. Only the remote ruleset cache
  (`~/.scanoss/crypto-finder/cache/rulesets`) is affected; `--rules-dir`
  directories are never touched. The `/v2/cryptography/rulesets` endpoint is
  no longer used.
