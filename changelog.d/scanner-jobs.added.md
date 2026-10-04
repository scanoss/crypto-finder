- `scan --scanner-jobs <n>` (or the `SCANOSS_SCANNER_JOBS` environment
  variable) sets the parallel jobs of the primary scan's OpenGrep process.
  The default `0` keeps OpenGrep's own default of one worker per detected
  core, the flag wins over the variable, and a `--jobs` passed to the scanner
  directly still wins over both. Set it when several scans share a host: with
  8 concurrent scans on 16 cores, `--scanner-jobs 2` used about a fifth of the
  CPU, finished about three times sooner, and kept findings that the default
  lost to OpenGrep rule timeouts. Findings and cache keys do not change.
