- A scan whose timeout expires, or that is interrupted with Ctrl-C, while
  OpenGrep rule timeouts are being retried now fails with the scanner timeout
  or cancellation error, as it does when the first run is stopped, instead of
  reporting the pre-retry findings as a successful scan. Dependency batch scans
  therefore see the failure and fall back to scanning the dependencies one by
  one, or fail them all on cancellation, rather than caching a cut-short report.
- A file OpenGrep timed out on keeps its timeout, and the report lists it under
  `incompleteFiles`, when the retry's output does not list the file among its
  scanned paths or name it in a result or an error (OpenGrep skipped it). Such
  a file was reported complete before, so a truncated report could be cached.
- `--exclude` patterns written relative to the working directory that name a
  directory below the scan target (`crypto-finder scan ./proj --exclude
  proj/vendor`) exclude it again. Since 0.36.2 scans run in the target
  directory over relative paths, which left such patterns matching nothing.
