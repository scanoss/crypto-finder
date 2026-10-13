- Call-graph construction is much faster on large dependency trees, with identical
  findings, reachability and exports. Go sources no longer re-read a whole function
  body for each name a callback API lookup resolves, and source files of all
  packages are parsed on one pool of workers (Go files one by one) instead of one
  package at a time. A `--scan-dependencies` scan of `smallstep/crypto`, whose
  dependencies include multi-megabyte generated Go files, drops from about 600 s to
  under 50 s of call-graph work on an 8-core host.
- `--export-graph-fragment` traces each finding's callers on all CPU cores before
  writing the fragment, which was single-threaded; the fragment is unchanged.
