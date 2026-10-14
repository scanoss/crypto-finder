- The Docker images (`crypto-finder`, `crypto-finder-deps` and the test image) now
  ship OpenGrep 1.30.2 instead of 1.12.1, the version the default `--opengrep-mode
  core` is verified against, and unpack its `opengrep-core` at build time, so the
  first scan in a fresh container runs in core mode instead of falling back to the
  CLI. Findings may differ from those of OpenGrep 1.12.1 where the engine's matching
  changed between the two releases. Dependency findings cache keys include the
  engine version and executable, so the first `--scan-dependencies` run on the new
  images scans every dependency again with a cold cache. The install hints now name
  v1.30.2; the minimum supported version stays 1.12.1, and the CLI mode keeps
  working with it.
