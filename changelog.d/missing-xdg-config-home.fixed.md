- `scan` no longer fails with `scanner_initialization_failed` when
  `XDG_CONFIG_HOME` names a directory that does not exist, as in a fresh or
  sandboxed environment. crypto-finder now creates that directory before it
  runs opengrep, which exits at startup without it.
