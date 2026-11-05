- `scan` no longer merges two calls on one line into one asset when the same rule matches
  both, side by side (`a = f(x); b = f(y)`) or nested
  (`bcrypt.hashpw(pw, bcrypt.gensalt())`). The deduplicator now reads the match columns:
  matches merge only when their spans overlap and no rule matched them at two different
  spans. Matches without columns are still grouped by line, and different rules that
  report one call are still merged into one asset.
