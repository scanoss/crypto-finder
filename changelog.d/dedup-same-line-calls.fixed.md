- `scan` no longer merges two calls on one line into one asset when the same rule matches
  both, side by side (`a = f(x); b = f(y)`) or nested
  (`bcrypt.hashpw(pw, bcrypt.gensalt())`). The deduplicator now reads the match columns:
  matches merge only when their spans overlap and no rule matched them at two different
  spans. Matches without columns are still grouped by line, and different rules that
  report one call are still merged into one asset.
- `finding_id` is now unique within a file's findings. When one rule reports two assets on one
  line, the first in source order keeps the id it always had. The others get an id that also
  hashes their columns. Before, every such asset shared one id, so joins on `finding_id`
  (callgraph and graph-fragment exports, `annotate`) mixed them up. Ids that were already
  unique do not change.
