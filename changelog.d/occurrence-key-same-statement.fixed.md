- Two calls of the same API in one statement that spans lines, such as
  `a ? SSLContext.getInstance(p) : SSLContext.getInstance(p, q)`, no longer
  share an `occurrence_key`. The second call was matched to the first call's
  position, so both assets carried one key and one call graph. Each call now
  has its own key and finding graph. Only the keys of calls that collided
  change, and only the later call of each pair; every other `occurrence_key`
  is byte-identical. `finding_id` is unchanged: it hashes file, start line and
  rule, so such a pair still shares it and is told apart by
  `(finding_id, occurrence_key)`.
