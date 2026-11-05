- `occurrence_key` no longer gives two calls the same key when one rule matched both and the
  call graph could not tell the matches apart, for example the two `SSLContext.getInstance`
  calls of `provider == null ? SSLContext.getInstance(p) : SSLContext.getInstance(p, provider)`
  in a dependency report whose lines do not hold those calls in the local source. The first
  match in source order keeps the key it had; each later match of that rule gets the next
  `-N` suffix. Consumers that key findings on `occurrence_key` and the rule id no longer drop
  one of the calls. Keys that were not shared by two matches of one rule do not change.
