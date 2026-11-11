- Rust: a crypto operation written as a binary operator is no longer dropped when
  one of its operands is a call to the scanned program's own function. A
  curve25519-dalek ristretto255 key agreement such as `secret * decode(&peer)`
  now reports its key agreement and shared secret: the filter that drops a crate
  rule's match on the program's own type no longer takes `decode` for the matched
  operation, because the call starts after the match does.
