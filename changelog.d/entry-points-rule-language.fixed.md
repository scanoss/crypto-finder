- Library entry points now take their crypto metadata only from rules of the
  scanned package's language. Previously a Rust rule could tag npm
  `jsonwebtoken` findings with `pkg:cargo/jsonwebtoken`.
