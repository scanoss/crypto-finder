- `scan` no longer reports a truncated algorithm name such as `ECDH-`, `ML-KEM-` or
  `PBKDF2---32` when a rule's metadata template references a metavariable or capture
  group that did not bind on the match. The field whose template stayed unresolved is
  left out of the asset instead (the rest of the rule metadata, such as
  `algorithmFamily`, is kept), and a `parameterCondition` keeps a `$` reference that
  does not bind as written instead of losing it.
