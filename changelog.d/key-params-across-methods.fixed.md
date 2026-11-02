- The callgraph export lost the key size or curve when a key generator was
  created in one method and configured in another. A size passed as an
  argument (`genKey("RSA", 4096)` into `kpg.initialize(size)`, or a curve name
  into `new ECGenParameterSpec(curve)`) now resolves as `resolved_key_length`
  when every call site passes the same literal or constant; call sites that
  disagree still report no size. A generator returned by a helper
  (`KeyPairGenerator kpg = newKpg(); kpg.initialize(2048)`) now gets the
  caller's configuration calls as supporting calls of the finding that created
  it, with their resolved size. Parameters are followed through at most four
  calls and returned objects through at most three helpers. The
  `annotate` command, which re-derives supporting calls from a cached graph
  fragment, does not follow returned objects yet.
