- Python call graph contracts for the standard library: `hashlib` (named
  constructors, `new`, `file_digest` and the hash-object protocol, including
  BLAKE2 and SHAKE), `hmac` (`new`, `HMAC`, `digest`, `compare_digest`),
  `ssl` (`SSLContext` factories, cipher, curve, certificate and trust
  configuration, `wrap_socket`/`wrap_bio`, and the `SSLSocket`/`SSLObject`
  handshake and peer-certificate calls), `secrets`, `os.urandom`/`getrandom`
  and `random.SystemRandom`. Calls on the objects these modules return are
  exported as supporting calls under the stdlib class with their lifecycle
  category, for example `_hashlib.HASH.digest` or `ssl.SSLContext.set_ciphers`.
  The `hashlib.pbkdf2_hmac` and `hashlib.scrypt` contracts now belong to the
  `python-stdlib-crypto` library.
  In the structural graph, a method chained on a stdlib call, such as
  `hashlib.sha256(d).hexdigest()`, now targets the stdlib class; a call through
  a local variable keeps its local target. `graphfrag.GraphAlgoVersion`
  `graph-algo-9` of this release covers this change, so a consumer that caches
  structural graphs under `scan_metadata.graph_algo_version` must re-mine. The
  wire schema is unchanged.
