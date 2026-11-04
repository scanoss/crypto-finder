- A library API entry point now keeps its rule's `parameterCondition` when the
  condition holds a `$`: a regex anchor (`param[0]:type~=^...AESEngine$`) or a
  literal (`"$y$"`). It was dropped as if it were an unbound Semgrep
  metavariable, so the entry point had no condition and every route to the API
  counted for every variant: the AES-CBC and Serpent-CBC entry points of
  BouncyCastle's `CBCBlockCipher` were both reachable through any CBC cipher.
