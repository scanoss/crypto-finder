- A library API entry point whose rule carries a `parameterCondition` (the
  3DES-CBC variant of BouncyCastle's `CBCBlockCipher(BlockCipher)`, for
  example) now keeps only the routes whose call into the API passes a matching
  argument. Before, every route to the API counted, so a CBC cipher built over
  AES in one library made the 3DES variant reachable. A type condition is read
  from the class the argument was constructed as (`new DESedeEngine()`); an
  argument whose class is not known still never drops a route.
