- Java and Python scans now resolve an algorithm read through a getter of a
  field the constructor sets: `Signature.getInstance(new Holder("SHA256withECDSA").getAlg())`
  and `hashlib.new(Holder("sha256").get_alg())` are reported with the
  constructor's argument, also when the class is declared in another file or
  module, when the receiver is a local bound once to the construction, and
  through a helper's parameter. A Java enum constant's getter or `toString()`
  that returns such a field gives the constant's argument:
  `AlgoName.ECDSA.getValue()` for `ECDSA("SHA256withECDSA")`. The getter must
  have one return statement, returning the field itself; in Python that
  statement is the whole body, and the class must be imported into the calling
  module. The value is dropped when anything other than one constructor
  assignment writes the field (a setter, another method, a second constructor,
  a Java field that is neither `private` nor `final`, `setattr` in the Python
  class), when the receiver local is rebound or has an attribute written in the
  same function, when the constructed class overrides or only inherits the
  getter, or when the enum constant's body overrides it. A Python `@property`
  and a direct attribute read such as `h.alg` stay unresolved. Call-graph
  exports stamp `graph_algo_version` `graph-algo-22`; cached Java and Python
  structural graphs from `graph-algo-21` are rebuilt.
