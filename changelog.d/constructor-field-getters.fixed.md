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
  assignment writes the field: a setter, another method, a second constructor,
  an initializer block, a nested, inner or anonymous class or a lambda, or a
  write through another reference such as `h.alg = "MD5"` or
  `Holder.this.alg = ...` anywhere in the declaring Java file; a Java field
  that is neither `private` nor `final`; `setattr` in the Python class. A
  Python class with a base other than `object`, a decorator, a class attribute
  or property named like the field, its own `__new__`, `__setattr__`,
  `__delattr__` or `__getattribute__`, or a method that passes, returns or
  stores `self` gives no value either. A Python receiver local resolves only
  when every use of it in the function is a direct method call such as
  `h.get_alg()`: passed to a helper, aliased, returned, stored, captured by a
  nested function or lambda, or used in `with`, it gives no value. The value is
  also dropped when the receiver local is rebound, when the constructed class
  overrides or only inherits the getter, or when the enum constant's body
  overrides it. A Python `@property` and a direct attribute read such as
  `h.alg` stay unresolved. Not covered: a class patched from another module
  (`Holder.get_alg = ...` or a replaced `__init__`), or a field written by
  reflection (Java `Field.set`, Python `gc` or `ctypes`), still reads as the
  constructor's argument. Call-graph
  exports stamp `graph_algo_version` `graph-algo-22`; cached Java and Python
  structural graphs from `graph-algo-21` are rebuilt.
