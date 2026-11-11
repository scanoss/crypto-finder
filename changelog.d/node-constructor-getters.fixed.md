- JavaScript and TypeScript scans now resolve an algorithm read through a
  getter of a field the constructor sets from a parameter:
  `crypto.createHash(new Holder("sha256").getAlg())` is reported as `sha256`,
  also for a `#private` field, when the receiver is a local bound once to the
  construction, when the class is imported by name from another project
  module, and through a helper's parameter. The getter's body must be
  `return this.field`. The value is dropped when the class extends another,
  when another method, a field initializer or `Object.assign(this, ..)`
  writes the field, when the file reassigns a member of the class, when a
  static or accessor member shares the getter's name, and when the receiver
  local is rebound or has a member written. It is also dropped when any code
  in the declaring file writes a property of that name through another
  reference (`h.alg = ..` or `h["alg"] = ..`, a static method's parameter or
  a static block's local included), and when the class uses `this` other than
  to reach a member, for example `return this` or `registry.push(this)`. A
  receiver local resolves only when every use of it in the function is a
  direct method call such as `h.getAlg()`: passed to a helper, aliased,
  returned, stored, captured by a closure, or a method taken as a value, it
  gives no value. A property read such as `h.alg` and a `get` accessor stay
  unresolved. Not covered: a computed write such as `o[key] = v` on an object
  reached through a module-level binding, or a class patched from another
  module, still reads as the constructor's argument.
