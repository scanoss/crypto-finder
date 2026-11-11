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
  local is rebound or has a member written. A property read such as `h.alg`
  and a `get` accessor stay unresolved.
