- Reachability: a method called on a variable that holds what a factory
  function returns now reaches the method of the class that factory builds,
  when every return of the factory builds that one class (`return new
  Standard()` in Java and JavaScript, `return _Standard()` in Python, `return
  standard{}` or `&standard{}` in Go, `Box::new(Standard)` behind a
  `Box<dyn Trait>` in Rust). Go, Python, JavaScript and Rust used to leave such
  a call on an interface, trait or base-class result unlinked, so crypto behind
  it read unreachable; Java linked it to every implementation, so a factory
  that builds a harmless implementation read as reaching a crypto one. The
  call is now an `exact` edge to that class's method.
