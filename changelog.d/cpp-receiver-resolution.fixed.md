- C++ calls on a variable declared `auto` (including `const auto&` and `auto x{...}`) now resolve
  to the type the producing call returns according to the callgraph contracts, so
  `auto h = Botan::HashFunction::create("SHA-256"); h->update(x);` is keyed as
  `std::unique_ptr<Botan::HashFunction>.update` instead of `auto.update` and its supporting calls
  carry their contract role. A variable bound to two different producer types in one function is
  left unresolved.
- C++ direct initialization (`std::unique_ptr<X> h(X::create(...))`, `X h{f()}`) now binds the
  variable to the call, so the calls made on it are reported as the finding's supporting calls.
- C++ templated calls are recorded without their template arguments: `f<32>(x)` was not recorded at
  all, `ns::f<T>(x)` was recorded as `f<T>`, and `ns::f<libff::alt_bn128_pp>(x)` was split at the
  `::` inside the template arguments. Member template calls (`obj->m<N>(x)`) remain unrecorded:
  the C++ grammar reads them as comparisons.
