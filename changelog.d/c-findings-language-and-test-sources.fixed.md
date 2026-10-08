- C and C++ findings in a component of another language now report `c` or
  `c++`, so C code bundled in a Python package no longer reads `python`.
- C and C++ test, benchmark and known-answer generator sources (`test.c`,
  `test_*.c`, `*_test.c`, `bench.c`, `genkat.c` and the `.cc`/`.cpp` forms) are
  skipped when the target has other C or C++ sources, so a library's self-tests
  are no longer reported as its cryptography. A target whose only C sources
  match these names is scanned in full.
