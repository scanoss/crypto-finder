- Findings in a component scanned for several languages now report the language
  of their own file, so C code bundled in a Python package reads `c` instead of
  `python`.
- C and C++ test, benchmark and known-answer generator sources (`test.c`,
  `test_*.c`, `*_test.c`, `bench.c`, `genkat.c` and the `.cc`/`.cpp` forms) are
  skipped when the target has other C or C++ sources, so a library's self-tests
  are no longer reported as its cryptography. A target whose only C sources
  match these names is scanned in full.
