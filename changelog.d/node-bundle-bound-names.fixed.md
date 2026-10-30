- The JavaScript/TypeScript call graph no longer takes time quadratic in the size of a bundled
  file. Every function re-read the bodies of all the functions around it, so a bundle that wraps
  thousands of functions in one wrapper, such as `@stencil/core`'s 13 MB `compiler/stencil.js`,
  kept the call graph building past the 60-minute scan timeout. The names each scope binds are
  now read once per file; that file parses in about 30 seconds and the graph is unchanged.
