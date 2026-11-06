- Scanning an npm package that ships a large bundle (`dist/*.min.js`, asm.js or
  WASM builds) no longer spends minutes to hours building the call graph: since
  0.46.0 each call inside a bundle re-read the whole bundle to find what it
  exports. Each module is now read once. web3@4.0.0-alpha.0 takes about 10 s
  instead of 24 min. Findings and the exported graph fragment are unchanged.
