- JavaScript and TypeScript call graph: a call on the WebCrypto API resolves to
  its WebIDL interface, `SubtleCrypto.<method>` or `Crypto.getRandomValues`,
  under every spelling: the global `crypto` object (bare, `globalThis.`,
  `window.`, `self.`), Node's `crypto.webcrypto` through `require` or `import`,
  and a `subtle` object held in a variable or destructured. Contracts for the
  `SubtleCrypto` operations (`encrypt`, `decrypt`, `sign`, `verify`, `digest`,
  `generateKey`, `importKey`, `exportKey`, `deriveKey`, `deriveBits`,
  `wrapKey`, `unwrapKey`) and `Crypto.getRandomValues` export them as
  supporting calls with their lifecycle category.
  The structural graph of a Node scan that uses WebCrypto changes;
  `graphfrag.GraphAlgoVersion` `graph-algo-10` of this release covers this
  change, so a consumer that caches structural graphs under
  `scan_metadata.graph_algo_version` must re-mine. The wire schema is unchanged.
