- `StitchOptions.ChainEntrySignatures` now accepts every function the
  `crypto_entry_points` index publishes, root or not, in its canonical or
  erased spelling. Previously a published entry point that was not a root
  produced no chains, so filtering on it returned no findings.
- A stitch restricted by `ChainEntrySignatures` keeps the entry-point index
  complete for operations the restriction leaves without chains.
