- Synthesized library entry-point assets (`crypto-finder.api-entry-point`) are now
  written in the same order on every run. Previously two scans of the same target
  could list them in a different order, so their reports were not byte-identical.
