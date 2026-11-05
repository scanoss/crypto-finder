- The `-deps` container image no longer bundles Semgrep. Dependency scanning runs OpenGrep,
  the default scanner, so `scan --scan-dependencies` is unchanged. `scan --scanner semgrep`
  in the `-deps` image now fails because `semgrep` is not on PATH; use the standard image
  (`latest`), which still ships Semgrep, or install it into the container. The image is
  about 290 MB smaller unpacked and about 70 MB smaller to download (amd64).
