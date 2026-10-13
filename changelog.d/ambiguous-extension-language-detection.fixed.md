- Language detection no longer guesses from the file name alone when an
  extension belongs to several languages: `.rs` (Rust, RenderScript, XML) and
  similar files are classified by their content. A crate source package whose
  only source is `src/lib.rs`, such as `aes-gcm` from crates.io, was detected as
  XML, so its Rust rules did not run and `--export-graph-fragment` and the call
  graph exports failed with "could not determine a supported ecosystem".
